/**
 * 纯浏览器构建的 `invoke` 桥。
 *
 * 桌面/安卓构建里前端靠 `@tauri-apps/api` 的 `invoke` 调 Rust 命令；
 * 浏览器里没有 Tauri，这里用同名命令模拟一遍：数据走 `edge.ts` 的加密通道，
 * 封面/HLS 走 dev server 的 `/hg/*` 代理，登录态存 localStorage。
 *
 * 入口：`main.web.tsx` 会在挂载 App 之前调用 `installWebBridge()`，
 * 把 `window.__TAURI_INTERNALS__` 补出来，业务代码一行都不用改。
 */

import { edgeCall, innerBody, resetSessions, type EdgeResult } from "./edge";

const BASE_KEY = "hghub_web_base";
const TOKEN_KEY = "hghub_web_token";
const USER_KEY = "hghub_web_user";
const STRICT_KEY = "hghub_web_strict";

/**
 * 默认线路。
 *
 * `.com` 与 `.ai` 已停服，`.io` 在 2026-11-10 之后也解析不到（DNS 返回 0.0.0.0）。
 * 站点现在只活在镜像上：`thu.gitiecgad.cc` 之类的子域 301 到一个当日域名
 * （今天实测是 `00b4b.adihsppe.cc`，而跳板本身已 ECONNRESET）。
 * 所以这里走「发布页 → 跳板 → 当日域名」三级自动发现，见 `discoverBase()`。
 */
const PUBLISH_PAGE = "https://huangguoai.pages.dev/";
const MIRROR_BOOTSTRAP = "https://thu.gitiecgad.cc";
const DEFAULT_BASE = MIRROR_BOOTSTRAP;

const FIXED_LINES = [
  { name: "镜像线路（自动发现当日域名）", url: MIRROR_BOOTSTRAP },
  { name: "固定线路 1", url: "https://huangguoai.io" },
  { name: "固定线路 2", url: "https://huangguoai.com" },
  { name: "固定线路 3", url: "https://huangguoai.ai" },
];

const TRUSTED_AUTH = new Set([
  "https://huangguoai.com",
  "https://huangguoai.ai",
  "https://huangguoai.io",
]);

function getBase(): string {
  try {
    return localStorage.getItem(BASE_KEY) || DEFAULT_BASE;
  } catch {
    return DEFAULT_BASE;
  }
}

function setBase(url: string): string {
  const norm = normalizeBase(url);
  if (!norm) throw new Error("线路地址无效（需要纯 HTTPS 站点地址）");
  localStorage.setItem(BASE_KEY, norm);
  resetSessions();
  return norm;
}

/** 只接受纯 HTTPS origin：不带路径、查询串、片段与认证信息。 */
function normalizeBase(raw: string): string | null {
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    return null;
  }
  if (u.protocol !== "https:") return null;
  if (u.pathname !== "/" || u.search || u.hash) return null;
  if (u.username || u.password) return null;
  return u.origin;
}

const token = () => localStorage.getItem(TOKEN_KEY) || "";
const setToken = (t: string) => localStorage.setItem(TOKEN_KEY, t);
const clearToken = () => {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
};

/**
 * 把线路 origin 跟到「真正提供服务的那台主机」。
 *
 * 镜像线路（`thu.gitiecgad.cc` 之类）只是 301 跳板，全部跳到一个当日域名。
 * 加密握手固定 `redirect: "error"`，不先跟跳就会停在 301 上。
 *
 * 跳板本身也会挂（实测 `thu.gitiecgad.cc` 已 ECONNRESET），所以跳板不可达时
 * 回落到发布页 `publish.js` 里也没有线索，就只能用上一次成功过的 origin。
 * 结果缓存 10 分钟，避免每次调用都多打一次请求。
 */
const resolvedOrigins = new Map<string, { origin: string; at: number }>();

/** 上一个真正握手成功的 origin，跳板全挂时用它兜底。 */
let lastGoodOrigin = "";

/** 浏览器里上游请求一律走同源反代（见 `vite.hgweb.ts` 的 `/api-proxy`）。 */
const viaProxy = (target: string) => `/api-proxy?u=${encodeURIComponent(target)}`;

/**
 * 握手探活：能拿到合法 hello 才算这个 origin 可用。
 *
 * 必须带真的 `client_pub`：站点对缺字段的 hello 回 400 `invalid_request`，
 * 用空 `{v:1,type:"hello"}` 探活会把所有可用 origin 误判成不可用。
 */
async function probeHello(origin: string): Promise<boolean> {
  try {
    const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
      "deriveBits",
    ])) as CryptoKeyPair;
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    let s = "";
    for (let i = 0; i < raw.length; i++) s += String.fromCharCode(raw[i]);
    const clientPub = btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

    const res = await fetch(viaProxy(`${origin}/api/public/request`), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ v: 1, type: "hello", client_pub: clientPub }),
      cache: "no-store",
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) return false;
    const j = (await res.json()) as Json;
    return j.v === 1 && j.type === "hello" && typeof j.server_pub === "string" && !!j.server_pub;
  } catch {
    return false;
  }
}

/**
 * 自动发现当日可用 origin。
 *
 * 站点每天换域名，跳板也经常单独挂掉，所以候选一律实测 hello，通过即用。
 * 关键点：候选要**并发**探测，串行等 8 个超时就是 60 秒白屏。
 */
async function discoverBase(): Promise<string> {
  const candidates: string[] = [];
  const push = (raw: string) => {
    const origin = normalizeBase(raw);
    if (origin) candidates.push(origin);
  };

  // 上轮成功过的 + 缓存命中的，排最前
  if (lastGoodOrigin) push(lastGoodOrigin);
  const cached = resolvedOrigins.get(getBase());
  if (cached) push(cached.origin);

  // 跳板跟跳（可能直接给出当日域名）
  try {
    const followed = await withTimeout(probeOrigin(MIRROR_BOOTSTRAP), 6000);
    if (followed) push(followed);
  } catch {
    /* 跳板挂了就跳过 */
  }

  // 发布页里的镜像域名（只取前几组，避免笛卡尔积爆炸）
  try {
    const html = await withTimeout(
      fetch(viaProxy(PUBLISH_PAGE), { cache: "no-store" }).then((r) => r.text()),
      8000,
    );
    const m = /src="([^"]*\.js[^"]*)"/.exec(html);
    const script = new URL(m?.[1] ?? "publish.js", PUBLISH_PAGE).href;
    const js = await withTimeout(
      fetch(viaProxy(script), { cache: "no-store" }).then((r) => r.text()),
      8000,
    );
    const domains = jsArray(js, "var urls");
    const subs = jsArray(js, "var subdomains");
    for (const d of domains) {
      const host = d.replace(/\/$/, "");
      if (!host) continue;
      if (subs.length) push(`https://${subs[0]}.${host}`);
      push(`https://${host}`);
    }
  } catch {
    /* 发布页挂了就跳过 */
  }

  // 固定线路与历史当日域名兜底
  for (const u of ["https://00b4b.adihsppe.cc", DEFAULT_BASE, "https://huangguoai.io"]) push(u);

  const unique = [...new Set(candidates)];
  if (unique.length === 0) return lastGoodOrigin || getBase();

  // 并发探测，谁先通过用谁
  const winner = await firstTrue(unique, (origin) => probeHello(origin));
  if (winner) {
    resolvedOrigins.set(getBase(), { origin: winner, at: Date.now() });
    lastGoodOrigin = winner;
    return winner;
  }
  return lastGoodOrigin || getBase();
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, reject) => setTimeout(() => reject(new Error("timeout")), ms)),
  ]);
}

/** 并发跑 `test`，返回第一个为真的输入。 */
async function firstTrue(items: string[], test: (item: string) => Promise<boolean>): Promise<string | null> {
  const wrapped = items.map((item) => test(item).then((ok) => (ok ? item : null)).catch(() => null));
  const results = await Promise.all(wrapped);
  return results.find((r) => r !== null) ?? null;
}

async function probeOrigin(origin: string): Promise<string> {
  let current = origin;
  for (let hop = 0; hop < 4; hop++) {
    const res = await fetch(viaProxy(`${current}/`), { redirect: "manual", cache: "no-store" });
    const location = res.headers.get("location");
    if (res.status < 300 || res.status >= 400 || !location) break;
    const next = new URL(location, `${current}/`);
    if (next.protocol !== "https:") break;
    if (next.origin === current) break;
    current = next.origin;
  }
  return current;
}

async function resolveOrigin(origin: string): Promise<string> {
  const hit = resolvedOrigins.get(origin);
  if (hit && Date.now() - hit.at < 10 * 60 * 1000) return hit.origin;

  // 先用缓存过的已知可用 origin，省掉一次发现
  if (lastGoodOrigin && (await probeHello(lastGoodOrigin))) {
    resolvedOrigins.set(origin, { origin: lastGoodOrigin, at: Date.now() });
    return lastGoodOrigin;
  }

  const discovered = await discoverBase();
  resolvedOrigins.set(origin, { origin: discovered, at: Date.now() });
  return discovered;
}

/** 实际发请求用的 origin：先跟跳，再握手。 */
async function activeBase(): Promise<string> {
  const base = getBase();
  try {
    return await resolveOrigin(base);
  } catch {
    return lastGoodOrigin || base;
  }
}

type Json = Record<string, unknown>;

/** 业务调用：发一帧加密请求并解出 `{status, data, msg}`。 */
async function callEdge(
  method: string,
  path: string,
  body?: Json | null,
  withToken = true,
): Promise<unknown> {
  const base = await activeBase();
  const payload = body ? new TextEncoder().encode(JSON.stringify(body)) : null;
  const contentType = body ? "application/json" : "";
  const t = withToken ? token() : "";

  const inner: EdgeResult = await edgeCall(base, method, path, payload, contentType, t);
  const text = innerBody(inner);

  if (inner.status === 401 || inner.status === 403) {
    clearToken();
    throw "401";
  }
  if (inner.status < 200 || inner.status >= 300) {
    throw `HTTP ${inner.status}: ${text.slice(0, 160)}`;
  }
  if (!text.trim()) return null;

  let parsed: Json;
  try {
    parsed = JSON.parse(text) as Json;
  } catch {
    throw `业务响应不是 JSON: ${text.slice(0, 160)}`;
  }

  if (parsed.status === 1) {
    return parsed.data ?? null;
  }
  throw String(parsed.msg || "接口返回失败");
}

async function authed(method: string, path: string, body?: Json | null): Promise<unknown> {
  if (!token()) throw "请先登录";
  return callEdge(method, path, body, true);
}

/* ───────────────────────── 播放地址摊平 ───────────────────────── */

/** 新接口给 `{streams:{main,hevc}, ep}`，前端读 `video_url`/`ep_num`，这里对齐。 */
function normalizePlay(value: unknown, id: number, ep: number): Json {
  const v = (value ?? {}) as Json;
  if (typeof v !== "object") return v;
  const streams = (v.streams ?? null) as Json | null;
  const main = (streams?.main as string) || "";
  const hevc = (streams?.hevc as string) || "";

  const out: Json = { ...v };
  if (!out.video_url && main) out.video_url = main;
  if (!out.video_url_hevc && hevc) out.video_url_hevc = hevc;
  if (out.ep_num === undefined) out.ep_num = out.ep ?? ep;
  if (out.id === undefined) out.id = id;
  return out;
}

/* ───────────────────────── 命令实现 ───────────────────────── */

const commands: Record<string, (args: Json) => Promise<unknown> | unknown> = {
  /* 启动 */
  app_boot: () => ({
    user: readUser(),
    logged_in: !!token(),
    base: getBase(),
    strict_security: localStorage.getItem(STRICT_KEY) !== "0",
    cli_relaxed: false,
  }),

  security_set: (a) => {
    localStorage.setItem(STRICT_KEY, a.strict ? "1" : "0");
    return !!a.strict;
  },

  debug_log: (a) => {
    const line = `[web] ${String(a.msg ?? "")}`;
    // 浏览器里没有 debug.log，落 console 便于右侧栏直接看
    console.debug(line);
  },

  net_diag: () => ({
    base: getBase(),
    host: safeHost(getBase()),
    dns: { note: "浏览器构建不做 DNS 自检" },
    http: { note: "浏览器构建不做 HTTP 自检" },
    env: { HGHUB_PROXY: null, note: "由 dev server 代理" },
  }),

  /* 线路 */
  line_state: () => ({
    base: getBase(),
    default: DEFAULT_BASE,
    fixed: FIXED_LINES,
  }),

  line_set: (a) => {
    const next = setBase(String(a.url ?? ""));
    return next;
  },

  line_mirrors: async () => {
    const page = "https://huangguoai.pages.dev/";
    const html = await (await fetch(viaProxy(page))).text();
    const m = /src="([^"]*\.js[^"]*)"/.exec(html);
    const script = new URL(m?.[1] ?? "publish.js", page).href;
    const js = await (await fetch(viaProxy(script))).text();

    const domains = jsArray(js, "var urls");
    const subs = jsArray(js, "var subdomains");
    if (domains.length === 0) throw "地址发布页格式有变化：没找到镜像域名";

    const items: { name?: string; url: string; host: string }[] = [];
    const seen = new Set<string>();
    outer: for (const domain of domains) {
      const d = domain.replace(/\/$/, "");
      if (!d) continue;
      const hosts = subs.length ? subs.map((s) => `${s}.${d}`) : [d];
      for (const host of hosts) {
        if (seen.has(host)) continue;
        seen.add(host);
        items.push({ url: `https://${host}`, host });
        if (items.length >= 60) break outer;
      }
    }
    return { source: page, script, items };
  },

  line_probe: async (a) => {
    const urls = (a.urls ?? []) as string[];
    const out: Json[] = [];
    for (const u of urls) {
      const started = performance.now();
      try {
        const res = await fetch(viaProxy(`${u.replace(/\/$/, "")}/`), { method: "HEAD", cache: "no-store" });
        out.push({ url: u, ok: res.status < 400, status: res.status, ms: Math.round(performance.now() - started) });
      } catch (e) {
        out.push({ url: u, ok: false, ms: Math.round(performance.now() - started), error: (e as Error).message });
      }
    }
    return out;
  },

  /* 账号 */
  api_login: async (a) => {
    const base = getBase();
    if (!TRUSTED_AUTH.has(base)) throw "镜像线路仅供游客浏览；登录/注册请切换到固定线路";
    const data = (await callEdge(
      "POST",
      "/api/account/loginByPassword",
      { username: a.username, password: a.password },
      false,
    )) as Json;
    const t = data?.token as string;
    if (!t) throw "登录返回缺少 token";
    setToken(t);
    writeUser((data.user ?? null) as Json | null);
    return { user: data.user ?? null };
  },

  api_register: async (a) => {
    const base = getBase();
    if (!TRUSTED_AUTH.has(base)) throw "镜像线路仅供游客浏览；登录/注册请切换到固定线路";
    const body: Json = {
      username: a.username,
      password: a.password,
      confirm_password: a.password,
    };
    const email = String(a.email ?? "").trim();
    if (email) body.email = email;
    const data = (await callEdge("POST", "/api/account/registerByPassword", body, false)) as Json;
    const t = data?.token as string;
    if (!t) throw "注册返回缺少 token";
    setToken(t);
    writeUser((data.user ?? null) as Json | null);
    return { user: data.user ?? null };
  },

  api_logout: async () => {
    try {
      await callEdge("POST", "/api/account/logout", null, true);
    } catch {
      /* 登出失败也要清本地 */
    }
    clearToken();
    return { ok: true };
  },

  api_me: async () => {
    const me = await callEdge("GET", "/api/account/me", null, true);
    writeUser((me ?? null) as Json | null);
    return me;
  },

  /* 列表 */
  api_feed: (a) => callEdge("GET", `/api/videos?page=${a.page}&size=${a.size}`),
  api_category: (a) =>
    callEdge("GET", `/api/videos/category/${encodeURIComponent(String(a.cate))}?page=${a.page}&size=${a.size}`),
  api_rank: (a) => {
    const kind = a.kind === "recommend" || a.kind === "potential" ? a.kind : "hot";
    return callEdge("GET", `/api/ranks/${kind}`);
  },
  api_search: (a) => {
    const q = encodeURIComponent(String(a.q ?? ""));
    return callEdge("GET", `/api/search?q=${q}&page=${a.page}&size=${a.size}`);
  },
  api_posts: (a) => callEdge("GET", `/api/posts?page=${a.page}&size=${a.size}`),
  api_post: (a) => callEdge("GET", `/api/posts/${a.id}`),
  api_post_comments: (a) => callEdge("GET", `/api/posts/${a.id}/comments?page=${a.page}&size=${a.size}`),

  /* 详情 / 播放 */
  api_video: (a) => callEdge("GET", `/api/videos/${a.id}`),

  api_play: async (a) => {
    const id = Number(a.id);
    const ep = Number(a.ep);
    try {
      const v = await callEdge("POST", `/api/videos/${id}/episodes/${ep}/playback`, null, true);
      return normalizePlay(v, id, ep);
    } catch (first) {
      try {
        const v = await callEdge("GET", `/api/videos/${id}/play?ep=${ep}&page_texts=0`, null, true);
        return normalizePlay(v, id, ep);
      } catch {
        throw first;
      }
    }
  },

  /* 评论 / 互动 */
  api_comments: (a) =>
    callEdge("GET", `/api/videos/${a.id}/comments?ep=${a.ep}&page=${a.page}&size=${a.size}`),

  api_comment_send: (a) => {
    const reply = Number(a.replyId ?? 0);
    // 服务端允许不带 ep 的发表；带 reply 时走同一路径
    const path = `/api/videos/${a.id}/comments?ep=${a.ep}`;
    const body: Json = { text: a.text };
    if (reply > 0) body.reply_id = reply;
    return authed("POST", path, body);
  },

  api_like: (a) => authed(a.on ? "POST" : "DELETE", `/api/videos/${a.id}/like?ep=${a.ep}`),
  api_collect: (a) => authed(a.on ? "POST" : "DELETE", `/api/videos/${a.id}/collect`),
  api_follow: (a) => authed(a.on ? "POST" : "DELETE", `/api/users/${a.uid}/follow`),
  api_post_like: (a) => authed(a.on ? "POST" : "DELETE", `/api/posts/${a.id}/like`),
  api_post_collect: (a) => authed(a.on ? "POST" : "DELETE", `/api/posts/${a.id}/collect`),

  /* 杂项 */
  cache_clear: () => {
    resetSessions();
  },
  check_update: async () => ({
    current: "1.2.0",
    latest: "1.2.0",
    has_update: false,
    url: "https://github.com/Minireel/HGhub/releases",
    notes: "浏览器预览构建，不做更新检查",
  }),
  open_url: (a) => {
    window.open(String(a.url ?? ""), "_blank", "noopener");
  },
  /* App.tsx 里退出时调用的插件命令，浏览器里没有意义 */
  "plugin:app|exit": () => {},
};

function readUser(): Json | null {
  try {
    const raw = localStorage.getItem(USER_KEY);
    return raw ? (JSON.parse(raw) as Json) : null;
  } catch {
    return null;
  }
}

function writeUser(user: Json | null): void {
  try {
    if (user) localStorage.setItem(USER_KEY, JSON.stringify(user));
    else localStorage.removeItem(USER_KEY);
  } catch {
    /* 隐私模式下忽略 */
  }
}

function safeHost(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

/** 取 JS 里 `var <name> = [ ... ]` 的字符串数组。 */
function jsArray(src: string, decl: string): string[] {
  const at = src.indexOf(decl);
  if (at < 0) return [];
  const rest = src.slice(at);
  const open = rest.indexOf("[");
  const close = rest.indexOf("]", open);
  if (open < 0 || close < 0) return [];
  return rest
    .slice(open + 1, close)
    .split(",")
    .map((s) => s.trim().replace(/^['"]|['"]$/g, "").trim())
    .filter((s) => s && !s.includes("//") && !s.startsWith("JumpPage"))
    .map((s) => s.split("//")[0].trim())
    .filter(Boolean);
}

/* ───────────────────────── 安装桥接 ───────────────────────── */

/**
 * 把 `window.__TAURI_INTERNALS__.invoke` 补齐，`@tauri-apps/api/core` 的
 * `invoke` 会优先走这里，因此业务代码不需要任何条件分支。
 *
 * 除 `invoke` 之外还要补 `metadata`：`@tauri-apps/api/window` 在模块加载时就读
 * `__TAURI_INTERNALS__.metadata.currentWindow.label`，缺了会直接抛
 * `Cannot read properties of undefined (reading 'currentWindow')`，整个 App 白屏。
 */
export function installWebBridge(): void {
  const internals = (window as unknown as { __TAURI_INTERNALS__?: Json }).__TAURI_INTERNALS__ ?? {};

  internals.invoke = async (cmd: string, args?: Json) => {
    const impl = commands[cmd];
    if (!impl) {
      throw new Error(`[web] 未实现的命令: ${cmd}`);
    }
    return impl(args ?? {});
  };

  // window/webview 插件在模块初始化时读取这些字段
  internals.metadata = {
    currentWindow: { label: "main" },
    currentWebview: { label: "main", windowLabel: "main" },
    windows: [{ label: "main" }],
    webviews: [{ label: "main", windowLabel: "main" }],
  };

  internals.transformCallback = (cb: unknown) => cb;
  internals.unregisterCallback = () => {};
  internals.convertFileSrc = (p: string) => p;
  internals.plugins = {};

  (window as unknown as { __TAURI_INTERNALS__: Json }).__TAURI_INTERNALS__ = internals;
  (window as unknown as { __HGHUB_WEB__: boolean }).__HGHUB_WEB__ = true;
}

/** 供调试用：当前线路与登录态。 */
export function webDebugState(): Json {
  return { base: getBase(), hasToken: !!token(), user: readUser() };
}
