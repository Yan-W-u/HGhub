/**
 * `dx150-edge-v1` 加密通道（浏览器版）。
 *
 * 站点在 2026-11 把 `/api/edge/request` 明文信封换成了四个加密入口，
 * 桌面端由 Rust（`src-tauri/src/edge_crypto.rs`）实现；这里是同一协议的
 * WebCrypto 实现，供纯浏览器构建使用（右侧栏实时预览 / 网页调试）。
 *
 * 协议（与站点 `static/web/js/edge-api-crypto.js` 对齐）：
 *   1. hello:  ECDH P-256 → { kid, sid, server_pub, salt, site, server_time, expires_at }
 *   2. shared: ECDH(client_priv, server_pub)
 *   3. key:    HKDF-SHA256(shared, salt, info + "\n" + ("req"|"res"))
 *              info = "dx150-edge-v1\n{scope}\n{site}\n{kid}\n{sid}"
 *   4. frame:  iv = 4×0x00 ‖ BE32(seq)
 *              aad = "{info}\n{req|res}\n{seq}\n{ts}"
 *   5. inner:  请求 { request, authorization? }
 *              响应 { status, headers, body(base64) }
 */

export const PROTOCOL = "dx150-edge-v1";
const MAX_SEQUENCE = 16384;

type Scope = "public" | "user" | "playback" | "dynamic";

type Session = {
  scope: Scope;
  kid: string;
  sid: string;
  info: string;
  requestKey: CryptoKey;
  responseKey: CryptoKey;
  sequence: number;
  clockOffset: number;
  expiresAt: number;
};

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 8192) {
    s += String.fromCharCode(...bytes.subarray(i, i + 8192));
  }
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function unb64url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("加密响应编码无效");
  const raw = atob(value.replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(new ArrayBuffer(raw.length));
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function unb64(value: string): Uint8Array {
  const raw = atob(value);
  const out = new Uint8Array(new ArrayBuffer(raw.length));
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

/** WebCrypto 要 `ArrayBuffer` 底的视图；TS 5.9 的 `BufferSource` 不接受 `ArrayBufferLike`。 */
const src = (v: Uint8Array): BufferSource => v as unknown as BufferSource;

function nonce(sequence: number): Uint8Array {
  const iv = new Uint8Array(new ArrayBuffer(12));
  new DataView(iv.buffer).setUint32(8, sequence, false);
  return iv;
}

/* ───────────────────────── scope 路由 ───────────────────────── */

/** 站点前端 `encryptedAPIRoutes` 的路径 → 入口映射（数字占位符必须为纯数字）。 */
const ROUTES: Array<[Scope, string, string]> = [
  // playback
  ["playback", "GET", "/api/videos/:id/play"],
  ["playback", "POST", "/api/videos/:id/playback"],
  ["playback", "POST", "/api/videos/:id/episodes/:ep/playback"],
  ["playback", "POST", "/api/posts/:id/playback"],
  ["playback", "POST", "/api/media/playback/previews"],
  ["playback", "POST", "/api/media/prerolls/:id/playback"],
  // user
  ["user", "POST", "/api/account/loginByPassword"],
  ["user", "POST", "/api/account/registerByPassword"],
  ["user", "POST", "/api/account/logout"],
  ["user", "POST", "/api/account/password"],
  ["user", "GET", "/api/account/me"],
  ["user", "PATCH", "/api/account/profile"],
  ["user", "GET", "/api/users/me/collects"],
  ["user", "GET", "/api/users/me/comments"],
  ["user", "GET", "/api/users/me/follows"],
  ["user", "GET", "/api/users/me/history"],
  ["user", "POST", "/api/users/me/history"],
  ["user", "POST", "/api/users/me/history/delete"],
  ["user", "POST", "/api/users/me/history/sync"],
  ["user", "GET", "/api/users/me/likes"],
  ["user", "POST", "/api/users/me/likes/sync"],
  ["user", "GET", "/api/users/me/messages"],
  ["user", "DELETE", "/api/users/me/messages/:id"],
  ["user", "POST", "/api/users/me/messages/:id/read"],
  ["user", "POST", "/api/users/me/messages/batch-delete"],
  ["user", "POST", "/api/users/me/messages/read-all"],
  ["user", "GET", "/api/users/me/messages/unread-count"],
  ["user", "POST", "/api/users/:id/follow"],
  ["user", "DELETE", "/api/users/:id/follow"],
  ["user", "GET", "/api/videos/following"],
  ["user", "POST", "/api/videos/:id/like"],
  ["user", "DELETE", "/api/videos/:id/like"],
  ["user", "POST", "/api/videos/:id/collect"],
  ["user", "DELETE", "/api/videos/:id/collect"],
  ["user", "POST", "/api/videos/:id/comments"],
  ["user", "GET", "/api/videos/:id/comments"],
  ["user", "POST", "/api/videos/:id/comments/:cid/like"],
  ["user", "DELETE", "/api/videos/:id/comments/:cid/like"],
  ["user", "POST", "/api/videos/:id/comments/:cid/guest-like"],
  ["user", "GET", "/api/videos/:id/comments/liked"],
  ["user", "GET", "/api/videos/:id/comments/state"],
  ["user", "POST", "/api/videos/:id/guest-comments"],
  ["user", "POST", "/api/videos/:id/guest-like"],
  ["user", "GET", "/api/videos/:id/guest-liked"],
  ["user", "GET", "/api/videos/:id/interaction-state"],
  ["user", "GET", "/api/videos/:id/rating"],
  ["user", "POST", "/api/videos/:id/rating"],
  ["user", "POST", "/api/videos/:id/report"],
  ["user", "POST", "/api/videos/:id/feedback"],
  ["user", "POST", "/api/posts/:id/like"],
  ["user", "DELETE", "/api/posts/:id/like"],
  ["user", "POST", "/api/posts/:id/collect"],
  ["user", "DELETE", "/api/posts/:id/collect"],
  ["user", "POST", "/api/posts/:id/comments"],
  ["user", "GET", "/api/posts/:id/comments/liked"],
  ["user", "POST", "/api/posts/:id/comments/:cid/like"],
  ["user", "DELETE", "/api/posts/:id/comments/:cid/like"],
  ["user", "POST", "/api/posts/:id/comments/:cid/guest-like"],
  ["user", "POST", "/api/posts/:id/guest-comments"],
  ["user", "POST", "/api/posts/:id/guest-like"],
  ["user", "GET", "/api/posts/:id/guest-liked"],
  ["user", "POST", "/api/posts/:id/visit"],
  ["user", "POST", "/api/ai-wish"],
  // dynamic
  ["dynamic", "GET", "/api/search"],
  ["dynamic", "GET", "/api/search/hot"],
  ["dynamic", "GET", "/api/search/suggest"],
  ["dynamic", "GET", "/api/search/tags/hot"],
  ["dynamic", "GET", "/api/home"],
  ["dynamic", "GET", "/api/posts/:id"],
  ["dynamic", "GET", "/api/posts/:id/comments"],
  ["dynamic", "POST", "/api/posts/:id/share"],
  ["dynamic", "GET", "/api/users/:id"],
  ["dynamic", "GET", "/api/videos/:id"],
  ["dynamic", "GET", "/api/videos/:id/comments"],
  ["dynamic", "GET", "/api/videos/:id/comments/:cid/replies"],
  ["dynamic", "GET", "/api/videos/:id/next"],
  ["dynamic", "POST", "/api/videos/:id/play"],
  ["dynamic", "POST", "/api/videos/:id/visit"],
  ["dynamic", "POST", "/api/videos/recommend"],
  ["dynamic", "POST", "/api/videos/recommend/ref/:ref"],
  ["dynamic", "POST", "/api/edge/image"],
  ["dynamic", "POST", "/api/media/covers"],
  ["dynamic", "GET", "/api/site/address-poster"],
  ["dynamic", "POST", "/api/site/click"],
  ["dynamic", "GET", "/api/site/entries"],
  ["dynamic", "GET", "/api/site/go-home"],
  ["dynamic", "POST", "/api/site/home-slots"],
  ["dynamic", "POST", "/api/stats/click"],
  ["dynamic", "POST", "/api/stats/origin"],
  ["dynamic", "GET", "/api/whoami"],
  // public
  ["public", "GET", "/api/videos"],
  ["public", "GET", "/api/videos/long"],
  ["public", "GET", "/api/videos/category/:route"],
  ["public", "GET", "/api/videos/sort/:route"],
  ["public", "GET", "/api/videos/tag/:tag"],
  ["public", "GET", "/api/videos/user/:id"],
  ["public", "GET", "/api/videos/:id/related"],
  ["public", "GET", "/api/videos/report-reasons"],
  ["public", "GET", "/api/posts"],
  ["public", "GET", "/api/posts/category/:route"],
  ["public", "GET", "/api/posts/tag/:tag"],
  ["public", "GET", "/api/posts/user/:id"],
  ["public", "GET", "/api/posts/:id/adjacent"],
  ["public", "GET", "/api/posts/:id/related"],
  ["public", "GET", "/api/ranks/:type"],
  ["public", "GET", "/api/feed/today"],
  ["public", "GET", "/api/feed/recommend"],
  ["public", "GET", "/api/feed/post/today"],
  ["public", "GET", "/api/home/latest"],
  ["public", "GET", "/api/home/recommends"],
  ["public", "GET", "/api/tags"],
  ["public", "GET", "/api/topics"],
  ["public", "GET", "/api/topics/:slug"],
  ["public", "GET", "/api/users/:id/stats"],
  ["public", "GET", "/api/site/categories/video"],
  ["public", "GET", "/api/site/categories/post"],
  ["public", "GET", "/api/site/config"],
  ["public", "GET", "/api/site/links"],
  ["public", "GET", "/api/site/menus"],
  ["public", "GET", "/api/site/meta"],
  ["public", "GET", "/api/site/pages"],
  ["public", "GET", "/api/site/pages/:slug"],
  ["public", "GET", "/api/site/sorts/video"],
  ["public", "GET", "/api/site/transit"],
  ["public", "GET", "/api/site/watermark"],
];

function matches(segments: string[], pattern: string): boolean {
  const want = pattern.split("/");
  if (want.length !== segments.length) return false;
  return want.every((w, i) => {
    const got = segments[i];
    if (w === ":id" || w === ":cid" || w === ":ep") return /^\d+$/.test(got);
    if (w.startsWith(":")) return got !== "";
    return w === got;
  });
}

export function scopeFor(method: string, path: string): Scope {
  const m = method.trim().toUpperCase();
  const segments = path.split("?")[0].split("/");
  for (const [scope, wantMethod, pattern] of ROUTES) {
    if (wantMethod === m && matches(segments, pattern)) return scope;
  }
  return "dynamic";
}

/* ───────────────────────── 会话 ───────────────────────── */

const sessions = new Map<Scope, Promise<Session>>();

type Hello = {
  v: number;
  type: string;
  kid: string;
  sid: string;
  site: string;
  server_pub: string;
  salt: string;
  server_time: number;
  expires_at: number;
};

async function openSession(scope: Scope, base: string): Promise<Session> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ])) as CryptoKeyPair;
  const clientPub = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));

  const raw = await postJson(`${base}/api/${scope}/request`, {
    v: 1,
    type: "hello",
    client_pub: b64url(clientPub),
  });
  const hello = validateHello(raw);

  const serverPub = await crypto.subtle.importKey(
    "raw",
    src(unb64url(hello.server_pub)),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const shared = await crypto.subtle.deriveBits(
    { name: "ECDH", public: serverPub },
    pair.privateKey,
    256,
  );
  const hkdfKey = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const salt = unb64url(hello.salt);
  const info = [PROTOCOL, scope, hello.site, hello.kid, hello.sid].join("\n");

  const derive = (direction: string) =>
    crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: src(salt),
        info: src(encoder.encode(`${info}\n${direction}`)),
      },
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false,
      [direction === "req" ? "encrypt" : "decrypt"],
    );

  const [requestKey, responseKey] = await Promise.all([derive("req"), derive("res")]);
  const local = Math.floor(Date.now() / 1000);
  return {
    scope,
    kid: hello.kid,
    sid: hello.sid,
    info,
    requestKey,
    responseKey,
    sequence: 0,
    clockOffset: hello.server_time - local,
    expiresAt: local + (hello.expires_at - hello.server_time),
  };
}

function validateHello(raw: Record<string, unknown>): Hello {
  const bad = (): never => {
    throw new Error("加密握手响应无效");
  };
  if (raw.v !== 1 || raw.type !== "hello") bad();
  const kid = raw.kid;
  if (typeof kid !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(kid)) bad();
  const sid = raw.sid;
  if (typeof sid !== "string" || sid.length < 16 || sid.length > 128) bad();
  const site = raw.site;
  if (typeof site !== "string" || site.length > 256) bad();
  const serverPub = raw.server_pub;
  if (typeof serverPub !== "string") bad();
  const salt = raw.salt;
  if (typeof salt !== "string") bad();
  const serverTime = raw.server_time;
  const expiresAt = raw.expires_at;
  if (!Number.isSafeInteger(serverTime) || !Number.isSafeInteger(expiresAt)) bad();
  const st = serverTime as number;
  const ex = expiresAt as number;
  if (ex <= st || ex - st > 600) bad();
  return {
    v: 1,
    type: "hello",
    kid: kid as string,
    sid: sid as string,
    site: site as string,
    server_pub: serverPub as string,
    salt: salt as string,
    server_time: st,
    expires_at: ex,
  };
}

async function getSession(scope: Scope, base: string): Promise<Session> {
  const existing = sessions.get(scope);
  if (existing) {
    const s = await existing.catch(() => null);
    if (s && s.expiresAt > Math.floor(Date.now() / 1000) + 5 && s.sequence < MAX_SEQUENCE) {
      return s;
    }
  }
  const pending = openSession(scope, base).catch((e) => {
    sessions.delete(scope);
    throw e;
  });
  sessions.set(scope, pending);
  return pending;
}

export function resetSessions(): void {
  sessions.clear();
}

/* ───────────────────────── 调用 ───────────────────────── */

/**
 * 浏览器里所有上游请求都走同源反代。
 *
 * 站点 `/api/&#42;/request` 不回 `Access-Control-Allow-Origin`，直连必被 CORS 拦。
 * dev server 的 `/api-proxy/<origin>/<path>` 中间件把请求转出去（见 `vite.hgweb.ts`），
 * 这样浏览器只看到同源请求。
 */
function proxyUrl(target: string): string {
  return `/api-proxy?u=${encodeURIComponent(target)}`;
}

async function postJson(url: string, body: unknown): Promise<Record<string, unknown>> {
  const res = await fetch(proxyUrl(url), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    redirect: "error",
    cache: "no-store",
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}: ${text.slice(0, 160)}`);
  }
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    throw new Error(`响应不是 JSON: ${text.slice(0, 160)}`);
  }
}

export type EdgeResult = { status: number; headers: Record<string, string[]>; body: string };

/**
 * 发一帧业务请求，返回解密后的内层响应。
 * `body` 是原始 UTF-8 字节（通常是 JSON），`contentType` 为空表示无正文。
 */
export async function edgeCall(
  base: string,
  method: string,
  path: string,
  body: Uint8Array | null,
  contentType: string,
  token?: string | null,
): Promise<EdgeResult> {
  const upper = method.trim().toUpperCase();
  const scope = scopeFor(upper, path);

  const attempt = async (): Promise<EdgeResult> => {
    const session = await getSession(scope, base);
    const sequence = ++session.sequence;
    if (sequence > MAX_SEQUENCE) throw new Error("加密会话已到期");
    const timestamp = Math.floor(Date.now() / 1000) + session.clockOffset;
    const iv = nonce(sequence);
    const aad = (dir: string) => encoder.encode([session.info, dir, sequence, timestamp].join("\n"));

    let encoded = "";
    if (body && body.length > 0) {
      let s = "";
      for (let i = 0; i < body.length; i += 8192) {
        s += String.fromCharCode(...body.subarray(i, i + 8192));
      }
      encoded = btoa(s);
    }

    const request: Record<string, unknown> = { method: upper, path, body: encoded, content_type: contentType };
    const packet: Record<string, unknown> = { request };
    if (scope !== "public" && token) packet.authorization = `Bearer ${token}`;

    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv as BufferSource, additionalData: aad("req") as BufferSource },
      session.requestKey,
      encoder.encode(JSON.stringify(packet)) as BufferSource,
    );

    const response = await postJson(`${base}/api/${scope}/request`, {
      v: 1,
      type: "call",
      kid: session.kid,
      sid: session.sid,
      seq: sequence,
      ts: timestamp,
      ciphertext: b64url(new Uint8Array(ciphertext)),
    });

    if (
      response.v !== 1 ||
      response.type !== "result" ||
      response.sid !== session.sid ||
      response.kid !== session.kid ||
      response.seq !== sequence ||
      response.ts !== timestamp
    ) {
      throw new Error("加密响应不匹配");
    }

    const raw = unb64url(response.ciphertext as string);
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv as BufferSource, additionalData: aad("res") as BufferSource },
      session.responseKey,
      raw as BufferSource,
    );
    const inner = JSON.parse(decoder.decode(plain)) as EdgeResult;
    if (!Number.isInteger(inner.status) || inner.status < 200 || inner.status > 599) {
      throw new Error("加密接口响应格式无效");
    }
    return inner;
  };

  try {
    return await attempt();
  } catch {
    // 会话可能被服务端回收（session_expired）：重开一次再放弃。
    sessions.delete(scope);
    return attempt();
  }
}

/** 从内层响应里取业务 JSON 文本。 */
export function innerBody(inner: EdgeResult): string {
  const raw = inner.body ?? "";
  if (!raw) return "";
  return decoder.decode(unb64(raw));
}
