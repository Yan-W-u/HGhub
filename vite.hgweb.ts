/**
 * 纯浏览器构建的代理层（Vite dev server 中间件）。
 *
 * 浏览器里有两个 Rust 侧不存在的问题：
 *
 * 1. **CORS**：站点的 `/api/&#42;/request` 不回 `Access-Control-Allow-&#42;`，浏览器直连必被拦。
 *    桌面端用 reqwest 发请求所以无感，浏览器则必须同源：这里把
 *    `/api-proxy?u=<完整 URL>` 反代到真实站点。
 * 2. **媒体**：封面是 AES 密文、m3u8 要改写成同源分片地址，浏览器自己做不了：
 *
 *      GET /hg/img?u=<封面>   → AES-128-CBC 解密
 *      GET /hg/hls?u=<m3u8>   → 改写分片/密钥指向 /hg/seg
 *      GET /hg/seg?u=<资源>   → 原样透传
 *
 * 只在 `vite` 开发服务器里生效，不打进生产构建。
 */

import type { Connect, Plugin, ViteDevServer } from "vite";
import { createDecipheriv } from "node:crypto";

/** 站点封面固定用这把 key/iv（见站点 crypto-image-protocol.js） */
const IMG_KEY = Buffer.from("f5d965df75336270", "utf8");
const IMG_IV = Buffer.from("97b60394abc2fbe1", "utf8");

const PREFIX = "/hg/";
/**
 * `/api-proxy?u=<完整 https URL>` —— 同源反代，绕开站点不回 CORS 头的问题。
 * 用查询参数而不是路径前缀：浏览器 URL 解析会把路径里的 `//` 规范化成一个，
 * `https://host` 塞进路径必然被改写成 `https:/host`。
 */
const API_PREFIX = "/api-proxy";

function decodeQuery(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

function targetOf(url: string): string {
  const q = url.split("?")[1] ?? "";
  for (const kv of q.split("&")) {
    if (kv.startsWith("u=")) return decodeQuery(kv.slice(2));
  }
  return "";
}

function imageKind(buf: Buffer): string | null {
  if (buf.length < 12) return null;
  if (buf[0] === 0xff && buf[1] === 0xd8) return "image/jpeg";
  if (buf.subarray(0, 4).toString("hex") === "89504e47") return "image/png";
  if (buf.subarray(0, 4).toString("ascii") === "GIF8") return "image/gif";
  if (buf.subarray(0, 4).toString("ascii") === "RIFF" && buf.subarray(8, 12).toString("ascii") === "WEBP")
    return "image/webp";
  return null;
}

function decryptCover(buf: Buffer): Buffer {
  if (buf.length === 0 || buf.length % 16 !== 0) return buf;
  const d = createDecipheriv("aes-128-cbc", IMG_KEY, IMG_IV);
  d.setAutoPadding(false);
  const out = Buffer.concat([d.update(buf), d.final()]);
  const pad = out.length > 0 ? out[out.length - 1] : 0;
  if (pad > 0 && pad <= 16 && out.length >= pad) {
    const ok = out.subarray(out.length - pad).every((b) => b === pad);
    if (ok) return out.subarray(0, out.length - pad);
  }
  return out;
}

/** m3u8 里的相对地址按 m3u8 自身地址解析成绝对地址。 */
function absolutize(base: string, ref: string): string {
  try {
    return new URL(ref, base).href;
  } catch {
    return ref;
  }
}

const SEG_PREFIX = `${PREFIX}seg?u=`;

/** 改写 `URI="..."` 属性（KEY / MAP / MEDIA / SESSION-KEY / PART 等）。 */
function rewriteAttr(line: string, base: string): string {
  return line.replace(/URI="([^"]+)"/g, (_all, uri: string) => {
    const abs = absolutize(base, uri);
    return `URI="${SEG_PREFIX}${encodeURIComponent(abs)}"`;
  });
}

function rewritePlaylist(base: string, text: string): string {
  const out: string[] = [];
  for (const raw of text.replace(/^\uFEFF/, "").split(/\r?\n/)) {
    const line = raw.trimEnd();
    if (!line) {
      out.push("");
      continue;
    }
    if (line.startsWith("#")) {
      if (line.startsWith("#EXT-X-CONTENT-STEERING:")) continue;
      out.push(line.includes('URI="') ? rewriteAttr(line, base) : line);
      continue;
    }
    const abs = absolutize(base, line);
    out.push(`${SEG_PREFIX}${encodeURIComponent(abs)}`);
  }
  return out.join("\n");
}

async function readBody(res: Response): Promise<Buffer> {
  return Buffer.from(await res.arrayBuffer());
}

function send(res: any, status: number, type: string, body: Buffer | string): void {
  res.statusCode = status;
  res.setHeader("Content-Type", type);
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.end(body);
}

export function hgMediaProxy(): Plugin {
  /** `/api-proxy?u=https://host/api/x` → 同源反代到 `https://host/api/x`。 */
  const apiProxy: Connect.NextHandleFunction = async (req, res, next) => {
    const url = req.url ?? "";
    const path = url.split("?")[0];
    if (path !== API_PREFIX && !path.startsWith(`${API_PREFIX}/`)) return next();

    const target = targetOf(url);
    if (!target) return send(res, 400, "text/plain", "missing u");

    let parsed: URL;
    try {
      parsed = new URL(target);
    } catch {
      return send(res, 400, "text/plain", "bad target");
    }
    // 只允许 HTTPS，避免被当成开放代理去访问内网 / 明文站点
    if (parsed.protocol !== "https:") return send(res, 400, "text/plain", "https only");

    try {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const body = Buffer.concat(chunks);

      const upstream = await fetch(parsed.href, {
        method: req.method,
        headers: {
          "Content-Type": (req.headers["content-type"] as string) ?? "application/json",
          Accept: "application/json",
        },
        body: req.method === "GET" || req.method === "HEAD" ? undefined : body,
        redirect: "follow",
      });

      const buf = Buffer.from(await upstream.arrayBuffer());
      res.statusCode = upstream.status;
      res.setHeader("Content-Type", upstream.headers.get("content-type") ?? "application/json");
      res.setHeader("Cache-Control", "no-store");
      res.end(buf);
    } catch (e) {
      return send(res, 502, "text/plain", (e as Error).message);
    }
  };

  const handler: Connect.NextHandleFunction = async (req, res, next) => {
    const url = req.url ?? "";
    if (!url.startsWith(PREFIX)) return next();

    const path = url.split("?")[0];
    const target = targetOf(url);
    if (!target) return send(res, 400, "text/plain", "missing u");

    try {
      if (path === `${PREFIX}img`) {
        const upstream = await fetch(target);
        if (!upstream.ok) return send(res, 502, "text/plain", `upstream HTTP ${upstream.status}`);
        let buf = await readBody(upstream);
        if (!imageKind(buf)) buf = decryptCover(buf);
        return send(res, 200, imageKind(buf) ?? "image/jpeg", buf);
      }

      if (path === `${PREFIX}hls`) {
        const upstream = await fetch(target);
        if (!upstream.ok) return send(res, 502, "text/plain", `upstream HTTP ${upstream.status}`);
        const text = await upstream.text();
        if (!text.replace(/^\uFEFF/, "").trimStart().startsWith("#EXTM3U")) {
          return send(res, 502, "text/plain", "响应不是 HLS 播放列表");
        }
        return send(res, 200, "application/vnd.apple.mpegurl", rewritePlaylist(target, text));
      }

      if (path === `${PREFIX}seg`) {
        const upstream = await fetch(target);
        if (!upstream.ok) return send(res, 502, "text/plain", `upstream HTTP ${upstream.status}`);
        const buf = await readBody(upstream);
        const type = upstream.headers.get("content-type") ?? "application/octet-stream";
        return send(res, 200, type, buf);
      }

      return send(res, 404, "text/plain", "not found");
    } catch (e) {
      return send(res, 502, "text/plain", (e as Error).message);
    }
  };

  return {
    name: "hghub-media-proxy",
    configureServer(server: ViteDevServer) {
      // api-proxy 必须先挂：/hg/* 与它路径不重叠，但顺序上更直观
      server.middlewares.use(apiProxy);
      server.middlewares.use(handler);
    },
  };
}
