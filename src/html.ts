import { LOCAL } from "./api";
import DOMPurify from "dompurify";

/** 站点根地址：正文里的相对路径要补全（.com 已下线，官方现用 .io） */
const SITE = "https://huangguoai.io";
// 启动前默认严格；有效状态只由 Rust app_boot / security_set 返回值更新。
let strictSecurity = true;

/** 当前是否启用严格安全模式（默认开启）。 */
export function isStrictSecurity(): boolean {
  return strictSecurity;
}

/** 切换严格安全模式（关闭后回退为兼容清洗与链接策略）。 */
export function setStrictSecurity(strict: boolean): void {
  strictSecurity = strict;

}

function isInternalWebviewHost(host: string): boolean {
  const h = host.replace(/\.+$/, "").toLowerCase();
  return h === "tauri.localhost" || h === "hg.localhost" || h === "ipc.localhost";
}

function isPrivateOrLocalHost(host: string): boolean {
  const h = host.replace(/\.+$/, "").toLowerCase();
  if (!h || isInternalWebviewHost(h)) return true;
  if (["localhost", "local", "internal", "home.arpa"].some((s) => h === s || h.endsWith(`.${s}`))) {
    return true;
  }
  if (h.startsWith("[") && h.endsWith("]")) {
    const v6 = h.slice(1, -1).toLowerCase();
    if (v6 === "::1" || v6 === "::" || v6.startsWith("fe80:") || v6.startsWith("fc") || v6.startsWith("fd") || v6.startsWith("::ffff:")) {
      return true;
    }
    return false;
  }
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (m) {
    const [a, b, c] = [Number(m[1]), Number(m[2]), Number(m[3])];
    if (a === 198 && (b === 18 || b === 19)) return false;
    if (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 192 && b === 0 && (c === 0 || c === 2)) ||
      (a === 192 && b === 88 && c === 99) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113)
    ) {
      return true;
    }
  }
  return false;
}

/** 把各种写法的图片地址补成绝对地址；占位符（data:）返回空串 */
function abs(raw: string, strict = strictSecurity): string {
  const s = (raw || "").trim();
  if (!s) return "";
  try {
    const url = new URL(s, SITE);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return "";
    if (isInternalWebviewHost(url.hostname)) return "";
    if (strict && isPrivateOrLocalHost(url.hostname)) return "";
    return url.href;
  } catch { return ""; }
}

/** 把正文里的图片换成走本地协议（带 Referer / 解密能力） */
function proxyImages(html: string, strict = strictSecurity): string {
  if (!html) return "";
  const doc = new DOMParser().parseFromString(html, "text/html");
  const imgPrefix = `${LOCAL}/img?u=`;
  doc.querySelectorAll("img").forEach((img) => {
    // 懒加载图：真实地址常在 data-* 上，src 只是占位
    const candidate =
      img.getAttribute("data-src") ||
      img.getAttribute("data-original") ||
      img.getAttribute("data-lazy-src") ||
      img.getAttribute("src") ||
      "";
    let raw = candidate.trim();
    if (raw.startsWith(imgPrefix)) {
      try { raw = decodeURIComponent(raw.slice(imgPrefix.length)); } catch { raw = ""; }
    }
    const src = abs(raw, strict);
    if (!src) {
      img.remove();
      return;
    }
    img.setAttribute("src", `${imgPrefix}${encodeURIComponent(src)}`);
    img.removeAttribute("srcset");
    img.removeAttribute("data-src");
    img.removeAttribute("data-original");
    img.removeAttribute("data-lazy-src");
    img.removeAttribute("loading");
    img.setAttribute("loading", "lazy");
  });
  // 正文链接补全，避免点开指向本地
  doc.querySelectorAll("a[href]").forEach((a) => {
    const href = (a.getAttribute("href") || "").trim();
    const full = abs(href, strict);
    if (full) {
      a.setAttribute("href", full);
      a.setAttribute("target", "_blank");
      a.setAttribute("rel", "noopener noreferrer");
    } else a.removeAttribute("href");
  });
  return doc.body.innerHTML;
}

const STRICT_TAGS = [
  "p", "div", "span", "br", "hr", "h1", "h2", "h3", "h4", "h5", "h6",
  "ul", "ol", "li", "blockquote", "strong", "b", "em", "i", "u", "s", "del", "pre", "code",
  "a", "img", "figure", "figcaption", "table", "thead", "tbody", "tr", "th", "td",
];
const STRICT_INPUT_ATTR = [
  "href", "src", "alt", "title", "colspan", "rowspan", "start",
  "data-src", "data-original", "data-lazy-src",
];
const STRICT_FINAL_ATTR = [
  "href", "src", "alt", "title", "colspan", "rowspan", "start", "target", "rel", "loading",
];
// 保留 DOMPurify 的安全 URL/普通属性值规则，并允许本应用的 macOS 图片协议。
const SAFE_FINAL_URI = /^(?:(?:https?|ftp|ftps|tel|mailto|callto|sms|cid|xmpp|matrix):|hg:\/\/localhost\/|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i;

/** 正文只接受所需 HTML 排版，不允许 SVG/MathML、事件、样式和可执行 URL。 */
export function sanitizeHtml(html: string): string {
  // 不支持清洗器的旧 WebView 必须拒绝正文，不能回退为原样渲染。
  if (!html || !DOMPurify.isSupported) return "";
  if (!strictSecurity) {
    const pre = DOMPurify.sanitize(html, {
      USE_PROFILES: { html: true },
      ADD_ATTR: ["data-src", "data-original", "data-lazy-src"],
      ALLOWED_URI_REGEXP: SAFE_FINAL_URI,
    });
    const rewritten = proxyImages(pre, false);
    return DOMPurify.sanitize(rewritten, {
      USE_PROFILES: { html: true },
      ADD_ATTR: ["target", "rel", "loading"],
      ALLOWED_URI_REGEXP: SAFE_FINAL_URI,
    });
  }
  const clean = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: STRICT_TAGS,
    ALLOWED_ATTR: STRICT_INPUT_ATTR,
    ALLOWED_URI_REGEXP: SAFE_FINAL_URI,
    ALLOW_DATA_ATTR: false,
    ALLOW_ARIA_ATTR: false,
    FORBID_TAGS: ["svg", "math"],
  });
  const rewritten = proxyImages(clean, true);
  // DOMPurify 作为进入 dangerouslySetInnerHTML 前的最后一步，避免二次解析引入差异。
  return DOMPurify.sanitize(rewritten, {
    ALLOWED_TAGS: STRICT_TAGS,
    ALLOWED_ATTR: STRICT_FINAL_ATTR,
    ALLOW_DATA_ATTR: false,
    ALLOW_ARIA_ATTR: false,
    FORBID_TAGS: ["svg", "math"],
    ALLOWED_URI_REGEXP: SAFE_FINAL_URI,
  });
}

/** 拦截正文内链接点击，防止 WebView 原地跳转或弹出无守卫新窗口 */
export function handleArticleClick(
  e: { target: EventTarget | null; preventDefault: () => void; stopPropagation: () => void },
  onOpenUrl?: (url: string) => void,
): void {
  const el = e.target instanceof Element ? e.target.closest("a") : null;
  if (!el) return;
  e.preventDefault();
  e.stopPropagation();
  const href = abs(el.getAttribute("href") || "", strictSecurity);
  if (href && onOpenUrl) onOpenUrl(href);
}
