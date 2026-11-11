//! 线路（数据源）：固定线路 + 地址发布页上的镜像线路。
//!
//! 上游只是域名在变，请求链路与数据模型完全一致，所以「切线路」等价于换 `net::base()`。
//! 镜像地址来自 <https://huangguoai.pages.dev/>：那个页面本身是空壳，真正的清单在
//! `publish.js` 里（`var urls` 域名数组 + `var subdomains` 子域数组，页面自己随机拼）。

use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// 固定线路：写死在客户端里，不依赖任何外部页面。
///
/// 2026-11 起 `huangguoai.com` 与 `huangguoai.ai` 都不再提供加密接口
/// （`.com` 直接连不上，`.ai` 对 `/api/*/request` 返回 nginx 404），
/// 站点当前在 `huangguoai.io` 提供服务，所以把它放在第一位。
pub const FIXED: [(&str, &str); 3] = [
    ("固定线路 1", "https://huangguoai.io"),
    ("固定线路 2", "https://huangguoai.com"),
    ("固定线路 3", "https://huangguoai.ai"),
];

const PUBLISH_PAGE: &str = "https://huangguoai.pages.dev/";
/// 镜像列表上限（子域 × 域名是笛卡尔积，界面只展示这么多）
const MIRROR_MAX: usize = 60;
/// 单条线路探测超时。
///
/// 站点页面本身 150 KB 左右，境外 CDN 回国内链路波动大，8 秒会把「能通但慢」误判成
/// 不可用，用户就会以为线路全挂了。留 15 秒。
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

pub fn fixed() -> Value {
    json!(FIXED
        .iter()
        .map(|(name, url)| json!({ "name": name, "url": url }))
        .collect::<Vec<_>>())
}

/// 拉地址发布页 → 解析 publish.js → 拼出镜像地址。只在用户点开「线路」时调用。
pub async fn mirrors() -> Result<Value, String> {
    let html = get_text(PUBLISH_PAGE).await?;
    let js_rel = script_src(&html).unwrap_or_else(|| "publish.js".to_string());
    let js_url = absolute(PUBLISH_PAGE, &js_rel);
    let js = get_text(&js_url).await?;

    let domains = js_array(&js, "var urls");
    let subs = js_array(&js, "var subdomains");
    if domains.is_empty() {
        return Err("地址发布页格式有变化：没找到镜像域名".to_string());
    }

    let mut items: Vec<Value> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    'outer: for domain in domains {
        let domain = domain.trim_end_matches('/').to_string();
        if domain.is_empty() {
            continue;
        }
        let hosts: Vec<String> = if subs.is_empty() {
            vec![domain.clone()]
        } else {
            subs.iter().map(|s| format!("{s}.{domain}")).collect()
        };
        for host in hosts {
            if !seen.insert(host.clone()) {
                continue;
            }
            items.push(json!({ "url": format!("https://{host}"), "host": host }));
            if items.len() >= MIRROR_MAX {
                break 'outer;
            }
        }
    }
    if items.is_empty() {
        return Err("地址发布页里没有可用的镜像地址".to_string());
    }

    Ok(json!({ "source": PUBLISH_PAGE, "script": js_url, "items": items }))
}

/// 可达性探测（并发 6 条一组）。只报结果，不做自动切换。
pub async fn probe(urls: Vec<String>) -> Value {    let mut out: Vec<Value> = Vec::new();
    for chunk in urls.chunks(6) {
        let mut handles = Vec::new();
        for u in chunk {
            let u = u.clone();
            handles.push(tokio::spawn(async move { probe_one(u).await }));
        }
        for h in handles {
            if let Ok(v) = h.await {
                out.push(v);
            }
        }
    }
    json!(out)
}

async fn probe_one(url: String) -> Value {
    let target = format!("{}/", url.trim_end_matches('/'));
    let started = Instant::now();
    // 只取响应头就算通：线路页动辄 150 KB，整页读完会把「能通但慢」判成不可用。
    let res = crate::net::head(&target, PROBE_TIMEOUT).await;
    let ms = started.elapsed().as_millis() as u64;
    match res {
        Ok(status) => json!({ "url": url, "ok": status < 400, "status": status, "ms": ms }),
        Err(e) => json!({ "url": url, "ok": false, "ms": ms, "error": e }),
    }
}

async fn get_text(url: &str) -> Result<String, String> {
    let resp = crate::net::get(url, Duration::from_secs(12), None, None).await?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {}", resp.status()));
    }
    resp.text().await.map_err(|e| crate::net::err_text(&e))
}

/// 从 HTML 里挑出脚本地址（发布页只有一个 `publish.js?<版本>`）。
fn script_src(html: &str) -> Option<String> {
    let mut rest = html;
    while let Some(i) = rest.find("src=\"") {
        let after = &rest[i + 5..];
        let end = after.find('"')?;
        let candidate = &after[..end];
        if candidate.contains(".js") {
            return Some(candidate.to_string());
        }
        rest = &after[end..];
    }
    None
}

fn absolute(base: &str, rel: &str) -> String {
    if rel.starts_with("http://") || rel.starts_with("https://") {
        return rel.to_string();
    }
    let origin = url::Url::parse(base)
        .ok()
        .map(|u| format!("{}://{}", u.scheme(), u.host_str().unwrap_or_default()));
    match origin {
        Some(o) if rel.starts_with('/') => format!("{o}{rel}"),
        Some(o) => format!("{o}/{rel}"),
        None => rel.to_string(),
    }
}

/// 取 JS 里 `var <name> = [ ... ]` 的字符串数组（去掉行尾 `//` 注释，但保留字符串里的 `//`）。
fn js_array(src: &str, decl: &str) -> Vec<String> {
    let Some(at) = src.find(decl) else {
        return Vec::new();
    };
    let rest = &src[at..];
    let Some(open) = rest.find('[') else {
        return Vec::new();
    };
    let Some(close) = rest[open..].find(']') else {
        return Vec::new();
    };
    strip_line_comments(&rest[open + 1..open + close])
        .split(',')
        .map(|raw| {
            raw.trim()
                .trim_matches(|c: char| c == '\'' || c == '"')
                .trim()
                .to_string()
        })
        .filter(|s| !s.is_empty())
        .collect()
}

/// 去掉 `//` 行尾注释（引号内的 `//` 是 URL，不能动）。
fn strip_line_comments(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut quote: Option<char> = None;
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        match quote {
            Some(q) => {
                out.push(c);
                if c == q {
                    quote = None;
                }
            }
            None => {
                if c == '\'' || c == '"' {
                    quote = Some(c);
                    out.push(c);
                } else if c == '/' && chars.peek() == Some(&'/') {
                    for n in chars.by_ref() {
                        if n == '\n' {
                            out.push('\n');
                            break;
                        }
                    }
                } else {
                    out.push(c);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
var subdomains = [
    'thu',  // 清华
    'pku',  // 北大
];
var urls=[
	'xxbgwypx.cc/',
];
var otherUrls = [
	'https://huangguoai.pages.dev',
];
var foreverUrls = [
	  'https://huangguoai.com',
	JumpPage,
	'https://huangguoai.ai',
];
"#;

    #[test]
    fn parses_publish_js_arrays() {
        assert_eq!(js_array(SAMPLE, "var urls"), vec!["xxbgwypx.cc/"]);
        assert_eq!(js_array(SAMPLE, "var subdomains"), vec!["thu", "pku"]);
        assert_eq!(
            js_array(SAMPLE, "var foreverUrls"),
            vec![
                "https://huangguoai.com",
                "JumpPage",
                "https://huangguoai.ai"
            ]
        );
    }

    #[test]
    fn resolves_relative_script() {
        assert_eq!(
            absolute("https://huangguoai.pages.dev/", "publish.js?20261103-2"),
            "https://huangguoai.pages.dev/publish.js?20261103-2"
        );
        assert_eq!(
            absolute("https://huangguoai.pages.dev/", "/a/b.js"),
            "https://huangguoai.pages.dev/a/b.js"
        );
    }

    #[test]
    fn picks_script_src() {
        let html = r#"<link rel="stylesheet" href="publish.css?1" /><script type="text/javascript" src="publish.js?20261103-2"></script>"#;
        assert_eq!(script_src(html).as_deref(), Some("publish.js?20261103-2"));
    }

    /// 手动跑：`cargo test --lib -- --ignored lines::tests::mirrors_live -- --nocapture`
    #[tokio::test]
    #[ignore = "联网测试：请求上游镜像列表，手动用 --ignored 运行"]
    async fn mirrors_live() {
        match mirrors().await {
            Ok(v) => println!("{}", serde_json::to_string_pretty(&v).expect("json")),
            Err(e) => panic!("mirrors failed: {e}"),
        }
    }

    /// 手动跑：`cargo test --lib -- --ignored lines::tests::probe_live -- --nocapture`
    #[tokio::test]
    #[ignore = "联网测试：探测上游线路连通性，手动用 --ignored 运行"]
    async fn probe_live() {
        let urls = vec![
            "https://huangguoai.com".to_string(),
            "https://huangguoai.ai".to_string(),
            "https://thu.xxbgwypx.cc".to_string(),
        ];
        println!(
            "{}",
            serde_json::to_string_pretty(&probe(urls).await).expect("json")
        );
    }
}
