//! `dx150-edge-v1` 加密通道：站点 2026-11 起用 ECDH P-256 + HKDF-SHA256 + AES-256-GCM
//! 取代了旧的 `POST /api/edge/request` 明文信封，老客户端因此全部 400/404。
//!
//! 协议（与站点前端 `static/web/js/edge-api-crypto.js` 对齐）：
//!
//! 1. 握手 `POST /api/{scope}/request`，明文 `{"v":1,"type":"hello","client_pub":"<b64url P-256 SPKI raw>"}`
//!    → `{"v":1,"type":"hello","kid","sid","server_pub","salt","site","server_time","expires_at"}`
//! 2. 共享密钥 = ECDH(client_priv, server_pub)（32 字节）
//! 3. `info = "dx150-edge-v1\n{scope}\n{site}\n{kid}\n{sid}"`
//!    请求键 = HKDF-SHA256(shared, salt, info+"\nreq", 32)
//!    响应键 = HKDF-SHA256(shared, salt, info+"\nres", 32)
//! 4. 每帧 `seq` 自增，`iv = 4 字节 0 || 8 字节大端 seq`，
//!    AAD = `"{info}\n{req|res}\n{seq}\n{ts}"`，`ts` 用服务端时钟校正。
//! 5. 明文 `{"request":{...},"authorization":"Bearer ..."}`；
//!    响应明文 `{"status":200,"headers":{...},"body":"<base64>"}`，`body` 里才是业务 JSON。
//!
//! 站点对 `scope` 有严格路由：`/api/videos` 走 public、`/videos/:id/play` 走 playback、
//! 搜索与详情走 dynamic、账号与互动走 user。走错 scope 会得到 400 `请求无法处理`。

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use p256::ecdh::EphemeralSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;
use serde_json::{json, Value};
use sha2::Sha256;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const PROTOCOL: &str = "dx150-edge-v1";
const MAX_SEQUENCE: u32 = 16384;

/// 站点按路径把 `/api/**` 分到四个加密入口；这里复刻它前端的路由表。
pub fn scope_for(method: &str, path: &str) -> &'static str {
    let method = method.trim().to_ascii_uppercase();
    let path_only = path.split('?').next().unwrap_or("");
    let segments: Vec<&str> = path_only.split('/').collect();

    for (scope, method_, pattern) in ROUTES {
        if *method_ != method {
            continue;
        }
        if matches_pattern(&segments, pattern) {
            return scope;
        }
    }
    // 兜底：站点前端映射不到 scope 时会退回 dynamic 入口。
    "dynamic"
}

/// `(` 起头的段是占位符；`:id`/`:cid`/`:ep` 必须是纯数字。
fn matches_pattern(segments: &[&str], pattern: &str) -> bool {
    let want: Vec<&str> = pattern.split('/').collect();
    if want.len() != segments.len() {
        return false;
    }
    want.iter().zip(segments).all(|(w, got)| {
        if *w == ":id" || *w == ":cid" || *w == ":ep" {
            !got.is_empty() && got.bytes().all(|b| b.is_ascii_digit())
        } else if w.starts_with(':') {
            !got.is_empty()
        } else {
            w == got
        }
    })
}

/// 静态路由优先于占位路由（站点前端同样按 dynamic 段数排序后匹配）。
static ROUTES: &[(&str, &str, &str)] = &[
    // playback（播放地址、预取）
    ("playback", "GET", "/api/videos/:id/play"),
    ("playback", "POST", "/api/videos/:id/playback"),
    ("playback", "POST", "/api/videos/:id/episodes/:ep/playback"),
    ("playback", "POST", "/api/posts/:id/playback"),
    ("playback", "POST", "/api/media/playback/previews"),
    ("playback", "POST", "/api/media/prerolls/:id/playback"),
    // user（账号、互动）
    ("user", "POST", "/api/account/loginByPassword"),
    ("user", "POST", "/api/account/registerByPassword"),
    ("user", "POST", "/api/account/logout"),
    ("user", "POST", "/api/account/password"),
    ("user", "GET", "/api/account/me"),
    ("user", "PATCH", "/api/account/profile"),
    ("user", "GET", "/api/users/me/collects"),
    ("user", "GET", "/api/users/me/comments"),
    ("user", "GET", "/api/users/me/follows"),
    ("user", "GET", "/api/users/me/history"),
    ("user", "POST", "/api/users/me/history"),
    ("user", "POST", "/api/users/me/history/delete"),
    ("user", "POST", "/api/users/me/history/sync"),
    ("user", "GET", "/api/users/me/likes"),
    ("user", "POST", "/api/users/me/likes/sync"),
    ("user", "GET", "/api/users/me/messages"),
    ("user", "DELETE", "/api/users/me/messages/:id"),
    ("user", "POST", "/api/users/me/messages/:id/read"),
    ("user", "POST", "/api/users/me/messages/batch-delete"),
    ("user", "POST", "/api/users/me/messages/read-all"),
    ("user", "GET", "/api/users/me/messages/unread-count"),
    ("user", "POST", "/api/users/:id/follow"),
    ("user", "DELETE", "/api/users/:id/follow"),
    ("user", "GET", "/api/videos/following"),
    ("user", "POST", "/api/videos/:id/like"),
    ("user", "DELETE", "/api/videos/:id/like"),
    ("user", "POST", "/api/videos/:id/collect"),
    ("user", "DELETE", "/api/videos/:id/collect"),
    ("user", "POST", "/api/videos/:id/comments"),
    ("user", "GET", "/api/videos/:id/comments"),
    ("user", "POST", "/api/videos/:id/comments/:cid/like"),
    ("user", "DELETE", "/api/videos/:id/comments/:cid/like"),
    ("user", "POST", "/api/videos/:id/comments/:cid/guest-like"),
    ("user", "GET", "/api/videos/:id/comments/liked"),
    ("user", "GET", "/api/videos/:id/comments/state"),
    ("user", "POST", "/api/videos/:id/guest-comments"),
    ("user", "POST", "/api/videos/:id/guest-like"),
    ("user", "GET", "/api/videos/:id/guest-liked"),
    ("user", "GET", "/api/videos/:id/interaction-state"),
    ("user", "GET", "/api/videos/:id/rating"),
    ("user", "POST", "/api/videos/:id/rating"),
    ("user", "POST", "/api/videos/:id/report"),
    ("user", "POST", "/api/videos/:id/feedback"),
    ("user", "POST", "/api/posts/:id/like"),
    ("user", "DELETE", "/api/posts/:id/like"),
    ("user", "POST", "/api/posts/:id/collect"),
    ("user", "DELETE", "/api/posts/:id/collect"),
    ("user", "POST", "/api/posts/:id/comments"),
    ("user", "GET", "/api/posts/:id/commentsliked"),
    ("user", "GET", "/api/posts/:id/comments/liked"),
    ("user", "POST", "/api/posts/:id/comments/:cid/like"),
    ("user", "DELETE", "/api/posts/:id/comments/:cid/like"),
    ("user", "POST", "/api/posts/:id/comments/:cid/guest-like"),
    ("user", "POST", "/api/posts/:id/guest-comments"),
    ("user", "POST", "/api/posts/:id/guest-like"),
    ("user", "GET", "/api/posts/:id/guest-liked"),
    ("user", "POST", "/api/posts/:id/visit"),
    ("user", "POST", "/api/ai-wish"),
    // dynamic（详情、搜索、首页、用户主页）
    ("dynamic", "GET", "/api/search"),
    ("dynamic", "GET", "/api/search/hot"),
    ("dynamic", "GET", "/api/search/suggest"),
    ("dynamic", "GET", "/api/search/tags/hot"),
    ("dynamic", "GET", "/api/home"),
    ("dynamic", "GET", "/api/posts/:id"),
    ("dynamic", "GET", "/api/posts/:id/comments"),
    ("dynamic", "POST", "/api/posts/:id/share"),
    ("dynamic", "GET", "/api/users/:id"),
    ("dynamic", "GET", "/api/videos/:id"),
    ("dynamic", "GET", "/api/videos/:id/comments"),
    ("dynamic", "GET", "/api/videos/:id/comments/:cid/replies"),
    ("dynamic", "GET", "/api/videos/:id/next"),
    ("dynamic", "POST", "/api/videos/:id/play"),
    ("dynamic", "POST", "/api/videos/:id/visit"),
    ("dynamic", "POST", "/api/videos/recommend"),
    ("dynamic", "POST", "/api/videos/recommend/ref/:ref"),
    ("dynamic", "POST", "/api/edge/image"),
    ("dynamic", "POST", "/api/media/covers"),
    ("dynamic", "GET", "/api/site/address-poster"),
    ("dynamic", "POST", "/api/site/click"),
    ("dynamic", "GET", "/api/site/entries"),
    ("dynamic", "GET", "/api/site/go-home"),
    ("dynamic", "POST", "/api/site/home-slots"),
    ("dynamic", "POST", "/api/stats/click"),
    ("dynamic", "POST", "/api/stats/origin"),
    ("dynamic", "GET", "/api/whoami"),
    // public（列表、排行、站点配置）
    ("public", "GET", "/api/videos"),
    ("public", "GET", "/api/videos/long"),
    ("public", "GET", "/api/videos/category/:route"),
    ("public", "GET", "/api/videos/sort/:route"),
    ("public", "GET", "/api/videos/tag/:tag"),
    ("public", "GET", "/api/videos/user/:id"),
    ("public", "GET", "/api/videos/:id/related"),
    ("public", "GET", "/api/videos/report-reasons"),
    ("public", "GET", "/api/posts"),
    ("public", "GET", "/api/posts/category/:route"),
    ("public", "GET", "/api/posts/tag/:tag"),
    ("public", "GET", "/api/posts/user/:id"),
    ("public", "GET", "/api/posts/:id/adjacent"),
    ("public", "GET", "/api/posts/:id/related"),
    ("public", "GET", "/api/ranks/:type"),
    ("public", "GET", "/api/feed/today"),
    ("public", "GET", "/api/feed/recommend"),
    ("public", "GET", "/api/feed/post/today"),
    ("public", "GET", "/api/home/latest"),
    ("public", "GET", "/api/home/recommends"),
    ("public", "GET", "/api/tags"),
    ("public", "GET", "/api/topics"),
    ("public", "GET", "/api/topics/:slug"),
    ("public", "GET", "/api/users/:id/stats"),
    ("public", "GET", "/api/site/categories/video"),
    ("public", "GET", "/api/site/categories/post"),
    ("public", "GET", "/api/site/config"),
    ("public", "GET", "/api/site/links"),
    ("public", "GET", "/api/site/menus"),
    ("public", "GET", "/api/site/meta"),
    ("public", "GET", "/api/site/pages"),
    ("public", "GET", "/api/site/pages/:slug"),
    ("public", "GET", "/api/site/sorts/video"),
    ("public", "GET", "/api/site/transit"),
    ("public", "GET", "/api/site/watermark"),
];

/// 一次握手得到的会话。
pub struct Session {
    pub scope: String,
    pub kid: String,
    pub sid: String,
    /// 握手响应里服务端自报的站点名，用于排查「握到了别的站」。
    #[allow(dead_code)]
    pub site: String,
    info: String,
    req_key: [u8; 32],
    res_key: [u8; 32],
    sequence: u32,
    clock_offset: i64,
    expires_at: u64,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hkdf(shared: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), shared);
    // 32 字节输出对 HKDF-SHA256 永远合法。
    let _ = hk.expand(info, &mut out);
    out
}

/// 校验握手响应。站点前端的检查项一个不少，避免把畸形响应当成可用会话。
pub fn parse_hello(scope: &str, value: &Value) -> Result<(String, String, String, Vec<u8>, Vec<u8>, u64, u64), String> {
    let err = || "加密握手响应无效".to_string();
    if value.get("v").and_then(Value::as_u64) != Some(1)
        || value.get("type").and_then(Value::as_str) != Some("hello")
    {
        return Err(err());
    }
    let kid = value.get("kid").and_then(Value::as_str).ok_or_else(err)?;
    if kid.is_empty() || kid.len() > 64 {
        return Err(err());
    }
    let sid = value.get("sid").and_then(Value::as_str).ok_or_else(err)?;
    if sid.len() < 16 || sid.len() > 128 {
        return Err(err());
    }
    let site = value.get("site").and_then(Value::as_str).ok_or_else(err)?;
    if site.is_empty() || site.len() > 256 {
        return Err(err());
    }
    let server_pub = B64URL
        .decode(value.get("server_pub").and_then(Value::as_str).ok_or_else(err)?)
        .map_err(|_| err())?;
    let salt = B64URL
        .decode(value.get("salt").and_then(Value::as_str).ok_or_else(err)?)
        .map_err(|_| err())?;
    if salt.len() != 32 {
        return Err(err());
    }
    let server_time = value.get("server_time").and_then(Value::as_i64).ok_or_else(err)?;
    let expires_at = value.get("expires_at").and_then(Value::as_i64).ok_or_else(err)?;
    if expires_at <= server_time || expires_at - server_time > 600 {
        return Err(err());
    }
    Ok((
        scope.to_string(),
        kid.to_string(),
        sid.to_string(),
        server_pub,
        salt,
        server_time as u64,
        expires_at as u64,
    ))
}

impl Session {
    /// 用握手响应和客户端私钥建立密钥。
    pub fn establish(
        scope: &str,
        secret: &EphemeralSecret,
        hello: &Value,
    ) -> Result<Self, String> {
        let (scope, kid, sid, server_pub, salt, server_time, expires_at) =
            parse_hello(scope, hello)?;
        let peer = PublicKey::from_sec1_bytes(&server_pub).map_err(|_| "加密握手响应无效".to_string())?;
        let shared = secret.diffie_hellman(&peer);
        let info = [
            PROTOCOL.to_string(),
            scope.clone(),
            hello["site"].as_str().unwrap_or_default().to_string(),
            kid.clone(),
            sid.clone(),
        ]
        .join("\n");
        let req_key = hkdf(shared.raw_secret_bytes(), &salt, format!("{info}\nreq").as_bytes());
        let res_key = hkdf(shared.raw_secret_bytes(), &salt, format!("{info}\nres").as_bytes());
        let site = hello["site"].as_str().unwrap_or_default().to_string();
        let local = now_secs() as i64;
        Ok(Self {
            scope,
            kid,
            sid,
            site,
            info,
            req_key,
            res_key,
            sequence: 0,
            clock_offset: server_time as i64 - local,
            expires_at: local as u64 + expires_at - server_time,
        })
    }

    pub fn usable(&self) -> bool {
        self.expires_at > now_secs() + 5 && self.sequence < MAX_SEQUENCE
    }

    fn nonce(sequence: u32) -> [u8; 12] {
        let mut iv = [0u8; 12];
        iv[8..].copy_from_slice(&sequence.to_be_bytes());
        iv
    }

    fn aad(&self, direction: &str, sequence: u32, timestamp: i64) -> Vec<u8> {
        format!("{}\n{}\n{}\n{}", self.info, direction, sequence, timestamp).into_bytes()
    }

    /// 加密一帧请求，返回 (seq, ts, ciphertext b64url)。
    pub fn seal(&mut self, method: &str, path: &str, body: &[u8], content_type: &str, token: Option<&str>) -> Result<(u32, i64, String), String> {
        let sequence = self.sequence + 1;
        if sequence > MAX_SEQUENCE {
            return Err("加密会话已到期".into());
        }
        self.sequence = sequence;
        let timestamp = now_secs() as i64 + self.clock_offset;

        let mut request = json!({
            "method": method.trim().to_ascii_uppercase(),
            "path": path,
            "body": B64.encode(body),
            "content_type": content_type,
        });
        if self.scope == "public" {
            // public 入口不接受来源字段，站点前端同样会清掉它们。
            request.as_object_mut().map(|o| o.remove("visitor_id"));
        }
        let mut packet = json!({ "request": request });
        if self.scope != "public" {
            if let Some(t) = token.filter(|t| !t.is_empty()) {
                packet["authorization"] = json!(format!("Bearer {t}"));
            }
        }

        let cipher = Aes256Gcm::new_from_slice(&self.req_key).map_err(|_| "加密会话失效".to_string())?;
        let iv = Self::nonce(sequence);
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&iv),
                Payload {
                    msg: packet.to_string().as_bytes(),
                    aad: &self.aad("req", sequence, timestamp),
                },
            )
            .map_err(|_| "请求加密失败".to_string())?;
        Ok((sequence, timestamp, B64URL.encode(ct)))
    }

    /// 解密一帧响应，返回内层 `{status, headers, body}`。
    pub fn open(&self, response: &Value, sequence: u32, timestamp: i64) -> Result<Value, String> {
        let err = || "加密响应无效".to_string();
        if response.get("v").and_then(Value::as_u64) != Some(1)
            || response.get("type").and_then(Value::as_str) != Some("result")
            || response.get("sid").and_then(Value::as_str) != Some(self.sid.as_str())
            || response.get("kid").and_then(Value::as_str) != Some(self.kid.as_str())
            || response.get("seq").and_then(Value::as_u64) != Some(sequence as u64)
            || response.get("ts").and_then(Value::as_i64) != Some(timestamp)
        {
            return Err(err());
        }
        let raw = B64URL
            .decode(response.get("ciphertext").and_then(Value::as_str).ok_or_else(err)?)
            .map_err(|_| err())?;
        let cipher = Aes256Gcm::new_from_slice(&self.res_key).map_err(|_| err())?;
        let iv = Self::nonce(sequence);
        let plain = cipher
            .decrypt(
                Nonce::from_slice(&iv),
                Payload {
                    msg: &raw,
                    aad: &self.aad("res", sequence, timestamp),
                },
            )
            .map_err(|_| err())?;
        let inner: Value = serde_json::from_slice(&plain).map_err(|_| err())?;
        let status = inner.get("status").and_then(Value::as_u64).ok_or_else(err)?;
        if !(200..=599).contains(&status) {
            return Err(err());
        }
        if !inner.get("headers").is_some_and(Value::is_object) {
            return Err(err());
        }
        Ok(inner)
    }

    /// 内层 `body` 是 base64 的业务 JSON。
    pub fn body_of(inner: &Value) -> Result<String, String> {
        let raw = inner.get("body").and_then(Value::as_str).unwrap_or("");
        if raw.is_empty() {
            return Ok(String::new());
        }
        let bytes = B64.decode(raw).map_err(|_| "业务响应体无法解码".to_string())?;
        String::from_utf8(bytes).map_err(|_| "业务响应体不是 UTF-8".to_string())
    }
}

/// 新建一次握手的客户端私钥。
pub fn new_secret() -> EphemeralSecret {
    EphemeralSecret::random(&mut rand_core::OsRng)
}

/// 取客户端公钥（未压缩 SEC1 点，站点用 `exportKey('raw')` 得到的同样是这段）。
pub fn public_of(secret: &EphemeralSecret) -> String {
    B64URL.encode(secret.public_key().to_encoded_point(false).as_bytes())
}

/// 会话空转多久算过期（站点给的是 600 秒上限，这里按握手给的 expires_at 判断）。
#[allow(dead_code)]
pub const SESSION_TTL: Duration = Duration::from_secs(600);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_routing_matches_site_table() {
        assert_eq!(scope_for("GET", "/api/videos?page=1&size=20"), "public");
        assert_eq!(scope_for("GET", "/api/videos/12"), "dynamic");
        assert_eq!(scope_for("GET", "/api/videos/12/play?ep=1"), "playback");
        assert_eq!(scope_for("GET", "/api/videos/12/comments?ep=1&page=1"), "user");
        assert_eq!(scope_for("POST", "/api/videos/12/like?ep=1"), "user");
        assert_eq!(scope_for("POST", "/api/account/loginByPassword"), "user");
        assert_eq!(scope_for("GET", "/api/account/me"), "user");
        assert_eq!(scope_for("GET", "/api/search?q=abc"), "dynamic");
        assert_eq!(scope_for("GET", "/api/posts?page=1&size=10"), "public");
        assert_eq!(scope_for("GET", "/api/posts/9"), "dynamic");
        assert_eq!(scope_for("GET", "/api/ranks/hot"), "public");
        assert_eq!(scope_for("GET", "/api/videos/category/douyin?page=1"), "public");
    }

    #[test]
    fn numeric_placeholders_require_digits() {
        // /api/videos/category/<route> 是字符串占位，不能落进 :id 规则。
        assert_eq!(scope_for("GET", "/api/videos/category/abc"), "public");
        // `:id` 必须是数字：非数字时也命中 public 的同构路由之前不会误判成 dynamic 详情。
        assert_eq!(scope_for("GET", "/api/videos/abc"), "dynamic");
        // 站点前端对不上的路径会退到 dynamic 入口，客户端保持同样兜底。
        assert_eq!(scope_for("GET", "/api/users/abc/stats"), "dynamic");
        assert_eq!(scope_for("GET", "/api/users/12/stats"), "public");
    }

    #[test]
    fn nonce_uses_big_endian_sequence_in_last_eight_bytes() {
        let iv = Session::nonce(258);
        assert_eq!(iv, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2]);
    }

    #[test]
    fn hkdf_separates_directions() {
        let shared = [7u8; 32];
        let salt = [3u8; 32];
        let req = hkdf(&shared, &salt, b"info\nreq");
        let res = hkdf(&shared, &salt, b"info\nres");
        assert_ne!(req, res);
    }

    #[test]
    fn hello_validation_rejects_malformed_payloads() {
        let good = json!({
            "v": 1, "type": "hello", "kid": "v20261109", "sid": "abcdefghijklmnop",
            "site": "example.com", "server_pub": "AA", "salt": B64URL.encode([0u8; 32]),
            "server_time": 100, "expires_at": 400,
        });
        assert!(parse_hello("public", &good).is_ok());
        for bad in [
            json!({"v": 2, "type": "hello"}),
            json!({"v": 1, "type": "call"}),
        ] {
            assert!(parse_hello("public", &bad).is_err());
        }
        let mut short_sid = good.clone();
        short_sid["sid"] = json!("short");
        assert!(parse_hello("public", &short_sid).is_err());
        let mut bad_window = good.clone();
        bad_window["expires_at"] = json!(900);
        assert!(parse_hello("public", &bad_window).is_err());
        let mut bad_salt = good.clone();
        bad_salt["salt"] = json!(B64URL.encode([0u8; 16]));
        assert!(parse_hello("public", &bad_salt).is_err());
    }
}
