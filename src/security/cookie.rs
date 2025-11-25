//! 安全 Cookie 助手模块
//!
//! 提供安全的 Cookie 签名和验证功能，包括：
//!
//! - **Cookie 签名**: 使用 HMAC-SHA256 签名 Cookie 值
//! - **Cookie 验证**: 验证签名并提取原始值
//! - **安全属性封装**: SecureCookie 结构体封装安全属性
//!
//! ## 使用示例
//!
//! ### 基本签名与验证
//!
//! ```rust
//! use authrs::security::cookie::{sign_cookie, verify_cookie};
//!
//! let secret = b"my-secret-key-at-least-32-bytes!";
//! let value = "user_session_data";
//!
//! // 签名 Cookie 值
//! let signed = sign_cookie(value, secret);
//!
//! // 验证并提取原始值
//! let original = verify_cookie(&signed, secret).unwrap();
//! assert_eq!(original, value);
//! ```
//!
//! ### 使用 SecureCookie
//!
//! ```rust
//! use authrs::security::cookie::{SecureCookie, SameSite};
//! use std::time::Duration;
//!
//! let cookie = SecureCookie::new("session", "abc123")
//!     .http_only(true)
//!     .secure(true)
//!     .same_site(SameSite::Strict)
//!     .max_age(Duration::from_secs(3600))
//!     .path("/")
//!     .domain("example.com");
//!
//! // 生成 Set-Cookie 头
//! let header = cookie.to_header_value();
//! ```
//!
//! ### 签名的 SecureCookie
//!
//! ```rust
//! use authrs::security::cookie::{SecureCookie, SameSite};
//!
//! let secret = b"my-secret-key-at-least-32-bytes!";
//!
//! // 创建并签名
//! let cookie = SecureCookie::new("session", "user123")
//!     .http_only(true)
//!     .secure(true)
//!     .signed(secret);
//!
//! // 验证签名值
//! let verified = cookie.verify_value(secret).unwrap();
//! assert_eq!(verified, "user123");
//! ```

use crate::{Error, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::time::Duration;

type HmacSha256 = Hmac<Sha256>;

/// 签名分隔符
const SIGNATURE_SEPARATOR: &str = ".";

/// SameSite Cookie 属性
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum SameSite {
    /// 严格模式：Cookie 只在同站请求时发送
    Strict,
    /// 宽松模式：允许顶级导航的跨站请求
    #[default]
    Lax,
    /// 无限制：所有请求都发送 Cookie（需要 Secure 属性）
    None,
}

impl std::fmt::Display for SameSite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SameSite::Strict => write!(f, "Strict"),
            SameSite::Lax => write!(f, "Lax"),
            SameSite::None => write!(f, "None"),
        }
    }
}

/// 安全 Cookie 结构
///
/// 封装 Cookie 的所有安全相关属性
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureCookie {
    /// Cookie 名称
    pub name: String,
    /// Cookie 值
    pub value: String,
    /// HttpOnly 属性（防止 JavaScript 访问）
    #[serde(default)]
    pub http_only: bool,
    /// Secure 属性（仅通过 HTTPS 发送）
    #[serde(default)]
    pub secure: bool,
    /// SameSite 属性
    #[serde(default)]
    pub same_site: SameSite,
    /// Max-Age 属性（秒）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_age: Option<Duration>,
    /// Expires 属性
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// Path 属性
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Domain 属性
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// 是否已签名
    #[serde(default)]
    is_signed: bool,
    /// 原始值（签名前）
    #[serde(skip_serializing_if = "Option::is_none")]
    original_value: Option<String>,
}

impl SecureCookie {
    /// 创建新的安全 Cookie
    ///
    /// # 参数
    ///
    /// - `name`: Cookie 名称
    /// - `value`: Cookie 值
    ///
    /// # 示例
    ///
    /// ```rust
    /// use authrs::security::cookie::SecureCookie;
    ///
    /// let cookie = SecureCookie::new("session", "abc123");
    /// ```
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            http_only: false,
            secure: false,
            same_site: SameSite::Lax,
            max_age: None,
            expires: None,
            path: None,
            domain: None,
            is_signed: false,
            original_value: None,
        }
    }

    /// 创建安全会话 Cookie（推荐默认值）
    ///
    /// 设置 HttpOnly、Secure、SameSite=Strict
    pub fn session(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self::new(name, value)
            .http_only(true)
            .secure(true)
            .same_site(SameSite::Strict)
    }

    /// 设置 HttpOnly 属性
    pub fn http_only(mut self, http_only: bool) -> Self {
        self.http_only = http_only;
        self
    }

    /// 设置 Secure 属性
    pub fn secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    /// 设置 SameSite 属性
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        self
    }

    /// 设置 Max-Age 属性
    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }

    /// 设置 Max-Age（秒）
    pub fn max_age_secs(mut self, secs: u64) -> Self {
        self.max_age = Some(Duration::from_secs(secs));
        self
    }

    /// 设置 Expires 属性（RFC 7231 格式）
    pub fn expires(mut self, expires: impl Into<String>) -> Self {
        self.expires = Some(expires.into());
        self
    }

    /// 设置 Path 属性
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    /// 设置 Domain 属性
    pub fn domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    /// 对 Cookie 值进行签名
    ///
    /// # 参数
    ///
    /// - `secret`: 签名密钥（推荐至少 32 字节）
    ///
    /// # 示例
    ///
    /// ```rust
    /// use authrs::security::cookie::SecureCookie;
    ///
    /// let secret = b"my-secret-key-at-least-32-bytes!";
    /// let cookie = SecureCookie::new("session", "user123").signed(secret);
    ///
    /// assert!(cookie.value().contains("."));
    /// ```
    pub fn signed(mut self, secret: &[u8]) -> Self {
        self.original_value = Some(self.value.clone());
        self.value = sign_cookie(&self.value, secret);
        self.is_signed = true;
        self
    }

    /// 获取 Cookie 名称
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 获取 Cookie 值
    pub fn value(&self) -> &str {
        &self.value
    }

    /// 检查是否已签名
    pub fn is_signed(&self) -> bool {
        self.is_signed
    }

    /// 验证签名并获取原始值
    ///
    /// # 参数
    ///
    /// - `secret`: 签名密钥
    ///
    /// # 返回
    ///
    /// 如果签名有效，返回原始值；否则返回错误
    pub fn verify_value(&self, secret: &[u8]) -> Result<String> {
        verify_cookie(&self.value, secret)
    }

    /// 生成 Set-Cookie 头值
    ///
    /// # 示例
    ///
    /// ```rust
    /// use authrs::security::cookie::{SecureCookie, SameSite};
    /// use std::time::Duration;
    ///
    /// let cookie = SecureCookie::new("session", "abc123")
    ///     .http_only(true)
    ///     .secure(true)
    ///     .same_site(SameSite::Strict)
    ///     .max_age(Duration::from_secs(3600))
    ///     .path("/");
    ///
    /// let header = cookie.to_header_value();
    /// assert!(header.contains("session=abc123"));
    /// assert!(header.contains("HttpOnly"));
    /// assert!(header.contains("Secure"));
    /// ```
    pub fn to_header_value(&self) -> String {
        let mut parts = vec![format!("{}={}", self.name, self.value)];

        if self.http_only {
            parts.push("HttpOnly".to_string());
        }

        if self.secure {
            parts.push("Secure".to_string());
        }

        parts.push(format!("SameSite={}", self.same_site));

        if let Some(ref max_age) = self.max_age {
            parts.push(format!("Max-Age={}", max_age.as_secs()));
        }

        if let Some(ref expires) = self.expires {
            parts.push(format!("Expires={}", expires));
        }

        if let Some(ref path) = self.path {
            parts.push(format!("Path={}", path));
        }

        if let Some(ref domain) = self.domain {
            parts.push(format!("Domain={}", domain));
        }

        parts.join("; ")
    }

    /// 从 Cookie 头解析（简单解析，不处理所有属性）
    pub fn parse(cookie_str: &str) -> Option<Self> {
        let parts: Vec<&str> = cookie_str.splitn(2, '=').collect();
        if parts.len() != 2 {
            return None;
        }

        let name = parts[0].trim();
        let value = parts[1].split(';').next()?.trim();

        Some(Self::new(name, value))
    }
}

/// 签名 Cookie 值
///
/// 使用 HMAC-SHA256 对值进行签名，返回格式为 `value.signature`
///
/// # 参数
///
/// - `value`: 要签名的值
/// - `secret`: 签名密钥（推荐至少 32 字节）
///
/// # 返回
///
/// 签名后的值，格式为 `base64(value).base64(signature)`
///
/// # 示例
///
/// ```rust
/// use authrs::security::cookie::sign_cookie;
///
/// let secret = b"my-secret-key-at-least-32-bytes!";
/// let signed = sign_cookie("user123", secret);
///
/// assert!(signed.contains("."));
/// ```
pub fn sign_cookie(value: &str, secret: &[u8]) -> String {
    let encoded_value = URL_SAFE_NO_PAD.encode(value.as_bytes());

    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(encoded_value.as_bytes());
    let signature = mac.finalize().into_bytes();
    let encoded_signature = URL_SAFE_NO_PAD.encode(signature);

    format!(
        "{}{}{}",
        encoded_value, SIGNATURE_SEPARATOR, encoded_signature
    )
}

/// 验证签名的 Cookie 值
///
/// # 参数
///
/// - `signed_value`: 签名后的值（格式为 `value.signature`）
/// - `secret`: 签名密钥
///
/// # 返回
///
/// 如果签名有效，返回原始值；否则返回错误
///
/// # 示例
///
/// ```rust
/// use authrs::security::cookie::{sign_cookie, verify_cookie};
///
/// let secret = b"my-secret-key-at-least-32-bytes!";
/// let signed = sign_cookie("user123", secret);
///
/// let original = verify_cookie(&signed, secret).unwrap();
/// assert_eq!(original, "user123");
/// ```
pub fn verify_cookie(signed_value: &str, secret: &[u8]) -> Result<String> {
    let parts: Vec<&str> = signed_value.rsplitn(2, SIGNATURE_SEPARATOR).collect();
    if parts.len() != 2 {
        return Err(Error::validation("Invalid signed cookie format"));
    }

    let encoded_signature = parts[0];
    let encoded_value = parts[1];

    // 验证签名
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(encoded_value.as_bytes());

    let expected_signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| Error::validation("Invalid signature encoding"))?;

    mac.verify_slice(&expected_signature)
        .map_err(|_| Error::validation("Cookie signature verification failed"))?;

    // 解码原始值
    let value_bytes = URL_SAFE_NO_PAD
        .decode(encoded_value)
        .map_err(|_| Error::validation("Invalid value encoding"))?;

    String::from_utf8(value_bytes).map_err(|_| Error::validation("Invalid UTF-8 in cookie value"))
}

/// 创建删除 Cookie 的头值
///
/// 设置 Max-Age=0 和过去的 Expires 时间
///
/// # 示例
///
/// ```rust
/// use authrs::security::cookie::delete_cookie_header;
///
/// let header = delete_cookie_header("session", Some("/"));
/// assert!(header.contains("Max-Age=0"));
/// ```
pub fn delete_cookie_header(name: &str, path: Option<&str>) -> String {
    let mut parts = vec![
        format!("{}=", name),
        "Max-Age=0".to_string(),
        "Expires=Thu, 01 Jan 1970 00:00:00 GMT".to_string(),
    ];

    if let Some(p) = path {
        parts.push(format!("Path={}", p));
    }

    parts.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &[u8] = b"test-secret-key-at-least-32-bytes!!";

    #[test]
    fn test_sign_and_verify() {
        let value = "test_value_123";
        let signed = sign_cookie(value, TEST_SECRET);

        assert!(signed.contains(SIGNATURE_SEPARATOR));

        let verified = verify_cookie(&signed, TEST_SECRET).unwrap();
        assert_eq!(verified, value);
    }

    #[test]
    fn test_verify_with_wrong_secret() {
        let value = "test_value";
        let signed = sign_cookie(value, TEST_SECRET);

        let wrong_secret = b"wrong-secret-key-at-least-32-bytes!!";
        let result = verify_cookie(&signed, wrong_secret);

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_tampered_value() {
        let value = "original_value";
        let signed = sign_cookie(value, TEST_SECRET);

        // 篡改签名部分（在分隔符后修改一个字符）
        let parts: Vec<&str> = signed.split('.').collect();
        if parts.len() == 2 {
            let mut sig_bytes = parts[1].as_bytes().to_vec();
            if !sig_bytes.is_empty() {
                // 修改签名的第一个字节
                sig_bytes[0] = if sig_bytes[0] == b'A' { b'B' } else { b'A' };
            }
            let tampered_sig = String::from_utf8(sig_bytes).unwrap();
            let tampered = format!("{}.{}", parts[0], tampered_sig);
            let result = verify_cookie(&tampered, TEST_SECRET);
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_verify_invalid_format() {
        let result = verify_cookie("no_separator_here", TEST_SECRET);
        assert!(result.is_err());
    }

    #[test]
    fn test_secure_cookie_new() {
        let cookie = SecureCookie::new("session", "abc123");

        assert_eq!(cookie.name(), "session");
        assert_eq!(cookie.value(), "abc123");
        assert!(!cookie.http_only);
        assert!(!cookie.secure);
        assert_eq!(cookie.same_site, SameSite::Lax);
    }

    #[test]
    fn test_secure_cookie_session() {
        let cookie = SecureCookie::session("session", "abc123");

        assert!(cookie.http_only);
        assert!(cookie.secure);
        assert_eq!(cookie.same_site, SameSite::Strict);
    }

    #[test]
    fn test_secure_cookie_builder() {
        let cookie = SecureCookie::new("session", "abc123")
            .http_only(true)
            .secure(true)
            .same_site(SameSite::Strict)
            .max_age(Duration::from_secs(3600))
            .path("/app")
            .domain("example.com");

        assert!(cookie.http_only);
        assert!(cookie.secure);
        assert_eq!(cookie.same_site, SameSite::Strict);
        assert_eq!(cookie.max_age, Some(Duration::from_secs(3600)));
        assert_eq!(cookie.path, Some("/app".to_string()));
        assert_eq!(cookie.domain, Some("example.com".to_string()));
    }

    #[test]
    fn test_secure_cookie_signed() {
        let cookie = SecureCookie::new("session", "user123").signed(TEST_SECRET);

        assert!(cookie.is_signed());
        assert!(cookie.value().contains(SIGNATURE_SEPARATOR));

        let verified = cookie.verify_value(TEST_SECRET).unwrap();
        assert_eq!(verified, "user123");
    }

    #[test]
    fn test_to_header_value() {
        let cookie = SecureCookie::new("session", "abc123")
            .http_only(true)
            .secure(true)
            .same_site(SameSite::Strict)
            .max_age(Duration::from_secs(3600))
            .path("/");

        let header = cookie.to_header_value();

        assert!(header.contains("session=abc123"));
        assert!(header.contains("HttpOnly"));
        assert!(header.contains("Secure"));
        assert!(header.contains("SameSite=Strict"));
        assert!(header.contains("Max-Age=3600"));
        assert!(header.contains("Path=/"));
    }

    #[test]
    fn test_to_header_value_minimal() {
        let cookie = SecureCookie::new("name", "value");
        let header = cookie.to_header_value();

        assert!(header.contains("name=value"));
        assert!(header.contains("SameSite=Lax"));
        assert!(!header.contains("HttpOnly"));
        assert!(!header.contains("Secure"));
    }

    #[test]
    fn test_delete_cookie_header() {
        let header = delete_cookie_header("session", Some("/"));

        assert!(header.contains("session="));
        assert!(header.contains("Max-Age=0"));
        assert!(header.contains("Expires="));
        assert!(header.contains("Path=/"));
    }

    #[test]
    fn test_parse_cookie() {
        let cookie = SecureCookie::parse("session=abc123; HttpOnly; Secure").unwrap();

        assert_eq!(cookie.name(), "session");
        assert_eq!(cookie.value(), "abc123");
    }

    #[test]
    fn test_parse_cookie_invalid() {
        let result = SecureCookie::parse("invalid");
        assert!(result.is_none());
    }

    #[test]
    fn test_same_site_display() {
        assert_eq!(format!("{}", SameSite::Strict), "Strict");
        assert_eq!(format!("{}", SameSite::Lax), "Lax");
        assert_eq!(format!("{}", SameSite::None), "None");
    }

    #[test]
    fn test_sign_cookie_with_special_chars() {
        let value = "user@example.com|token=abc123&data=xyz";
        let signed = sign_cookie(value, TEST_SECRET);
        let verified = verify_cookie(&signed, TEST_SECRET).unwrap();
        assert_eq!(verified, value);
    }

    #[test]
    fn test_sign_cookie_with_unicode() {
        let value = "用户名: 张三";
        let signed = sign_cookie(value, TEST_SECRET);
        let verified = verify_cookie(&signed, TEST_SECRET).unwrap();
        assert_eq!(verified, value);
    }

    #[test]
    fn test_max_age_secs() {
        let cookie = SecureCookie::new("test", "value").max_age_secs(7200);
        assert_eq!(cookie.max_age, Some(Duration::from_secs(7200)));
    }

    #[test]
    fn test_same_site_none_with_secure() {
        let cookie = SecureCookie::new("cross_site", "value")
            .same_site(SameSite::None)
            .secure(true);

        let header = cookie.to_header_value();
        assert!(header.contains("SameSite=None"));
        assert!(header.contains("Secure"));
    }
}
