//! CSRF (跨站请求伪造) 防护模块
//!
//! 提供 CSRF token 的生成、验证和管理功能。
//!
//! ## 功能特性
//!
//! - 安全的 token 生成（使用加密安全随机数）
//! - 可配置的 token 有效期
//! - 支持 HMAC 签名验证
//! - 常量时间比较防止时序攻击
//! - 可选的双重提交 Cookie 模式支持
//!
//! ## 基本用法
//!
//! ```rust
//! use authrs::security::csrf::{CsrfProtection, CsrfConfig};
//! use std::time::Duration;
//!
//! // 使用默认配置
//! let csrf = CsrfProtection::new(CsrfConfig::default());
//!
//! // 生成 token
//! let token = csrf.generate_token().unwrap();
//! println!("Token: {}", token.token);
//!
//! // 验证 token
//! assert!(csrf.verify(&token.token).unwrap());
//! ```
//!
//! ## 自定义配置
//!
//! ```rust
//! use authrs::security::csrf::{CsrfProtection, CsrfConfig};
//! use std::time::Duration;
//!
//! let config = CsrfConfig::new()
//!     .with_secret(b"my-secret-key-at-least-32-bytes!")
//!     .with_token_length(32)
//!     .with_ttl(Duration::from_secs(3600)); // 1小时有效期
//!
//! let csrf = CsrfProtection::new(config);
//! ```

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};
use crate::random::generate_random_bytes;

type HmacSha256 = Hmac<Sha256>;

/// CSRF 配置
#[derive(Debug, Clone)]
pub struct CsrfConfig {
    /// 用于签名的密钥
    secret: Vec<u8>,
    /// Token 长度（字节）
    token_length: usize,
    /// Token 有效期
    ttl: Duration,
}

impl Default for CsrfConfig {
    fn default() -> Self {
        // 使用 expect 因为在正常情况下随机数生成不会失败
        let secret = generate_random_bytes(32).expect("Failed to generate random secret");
        Self {
            secret,
            token_length: 32,
            ttl: Duration::from_secs(3600), // 1小时
        }
    }
}

impl CsrfConfig {
    /// 创建新的 CSRF 配置
    ///
    /// # 示例
    ///
    /// ```rust
    /// use authrs::security::csrf::CsrfConfig;
    ///
    /// let config = CsrfConfig::new();
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置签名密钥
    ///
    /// # 参数
    ///
    /// * `secret` - 密钥，建议至少 32 字节
    ///
    /// # 示例
    ///
    /// ```rust
    /// use authrs::security::csrf::CsrfConfig;
    ///
    /// let config = CsrfConfig::new()
    ///     .with_secret(b"my-super-secret-key-32-bytes!!!");
    /// ```
    pub fn with_secret(mut self, secret: &[u8]) -> Self {
        self.secret = secret.to_vec();
        self
    }

    /// 设置 token 长度
    ///
    /// # 参数
    ///
    /// * `length` - Token 长度（字节），默认 32
    pub fn with_token_length(mut self, length: usize) -> Self {
        self.token_length = length;
        self
    }

    /// 设置 token 有效期
    ///
    /// # 参数
    ///
    /// * `ttl` - 有效期
    ///
    /// # 示例
    ///
    /// ```rust
    /// use authrs::security::csrf::CsrfConfig;
    /// use std::time::Duration;
    ///
    /// let config = CsrfConfig::new()
    ///     .with_ttl(Duration::from_secs(7200)); // 2小时
    /// ```
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }
}

/// CSRF Token
#[derive(Debug, Clone)]
pub struct CsrfToken {
    /// 完整的 token 字符串（包含签名）
    pub token: String,
    /// Token 创建时间戳
    pub created_at: u64,
    /// Token 过期时间戳
    pub expires_at: u64,
}

impl CsrfToken {
    /// 检查 token 是否已过期
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now > self.expires_at
    }

    /// 获取剩余有效时间（秒）
    pub fn remaining_ttl(&self) -> Option<u64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now > self.expires_at {
            None
        } else {
            Some(self.expires_at - now)
        }
    }
}

/// CSRF 防护器
///
/// 提供 CSRF token 的生成和验证功能。
///
/// ## Token 格式
///
/// Token 由三部分组成，使用 `.` 分隔：
/// - 随机数据（base64url 编码）
/// - 时间戳（base64url 编码）
/// - HMAC 签名（base64url 编码）
#[derive(Debug, Clone)]
pub struct CsrfProtection {
    config: CsrfConfig,
}

impl CsrfProtection {
    /// 创建新的 CSRF 防护器
    ///
    /// # 参数
    ///
    /// * `config` - CSRF 配置
    ///
    /// # 示例
    ///
    /// ```rust
    /// use authrs::security::csrf::{CsrfProtection, CsrfConfig};
    ///
    /// let csrf = CsrfProtection::new(CsrfConfig::default());
    /// ```
    pub fn new(config: CsrfConfig) -> Self {
        Self { config }
    }

    /// 使用默认配置创建 CSRF 防护器
    ///
    /// # 示例
    ///
    /// ```rust
    /// use authrs::security::csrf::CsrfProtection;
    ///
    /// let csrf = CsrfProtection::with_default();
    /// ```
    pub fn with_default() -> Self {
        Self::new(CsrfConfig::default())
    }

    /// 使用指定密钥创建 CSRF 防护器
    ///
    /// # 参数
    ///
    /// * `secret` - 签名密钥
    ///
    /// # 示例
    ///
    /// ```rust
    /// use authrs::security::csrf::CsrfProtection;
    ///
    /// let csrf = CsrfProtection::with_secret(b"my-secret-key-32-bytes-long!!!!");
    /// ```
    pub fn with_secret(secret: &[u8]) -> Self {
        Self::new(CsrfConfig::default().with_secret(secret))
    }

    /// 生成新的 CSRF token
    ///
    /// # 返回
    ///
    /// 返回包含 token 和元数据的 `CsrfToken` 结构
    ///
    /// # 示例
    ///
    /// ```rust
    /// use authrs::security::csrf::{CsrfProtection, CsrfConfig};
    ///
    /// let csrf = CsrfProtection::new(CsrfConfig::default());
    /// let token = csrf.generate_token().unwrap();
    ///
    /// println!("Token: {}", token.token);
    /// println!("Expires at: {}", token.expires_at);
    /// ```
    pub fn generate_token(&self) -> Result<CsrfToken> {
        // 生成随机数据
        let random_data = generate_random_bytes(self.config.token_length)?;

        // 获取当前时间戳
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::internal(format!("系统时间错误: {}", e)))?
            .as_secs();

        let expires_at = now + self.config.ttl.as_secs();

        // 编码数据
        let random_b64 = URL_SAFE_NO_PAD.encode(&random_data);
        let timestamp_b64 = URL_SAFE_NO_PAD.encode(now.to_be_bytes());

        // 计算签名
        let signature = self.sign(&random_data, now)?;
        let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

        // 组合 token
        let token = format!("{}.{}.{}", random_b64, timestamp_b64, signature_b64);

        Ok(CsrfToken {
            token,
            created_at: now,
            expires_at,
        })
    }

    /// 验证 CSRF token
    ///
    /// # 参数
    ///
    /// * `token` - 要验证的 token 字符串
    ///
    /// # 返回
    ///
    /// 如果 token 有效返回 `true`，否则返回 `false`
    ///
    /// # 示例
    ///
    /// ```rust
    /// use authrs::security::csrf::{CsrfProtection, CsrfConfig};
    ///
    /// let csrf = CsrfProtection::new(CsrfConfig::default());
    /// let token = csrf.generate_token().unwrap();
    ///
    /// // 验证有效 token
    /// assert!(csrf.verify(&token.token).unwrap());
    ///
    /// // 验证无效 token
    /// assert!(!csrf.verify("invalid-token").unwrap_or(false));
    /// ```
    pub fn verify(&self, token: &str) -> Result<bool> {
        // 解析 token
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Ok(false);
        }

        // 解码各部分
        let random_data = match URL_SAFE_NO_PAD.decode(parts[0]) {
            Ok(data) => data,
            Err(_) => return Ok(false),
        };

        let timestamp_bytes = match URL_SAFE_NO_PAD.decode(parts[1]) {
            Ok(data) => data,
            Err(_) => return Ok(false),
        };

        let provided_signature = match URL_SAFE_NO_PAD.decode(parts[2]) {
            Ok(data) => data,
            Err(_) => return Ok(false),
        };

        // 解析时间戳
        if timestamp_bytes.len() != 8 {
            return Ok(false);
        }
        let mut timestamp_arr = [0u8; 8];
        timestamp_arr.copy_from_slice(&timestamp_bytes);
        let timestamp = u64::from_be_bytes(timestamp_arr);

        // 检查是否过期
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::internal(format!("系统时间错误: {}", e)))?
            .as_secs();

        let expires_at = timestamp + self.config.ttl.as_secs();
        if now > expires_at {
            return Ok(false);
        }

        // 计算预期签名
        let expected_signature = self.sign(&random_data, timestamp)?;

        // 常量时间比较
        Ok(provided_signature.ct_eq(&expected_signature).into())
    }

    /// 验证 token 并返回详细信息
    ///
    /// # 参数
    ///
    /// * `token` - 要验证的 token 字符串
    ///
    /// # 返回
    ///
    /// 如果有效，返回解析后的 `CsrfToken`
    pub fn verify_and_decode(&self, token: &str) -> Result<CsrfToken> {
        // 解析 token
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(Error::validation("无效的 token 格式"));
        }

        // 解码各部分
        let random_data = URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| Error::validation("无效的 token 格式"))?;

        let timestamp_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| Error::validation("无效的 token 格式"))?;

        let provided_signature = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|_| Error::validation("无效的 token 格式"))?;

        // 解析时间戳
        if timestamp_bytes.len() != 8 {
            return Err(Error::validation("无效的时间戳"));
        }
        let mut timestamp_arr = [0u8; 8];
        timestamp_arr.copy_from_slice(&timestamp_bytes);
        let timestamp = u64::from_be_bytes(timestamp_arr);

        // 检查是否过期
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::internal(format!("系统时间错误: {}", e)))?
            .as_secs();

        let expires_at = timestamp + self.config.ttl.as_secs();
        if now > expires_at {
            return Err(Error::validation("Token 已过期"));
        }

        // 计算预期签名
        let expected_signature = self.sign(&random_data, timestamp)?;

        // 常量时间比较
        if !bool::from(provided_signature.ct_eq(&expected_signature)) {
            return Err(Error::validation("签名验证失败"));
        }

        Ok(CsrfToken {
            token: token.to_string(),
            created_at: timestamp,
            expires_at,
        })
    }

    /// 计算 HMAC 签名
    fn sign(&self, data: &[u8], timestamp: u64) -> Result<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(&self.config.secret)
            .map_err(|e| Error::internal(format!("HMAC 初始化失败: {}", e)))?;

        mac.update(data);
        mac.update(&timestamp.to_be_bytes());

        Ok(mac.finalize().into_bytes().to_vec())
    }
}

/// 双重提交 Cookie 模式的 CSRF 防护
///
/// 这种模式不需要服务端存储，通过比较 Cookie 和请求体/头中的 token 来验证
#[derive(Debug, Clone)]
pub struct DoubleSubmitCsrf {
    config: CsrfConfig,
}

impl DoubleSubmitCsrf {
    /// 创建新的双重提交 CSRF 防护器
    pub fn new(config: CsrfConfig) -> Self {
        Self { config }
    }

    /// 使用默认配置创建
    pub fn with_default() -> Self {
        Self::new(CsrfConfig::default())
    }

    /// 生成 token 对（Cookie token 和 请求 token）
    ///
    /// # 返回
    ///
    /// 返回 (cookie_token, request_token) 元组
    ///
    /// # 示例
    ///
    /// ```rust
    /// use authrs::security::csrf::DoubleSubmitCsrf;
    ///
    /// let csrf = DoubleSubmitCsrf::with_default();
    /// let (cookie_token, request_token) = csrf.generate_token_pair().unwrap();
    ///
    /// // cookie_token 设置到 Cookie
    /// // request_token 返回给客户端放入表单或请求头
    /// ```
    pub fn generate_token_pair(&self) -> Result<(String, String)> {
        // 生成随机数据
        let random_data = generate_random_bytes(self.config.token_length)?;
        let token = URL_SAFE_NO_PAD.encode(&random_data);

        // 两个 token 相同，但可以根据需要添加额外的处理
        Ok((token.clone(), token))
    }

    /// 验证双重提交 token
    ///
    /// # 参数
    ///
    /// * `cookie_token` - 来自 Cookie 的 token
    /// * `request_token` - 来自请求体或请求头的 token
    ///
    /// # 返回
    ///
    /// 如果两个 token 匹配返回 `true`
    ///
    /// # 示例
    ///
    /// ```rust
    /// use authrs::security::csrf::DoubleSubmitCsrf;
    ///
    /// let csrf = DoubleSubmitCsrf::with_default();
    /// let (cookie_token, request_token) = csrf.generate_token_pair().unwrap();
    ///
    /// // 验证
    /// assert!(csrf.verify(&cookie_token, &request_token));
    ///
    /// // 不匹配的 token
    /// assert!(!csrf.verify(&cookie_token, "different-token"));
    /// ```
    pub fn verify(&self, cookie_token: &str, request_token: &str) -> bool {
        // 常量时间比较
        cookie_token
            .as_bytes()
            .ct_eq(request_token.as_bytes())
            .into()
    }
}

/// 带签名的双重提交 Cookie 模式
///
/// 相比普通的双重提交模式，这种方式对 Cookie 中的 token 进行签名，
/// 提供更强的安全性
#[derive(Debug, Clone)]
pub struct SignedDoubleSubmitCsrf {
    protection: CsrfProtection,
}

impl SignedDoubleSubmitCsrf {
    /// 创建新的签名双重提交 CSRF 防护器
    pub fn new(config: CsrfConfig) -> Self {
        Self {
            protection: CsrfProtection::new(config),
        }
    }

    /// 使用密钥创建
    pub fn with_secret(secret: &[u8]) -> Self {
        Self {
            protection: CsrfProtection::with_secret(secret),
        }
    }

    /// 生成 token 对
    ///
    /// # 返回
    ///
    /// 返回 (signed_cookie_token, plain_request_token) 元组
    pub fn generate_token_pair(&self) -> Result<(String, String)> {
        let csrf_token = self.protection.generate_token()?;

        // Cookie 使用完整的签名 token
        let cookie_token = csrf_token.token.clone();

        // 请求 token 只使用随机部分
        let parts: Vec<&str> = csrf_token.token.split('.').collect();
        let request_token = parts[0].to_string();

        Ok((cookie_token, request_token))
    }

    /// 验证 token 对
    ///
    /// # 参数
    ///
    /// * `cookie_token` - 来自 Cookie 的签名 token
    /// * `request_token` - 来自请求的普通 token
    pub fn verify(&self, cookie_token: &str, request_token: &str) -> Result<bool> {
        // 首先验证 Cookie token 的签名
        if !self.protection.verify(cookie_token)? {
            return Ok(false);
        }

        // 提取 Cookie token 的随机部分
        let parts: Vec<&str> = cookie_token.split('.').collect();
        if parts.is_empty() {
            return Ok(false);
        }

        // 比较随机部分
        Ok(parts[0].as_bytes().ct_eq(request_token.as_bytes()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_csrf_token_generation() {
        let csrf = CsrfProtection::with_default();
        let token = csrf.generate_token().unwrap();

        assert!(!token.token.is_empty());
        assert!(token.created_at > 0);
        assert!(token.expires_at > token.created_at);
    }

    #[test]
    fn test_csrf_token_verification() {
        let csrf = CsrfProtection::with_default();
        let token = csrf.generate_token().unwrap();

        assert!(csrf.verify(&token.token).unwrap());
    }

    #[test]
    fn test_csrf_invalid_token() {
        let csrf = CsrfProtection::with_default();

        assert!(!csrf.verify("invalid").unwrap_or(false));
        assert!(!csrf.verify("a.b.c").unwrap_or(false));
        assert!(!csrf.verify("").unwrap_or(false));
    }

    #[test]
    fn test_csrf_tampered_token() {
        let csrf = CsrfProtection::with_default();
        let token = csrf.generate_token().unwrap();

        // 篡改 token
        let mut tampered = token.token.clone();
        tampered.push('x');

        assert!(!csrf.verify(&tampered).unwrap_or(false));
    }

    #[test]
    fn test_csrf_different_secrets() {
        let csrf1 = CsrfProtection::with_secret(b"secret1-32-bytes-long-xxxxxxxxx");
        let csrf2 = CsrfProtection::with_secret(b"secret2-32-bytes-long-xxxxxxxxx");

        let token = csrf1.generate_token().unwrap();

        // 使用不同密钥验证应该失败
        assert!(!csrf2.verify(&token.token).unwrap());
    }

    #[test]
    fn test_csrf_expiration() {
        let config = CsrfConfig::new().with_ttl(Duration::from_secs(1));
        let csrf = CsrfProtection::new(config);

        let token = csrf.generate_token().unwrap();
        assert!(csrf.verify(&token.token).unwrap());

        // 等待过期（需要超过 1 秒，因为 TTL 是秒级精度）
        thread::sleep(Duration::from_secs(2));

        assert!(!csrf.verify(&token.token).unwrap());
    }

    #[test]
    fn test_csrf_token_is_expired() {
        let config = CsrfConfig::new().with_ttl(Duration::from_secs(1));
        let csrf = CsrfProtection::new(config);

        let token = csrf.generate_token().unwrap();
        assert!(!token.is_expired());

        thread::sleep(Duration::from_secs(2));

        assert!(token.is_expired());
    }

    #[test]
    fn test_csrf_remaining_ttl() {
        let config = CsrfConfig::new().with_ttl(Duration::from_secs(60));
        let csrf = CsrfProtection::new(config);

        let token = csrf.generate_token().unwrap();
        let remaining = token.remaining_ttl().unwrap();

        assert!(remaining > 0);
        assert!(remaining <= 60);
    }

    #[test]
    fn test_double_submit_csrf() {
        let csrf = DoubleSubmitCsrf::with_default();
        let (cookie, request) = csrf.generate_token_pair().unwrap();

        assert!(csrf.verify(&cookie, &request));
        assert!(!csrf.verify(&cookie, "wrong"));
    }

    #[test]
    fn test_signed_double_submit_csrf() {
        let csrf = SignedDoubleSubmitCsrf::with_secret(b"my-secret-key-32-bytes-long!!!!");

        let (cookie, request) = csrf.generate_token_pair().unwrap();

        assert!(csrf.verify(&cookie, &request).unwrap());
        assert!(!csrf.verify(&cookie, "wrong").unwrap());
    }

    #[test]
    fn test_verify_and_decode() {
        let csrf = CsrfProtection::with_default();
        let token = csrf.generate_token().unwrap();

        let decoded = csrf.verify_and_decode(&token.token).unwrap();

        assert_eq!(decoded.created_at, token.created_at);
        assert_eq!(decoded.expires_at, token.expires_at);
    }

    #[test]
    fn test_verify_and_decode_expired() {
        let config = CsrfConfig::new().with_ttl(Duration::from_secs(1));
        let csrf = CsrfProtection::new(config);

        let token = csrf.generate_token().unwrap();

        thread::sleep(Duration::from_secs(2));

        assert!(csrf.verify_and_decode(&token.token).is_err());
    }

    #[test]
    fn test_config_builder() {
        let config = CsrfConfig::new()
            .with_secret(b"test-secret-key-32-bytes-long!!")
            .with_token_length(64)
            .with_ttl(Duration::from_secs(7200));

        let csrf = CsrfProtection::new(config);
        let token = csrf.generate_token().unwrap();

        // Token 应该更长（64字节随机数据）
        assert!(token.token.len() > 100);
    }
}
