//! PKCE (Proof Key for Code Exchange) 实现
//!
//! PKCE 是 OAuth 2.0 授权码流程的安全扩展，用于防止授权码拦截攻击。
//! 特别适用于无法安全存储客户端密钥的公共客户端（如移动应用、SPA）。
//!
//! ## 工作原理
//!
//! 1. 客户端生成一个随机的 `code_verifier`
//! 2. 客户端计算 `code_challenge = transform(code_verifier)`
//! 3. 客户端发送 `code_challenge` 和 `code_challenge_method` 到授权端点
//! 4. 授权服务器存储 challenge
//! 5. 客户端用授权码和原始 `code_verifier` 换取 token
//! 6. 授权服务器验证 `transform(code_verifier) == stored_challenge`
//!
//! ## 示例
//!
//! ```rust
//! use authrs::oauth::pkce::{PkceChallenge, PkceMethod};
//!
//! // 生成 PKCE challenge（推荐使用 S256）
//! let challenge = PkceChallenge::new(PkceMethod::S256).unwrap();
//!
//! // 获取要发送到授权服务器的值
//! let code_challenge = challenge.challenge();
//! let method = challenge.method();
//!
//! // ... 完成授权流程，获得授权码 ...
//!
//! // 验证时使用 code_verifier
//! let code_verifier = challenge.verifier();
//!
//! // 服务端验证
//! let is_valid = PkceChallenge::verify(code_verifier, code_challenge, method);
//! assert!(is_valid);
//! ```

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

use crate::error::{ConfigError, Error, Result};
use crate::random::generate_random_bytes;

/// PKCE challenge 方法
///
/// RFC 7636 定义了两种方法：
/// - `Plain`: code_challenge = code_verifier（不推荐，仅用于不支持 S256 的场景）
/// - `S256`: code_challenge = BASE64URL(SHA256(code_verifier))（推荐）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PkceMethod {
    /// Plain 方法：challenge = verifier
    ///
    /// **安全警告**: 仅在客户端不支持 SHA256 时使用
    Plain,

    /// S256 方法：challenge = BASE64URL(SHA256(verifier))
    ///
    /// **推荐使用**：提供更强的安全保护
    S256,
}

impl PkceMethod {
    /// 从字符串解析 PKCE 方法
    ///
    /// # Arguments
    ///
    /// * `s` - 方法字符串（"plain" 或 "S256"）
    ///
    /// # Returns
    ///
    /// 返回对应的 `PkceMethod`，无效输入返回错误
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "plain" => Ok(PkceMethod::Plain),
            "s256" => Ok(PkceMethod::S256),
            _ => Err(Error::Config(ConfigError::InvalidValue {
                key: "code_challenge_method".to_string(),
                message: format!("unsupported PKCE method: {}", s),
            })),
        }
    }

    /// 转换为 OAuth 2.0 参数字符串
    pub fn as_str(&self) -> &'static str {
        match self {
            PkceMethod::Plain => "plain",
            PkceMethod::S256 => "S256",
        }
    }
}

impl std::fmt::Display for PkceMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Default for PkceMethod {
    fn default() -> Self {
        PkceMethod::S256
    }
}

/// PKCE Verifier 配置
#[derive(Debug, Clone)]
pub struct PkceConfig {
    /// code_verifier 的长度（字节数）
    ///
    /// RFC 7636 要求 verifier 长度在 43-128 字符之间
    /// 默认使用 32 字节，Base64 编码后为 43 字符
    pub verifier_length: usize,

    /// 使用的 challenge 方法
    pub method: PkceMethod,
}

impl Default for PkceConfig {
    fn default() -> Self {
        Self {
            verifier_length: 32, // 生成 43 字符的 base64url
            method: PkceMethod::S256,
        }
    }
}

impl PkceConfig {
    /// 创建高安全配置
    ///
    /// 使用更长的 verifier（64 字节）
    pub fn high_security() -> Self {
        Self {
            verifier_length: 64,
            method: PkceMethod::S256,
        }
    }

    /// 验证配置是否有效
    pub fn validate(&self) -> Result<()> {
        // Base64 编码后的长度约为 verifier_length * 4/3
        // RFC 7636 要求 43-128 字符
        let encoded_len = (self.verifier_length * 4 + 2) / 3;

        if encoded_len < 43 {
            return Err(Error::Config(ConfigError::InvalidValue {
                key: "verifier_length".to_string(),
                message: format!(
                    "verifier too short: encoded length {} < 43 minimum",
                    encoded_len
                ),
            }));
        }

        if encoded_len > 128 {
            return Err(Error::Config(ConfigError::InvalidValue {
                key: "verifier_length".to_string(),
                message: format!(
                    "verifier too long: encoded length {} > 128 maximum",
                    encoded_len
                ),
            }));
        }

        Ok(())
    }
}

/// PKCE Challenge
///
/// 包含 code_verifier 和对应的 code_challenge
#[derive(Debug, Clone)]
pub struct PkceChallenge {
    /// 原始的 code_verifier（保密，仅在 token 请求时发送）
    verifier: String,

    /// code_challenge（发送到授权端点）
    challenge: String,

    /// 使用的 challenge 方法
    method: PkceMethod,
}

impl PkceChallenge {
    /// 使用指定方法创建新的 PKCE challenge
    ///
    /// # Arguments
    ///
    /// * `method` - PKCE challenge 方法
    ///
    /// # Returns
    ///
    /// 返回新的 `PkceChallenge`
    ///
    /// # Example
    ///
    /// ```rust
    /// use authrs::oauth::pkce::{PkceChallenge, PkceMethod};
    ///
    /// let challenge = PkceChallenge::new(PkceMethod::S256).unwrap();
    /// println!("Challenge: {}", challenge.challenge());
    /// println!("Method: {}", challenge.method());
    /// ```
    pub fn new(method: PkceMethod) -> Result<Self> {
        Self::with_config(PkceConfig {
            method,
            ..Default::default()
        })
    }

    /// 使用配置创建新的 PKCE challenge
    ///
    /// # Arguments
    ///
    /// * `config` - PKCE 配置
    ///
    /// # Returns
    ///
    /// 返回新的 `PkceChallenge`
    pub fn with_config(config: PkceConfig) -> Result<Self> {
        config.validate()?;

        let verifier_bytes = generate_random_bytes(config.verifier_length)?;
        let verifier = URL_SAFE_NO_PAD.encode(&verifier_bytes);

        let challenge = Self::compute_challenge(&verifier, config.method);

        Ok(Self {
            verifier,
            challenge,
            method: config.method,
        })
    }

    /// 从已有的 verifier 创建 challenge
    ///
    /// 用于从存储中恢复 PKCE 状态
    ///
    /// # Arguments
    ///
    /// * `verifier` - 已有的 code_verifier
    /// * `method` - PKCE challenge 方法
    ///
    /// # Returns
    ///
    /// 返回 `PkceChallenge`
    pub fn from_verifier(verifier: String, method: PkceMethod) -> Result<Self> {
        // 验证 verifier 长度
        if verifier.len() < 43 || verifier.len() > 128 {
            return Err(Error::Config(ConfigError::InvalidValue {
                key: "code_verifier".to_string(),
                message: format!(
                    "verifier length must be 43-128 characters, got {}",
                    verifier.len()
                ),
            }));
        }

        // 验证 verifier 只包含允许的字符 [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
        if !verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' || c == '~')
        {
            return Err(Error::Config(ConfigError::InvalidValue {
                key: "code_verifier".to_string(),
                message: "verifier contains invalid characters".to_string(),
            }));
        }

        let challenge = Self::compute_challenge(&verifier, method);

        Ok(Self {
            verifier,
            challenge,
            method,
        })
    }

    /// 计算 code_challenge
    fn compute_challenge(verifier: &str, method: PkceMethod) -> String {
        match method {
            PkceMethod::Plain => verifier.to_string(),
            PkceMethod::S256 => {
                let hash = Sha256::digest(verifier.as_bytes());
                URL_SAFE_NO_PAD.encode(hash)
            }
        }
    }

    /// 获取 code_verifier
    ///
    /// 在 token 请求时使用
    pub fn verifier(&self) -> &str {
        &self.verifier
    }

    /// 获取 code_challenge
    ///
    /// 在授权请求时发送到授权服务器
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    /// 获取 challenge 方法
    pub fn method(&self) -> PkceMethod {
        self.method
    }

    /// 获取用于授权请求的参数
    ///
    /// 返回 (code_challenge, code_challenge_method) 元组
    pub fn authorization_params(&self) -> (&str, &str) {
        (&self.challenge, self.method.as_str())
    }

    /// 验证 code_verifier 是否匹配 code_challenge
    ///
    /// 服务端使用此方法验证 token 请求
    ///
    /// # Arguments
    ///
    /// * `verifier` - 客户端提供的 code_verifier
    /// * `challenge` - 存储的 code_challenge
    /// * `method` - 使用的 challenge 方法
    ///
    /// # Returns
    ///
    /// 验证成功返回 `true`
    ///
    /// # Example
    ///
    /// ```rust
    /// use authrs::oauth::pkce::{PkceChallenge, PkceMethod};
    ///
    /// let challenge = PkceChallenge::new(PkceMethod::S256).unwrap();
    ///
    /// // 服务端验证
    /// let is_valid = PkceChallenge::verify(
    ///     challenge.verifier(),
    ///     challenge.challenge(),
    ///     challenge.method()
    /// );
    /// assert!(is_valid);
    /// ```
    pub fn verify(verifier: &str, challenge: &str, method: PkceMethod) -> bool {
        let computed = Self::compute_challenge(verifier, method);

        // 使用常量时间比较防止时序攻击
        crate::random::constant_time_compare_str(&computed, challenge)
    }
}

/// PKCE Verifier（仅包含 verifier 的轻量结构）
///
/// 用于客户端存储，在 token 请求时使用
#[derive(Debug, Clone)]
pub struct PkceVerifier(String);

impl PkceVerifier {
    /// 从 PkceChallenge 提取 verifier
    pub fn from_challenge(challenge: &PkceChallenge) -> Self {
        Self(challenge.verifier.clone())
    }

    /// 获取 verifier 字符串
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 消费并返回 verifier 字符串
    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for PkceVerifier {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// PKCE Code Challenge（仅包含 challenge 的轻量结构）
///
/// 用于服务端存储，与授权码关联
#[derive(Debug, Clone)]
pub struct PkceCodeChallenge {
    /// code_challenge 值
    pub challenge: String,

    /// challenge 方法
    pub method: PkceMethod,
}

impl PkceCodeChallenge {
    /// 创建新的 code challenge
    pub fn new(challenge: String, method: PkceMethod) -> Self {
        Self { challenge, method }
    }

    /// 从 PkceChallenge 提取
    pub fn from_challenge(pkce: &PkceChallenge) -> Self {
        Self {
            challenge: pkce.challenge.clone(),
            method: pkce.method,
        }
    }

    /// 验证 verifier
    pub fn verify(&self, verifier: &str) -> bool {
        PkceChallenge::verify(verifier, &self.challenge, self.method)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_s256_challenge() {
        let challenge = PkceChallenge::new(PkceMethod::S256).unwrap();

        // verifier 长度应在有效范围内
        assert!(challenge.verifier().len() >= 43);
        assert!(challenge.verifier().len() <= 128);

        // challenge 应该是 base64url 编码的 SHA256 哈希
        // SHA256 输出 32 字节，base64 编码后为 43 字符
        assert_eq!(challenge.challenge().len(), 43);

        // 验证应该成功
        assert!(PkceChallenge::verify(
            challenge.verifier(),
            challenge.challenge(),
            PkceMethod::S256
        ));
    }

    #[test]
    fn test_pkce_plain_challenge() {
        let challenge = PkceChallenge::new(PkceMethod::Plain).unwrap();

        // Plain 方法：challenge = verifier
        assert_eq!(challenge.verifier(), challenge.challenge());

        // 验证应该成功
        assert!(PkceChallenge::verify(
            challenge.verifier(),
            challenge.challenge(),
            PkceMethod::Plain
        ));
    }

    #[test]
    fn test_pkce_verification_fails_with_wrong_verifier() {
        let challenge = PkceChallenge::new(PkceMethod::S256).unwrap();

        // 使用错误的 verifier 应该验证失败
        assert!(!PkceChallenge::verify(
            "wrong_verifier_that_is_long_enough_to_pass_length_check",
            challenge.challenge(),
            PkceMethod::S256
        ));
    }

    #[test]
    fn test_pkce_verification_fails_with_wrong_method() {
        let challenge = PkceChallenge::new(PkceMethod::S256).unwrap();

        // 使用错误的方法应该验证失败
        assert!(!PkceChallenge::verify(
            challenge.verifier(),
            challenge.challenge(),
            PkceMethod::Plain
        ));
    }

    #[test]
    fn test_pkce_method_from_str() {
        assert_eq!(PkceMethod::from_str("S256").unwrap(), PkceMethod::S256);
        assert_eq!(PkceMethod::from_str("s256").unwrap(), PkceMethod::S256);
        assert_eq!(PkceMethod::from_str("plain").unwrap(), PkceMethod::Plain);
        assert_eq!(PkceMethod::from_str("PLAIN").unwrap(), PkceMethod::Plain);

        assert!(PkceMethod::from_str("invalid").is_err());
    }

    #[test]
    fn test_pkce_method_as_str() {
        assert_eq!(PkceMethod::S256.as_str(), "S256");
        assert_eq!(PkceMethod::Plain.as_str(), "plain");
    }

    #[test]
    fn test_pkce_from_verifier() {
        // 创建一个有效的 verifier
        let original = PkceChallenge::new(PkceMethod::S256).unwrap();
        let verifier = original.verifier().to_string();

        // 从 verifier 重建
        let restored = PkceChallenge::from_verifier(verifier, PkceMethod::S256).unwrap();

        assert_eq!(original.verifier(), restored.verifier());
        assert_eq!(original.challenge(), restored.challenge());
    }

    #[test]
    fn test_pkce_from_verifier_invalid_length() {
        // 太短
        assert!(PkceChallenge::from_verifier("short".to_string(), PkceMethod::S256).is_err());

        // 太长
        let long = "a".repeat(129);
        assert!(PkceChallenge::from_verifier(long, PkceMethod::S256).is_err());
    }

    #[test]
    fn test_pkce_from_verifier_invalid_chars() {
        let invalid = "a".repeat(43) + "!@#"; // 包含非法字符
        assert!(PkceChallenge::from_verifier(invalid, PkceMethod::S256).is_err());
    }

    #[test]
    fn test_pkce_config_validation() {
        // 有效配置
        assert!(PkceConfig::default().validate().is_ok());
        assert!(PkceConfig::high_security().validate().is_ok());

        // 太短
        let short_config = PkceConfig {
            verifier_length: 10,
            method: PkceMethod::S256,
        };
        assert!(short_config.validate().is_err());

        // 太长
        let long_config = PkceConfig {
            verifier_length: 200,
            method: PkceMethod::S256,
        };
        assert!(long_config.validate().is_err());
    }

    #[test]
    fn test_pkce_authorization_params() {
        let challenge = PkceChallenge::new(PkceMethod::S256).unwrap();
        let (code_challenge, method) = challenge.authorization_params();

        assert_eq!(code_challenge, challenge.challenge());
        assert_eq!(method, "S256");
    }

    #[test]
    fn test_pkce_code_challenge() {
        let challenge = PkceChallenge::new(PkceMethod::S256).unwrap();
        let code_challenge = PkceCodeChallenge::from_challenge(&challenge);

        assert!(code_challenge.verify(challenge.verifier()));
        assert!(!code_challenge.verify("wrong_verifier_long_enough_to_pass"));
    }

    #[test]
    fn test_pkce_verifier() {
        let challenge = PkceChallenge::new(PkceMethod::S256).unwrap();
        let verifier = PkceVerifier::from_challenge(&challenge);

        assert_eq!(verifier.as_str(), challenge.verifier());
        assert_eq!(verifier.as_ref(), challenge.verifier());
    }

    #[test]
    fn test_pkce_uniqueness() {
        // 确保每次生成的 challenge 都不同
        let c1 = PkceChallenge::new(PkceMethod::S256).unwrap();
        let c2 = PkceChallenge::new(PkceMethod::S256).unwrap();

        assert_ne!(c1.verifier(), c2.verifier());
        assert_ne!(c1.challenge(), c2.challenge());
    }

    #[test]
    fn test_pkce_high_security_config() {
        let config = PkceConfig::high_security();
        let challenge = PkceChallenge::with_config(config).unwrap();

        // 高安全配置使用更长的 verifier
        assert!(challenge.verifier().len() > 43);

        // 但仍然应该可以验证
        assert!(PkceChallenge::verify(
            challenge.verifier(),
            challenge.challenge(),
            PkceMethod::S256
        ));
    }
}
