//! 统一错误类型模块
//!
//! 提供 authrs 库中所有操作的错误类型定义。

use std::fmt;
use std::time::Duration;

/// authrs 库的统一结果类型
pub type Result<T> = std::result::Result<T, Error>;

/// authrs 库的错误类型
#[derive(Debug)]
pub enum Error {
    /// 密码哈希错误
    PasswordHash(PasswordHashError),

    /// Token 相关错误
    Token(TokenError),

    /// 验证错误
    Validation(ValidationError),

    /// 配置错误
    Config(ConfigError),

    /// 存储错误
    Storage(StorageError),

    /// 加密错误
    Crypto(CryptoError),

    /// 速率限制超出
    RateLimitExceeded {
        /// 重试等待时间
        retry_after: Duration,
    },

    /// 内部错误
    Internal(String),

    /// 其他错误
    Other(String),
}

impl Error {
    /// 创建一个内部错误
    pub fn internal(msg: impl Into<String>) -> Self {
        Error::Internal(msg.into())
    }

    /// 创建一个验证错误
    pub fn validation(msg: impl Into<String>) -> Self {
        Error::Validation(ValidationError::Custom(msg.into()))
    }

    /// 创建一个速率限制错误
    pub fn rate_limited(retry_after: Duration) -> Self {
        Error::RateLimitExceeded { retry_after }
    }
}

/// 密码哈希相关错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordHashError {
    /// 哈希生成失败
    HashFailed(String),
    /// 密码验证失败
    VerifyFailed,
    /// 无效的哈希格式
    InvalidFormat(String),
    /// 算法不支持
    UnsupportedAlgorithm(String),
}

/// Token 相关错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// Token 已过期
    Expired,
    /// Token 格式无效
    InvalidFormat(String),
    /// Token 签名无效
    InvalidSignature,
    /// Token 编码失败
    EncodingFailed(String),
    /// Token 解码失败
    DecodingFailed(String),
    /// 缺少必需的 claim
    MissingClaim(String),
    /// 无效的 claim 值
    InvalidClaim(String),
}

/// 验证相关错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// 密码太短
    PasswordTooShort { min_length: usize, actual: usize },
    /// 密码太长
    PasswordTooLong { max_length: usize, actual: usize },
    /// 密码强度不足
    PasswordTooWeak(String),
    /// 无效的邮箱格式
    InvalidEmail(String),
    /// 无效的用户名格式
    InvalidUsername(String),
    /// 字段为空
    EmptyField(String),
    /// 自定义验证错误
    Custom(String),
}

/// 配置相关错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// 缺少必需的配置
    MissingRequired(String),
    /// 无效的配置值
    InvalidValue { key: String, message: String },
}

/// 存储相关错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    /// 连接失败
    ConnectionFailed(String),
    /// 记录未找到
    NotFound(String),
    /// 记录已存在
    AlreadyExists(String),
    /// 操作失败
    OperationFailed(String),
}

/// 加密相关错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// 随机数生成失败
    RngFailed(String),
    /// 密钥无效
    InvalidKey(String),
    /// 加密失败
    EncryptionFailed(String),
    /// 解密失败
    DecryptionFailed(String),
}

// ============================================================================
// Display 实现
// ============================================================================

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::PasswordHash(e) => write!(f, "Password hash error: {}", e),
            Error::Token(e) => write!(f, "Token error: {}", e),
            Error::Validation(e) => write!(f, "Validation error: {}", e),
            Error::Config(e) => write!(f, "Config error: {}", e),
            Error::Storage(e) => write!(f, "Storage error: {}", e),
            Error::Crypto(e) => write!(f, "Crypto error: {}", e),
            Error::RateLimitExceeded { retry_after } => {
                write!(f, "Rate limit exceeded, retry after {:?}", retry_after)
            }
            Error::Internal(msg) => write!(f, "Internal error: {}", msg),
            Error::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl fmt::Display for PasswordHashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PasswordHashError::HashFailed(msg) => write!(f, "hash generation failed: {}", msg),
            PasswordHashError::VerifyFailed => write!(f, "password verification failed"),
            PasswordHashError::InvalidFormat(msg) => write!(f, "invalid hash format: {}", msg),
            PasswordHashError::UnsupportedAlgorithm(alg) => {
                write!(f, "unsupported algorithm: {}", alg)
            }
        }
    }
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::Expired => write!(f, "token has expired"),
            TokenError::InvalidFormat(msg) => write!(f, "invalid token format: {}", msg),
            TokenError::InvalidSignature => write!(f, "invalid token signature"),
            TokenError::EncodingFailed(msg) => write!(f, "token encoding failed: {}", msg),
            TokenError::DecodingFailed(msg) => write!(f, "token decoding failed: {}", msg),
            TokenError::MissingClaim(claim) => write!(f, "missing required claim: {}", claim),
            TokenError::InvalidClaim(msg) => write!(f, "invalid claim value: {}", msg),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::PasswordTooShort { min_length, actual } => {
                write!(
                    f,
                    "password too short: minimum {} characters, got {}",
                    min_length, actual
                )
            }
            ValidationError::PasswordTooLong { max_length, actual } => {
                write!(
                    f,
                    "password too long: maximum {} characters, got {}",
                    max_length, actual
                )
            }
            ValidationError::PasswordTooWeak(msg) => write!(f, "password too weak: {}", msg),
            ValidationError::InvalidEmail(email) => write!(f, "invalid email format: {}", email),
            ValidationError::InvalidUsername(name) => {
                write!(f, "invalid username format: {}", name)
            }
            ValidationError::EmptyField(field) => write!(f, "field '{}' cannot be empty", field),
            ValidationError::Custom(msg) => write!(f, "{}", msg),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::MissingRequired(key) => {
                write!(f, "missing required configuration: {}", key)
            }
            ConfigError::InvalidValue { key, message } => {
                write!(f, "invalid configuration value for '{}': {}", key, message)
            }
        }
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::ConnectionFailed(msg) => write!(f, "storage connection failed: {}", msg),
            StorageError::NotFound(item) => write!(f, "not found: {}", item),
            StorageError::AlreadyExists(item) => write!(f, "already exists: {}", item),
            StorageError::OperationFailed(msg) => write!(f, "storage operation failed: {}", msg),
        }
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::RngFailed(msg) => write!(f, "random number generation failed: {}", msg),
            CryptoError::InvalidKey(msg) => write!(f, "invalid key: {}", msg),
            CryptoError::EncryptionFailed(msg) => write!(f, "encryption failed: {}", msg),
            CryptoError::DecryptionFailed(msg) => write!(f, "decryption failed: {}", msg),
        }
    }
}

// ============================================================================
// std::error::Error 实现
// ============================================================================

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl std::error::Error for PasswordHashError {}
impl std::error::Error for TokenError {}
impl std::error::Error for ValidationError {}
impl std::error::Error for ConfigError {}
impl std::error::Error for StorageError {}
impl std::error::Error for CryptoError {}

// ============================================================================
// From 实现 - 方便错误转换
// ============================================================================

impl From<PasswordHashError> for Error {
    fn from(err: PasswordHashError) -> Self {
        Error::PasswordHash(err)
    }
}

impl From<TokenError> for Error {
    fn from(err: TokenError) -> Self {
        Error::Token(err)
    }
}

impl From<ValidationError> for Error {
    fn from(err: ValidationError) -> Self {
        Error::Validation(err)
    }
}

impl From<ConfigError> for Error {
    fn from(err: ConfigError) -> Self {
        Error::Config(err)
    }
}

impl From<StorageError> for Error {
    fn from(err: StorageError) -> Self {
        Error::Storage(err)
    }
}

impl From<CryptoError> for Error {
    fn from(err: CryptoError) -> Self {
        Error::Crypto(err)
    }
}

impl From<String> for Error {
    fn from(msg: String) -> Self {
        Error::Other(msg)
    }
}

impl From<&str> for Error {
    fn from(msg: &str) -> Self {
        Error::Other(msg.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::PasswordHash(PasswordHashError::VerifyFailed);
        assert_eq!(
            err.to_string(),
            "Password hash error: password verification failed"
        );
    }

    #[test]
    fn test_error_from_password_hash() {
        let hash_err = PasswordHashError::HashFailed("test".to_string());
        let err: Error = hash_err.into();
        assert!(matches!(err, Error::PasswordHash(_)));
    }

    #[test]
    fn test_validation_error_display() {
        let err = ValidationError::PasswordTooShort {
            min_length: 8,
            actual: 4,
        };
        assert_eq!(
            err.to_string(),
            "password too short: minimum 8 characters, got 4"
        );
    }

    #[test]
    fn test_token_error_display() {
        let err = TokenError::Expired;
        assert_eq!(err.to_string(), "token has expired");
    }
}
