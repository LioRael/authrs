//! # AuthRS
//!
//! 一个全面的 Rust 认证库。
//!
//! ## 功能特性
//!
//! - **密码哈希**: 使用 Argon2 和 bcrypt 进行安全的密码哈希
//! - **密码强度检查**: 密码强度评估与验证
//! - **安全随机数**: 密码学安全的随机数生成
//! - **JWT Token**: JSON Web Token 的生成、验证和刷新
//! - **Session 管理**: 安全的 Session 创建、验证和存储
//! - **Refresh Token**: Token 轮换和重用检测
//! - **MFA**: TOTP/HOTP 多因素认证
//! - **速率限制**: 防止暴力破解攻击
//! - **CSRF 防护**: 跨站请求伪造防护
//!
//! ## Features
//!
//! 本库使用 Cargo features 来允许用户选择性地启用功能：
//!
//! - `argon2` - 启用 Argon2id 密码哈希支持（默认启用）
//! - `bcrypt` - 启用 bcrypt 密码哈希支持
//! - `jwt` - 启用 JWT 支持（默认启用）
//! - `mfa` - 启用 TOTP/HOTP 多因素认证（默认启用）
//! - `full` - 启用所有功能
//!
//! 默认启用的 features: `argon2`, `jwt`, `mfa`
//!
//! ## 密码哈希示例
//!
//! ```rust
//! use authrs::password::{hash_password, verify_password};
//!
//! // 哈希密码
//! let hash = hash_password("my_secure_password").unwrap();
//!
//! // 验证密码
//! let is_valid = verify_password("my_secure_password", &hash).unwrap();
//! assert!(is_valid);
//! ```
//!
//! ## 密码强度检查
//!
//! ```rust
//! use authrs::password::{validate_password_strength, PasswordRequirements};
//!
//! // 使用默认要求
//! let result = validate_password_strength("Str0ng_P@ssword!");
//! assert!(result.is_ok());
//!
//! // 使用严格要求
//! let requirements = PasswordRequirements::strict();
//! ```
//!
//! ## JWT Token 示例
//!
#![cfg_attr(feature = "jwt", doc = "```rust")]
#![cfg_attr(not(feature = "jwt"), doc = "```rust,ignore")]
//! use authrs::token::jwt::{JwtBuilder, JwtValidator};
//!
//! // 创建 JWT
//! let secret = b"my-secret-key-at-least-32-bytes!";
//! let token = JwtBuilder::new()
//!     .subject("user123")
//!     .issuer("my-app")
//!     .expires_in_hours(24)
//!     .build_with_secret(secret)
//!     .unwrap();
//!
//! // 验证 JWT
//! let validator = JwtValidator::new(secret);
//! let claims = validator.validate(&token).unwrap();
//! ```
//!
//! ## Session 管理示例
//!
//! ```rust
//! use authrs::token::session::{SessionManager, SessionConfig};
//!
//! // 创建 Session 管理器
//! let manager = SessionManager::new(SessionConfig::default());
//!
//! // 创建 Session
//! let session = manager.create("user123").unwrap();
//!
//! // 获取 Session
//! if let Some(s) = manager.get(&session.id) {
//!     println!("User: {}", s.user_id);
//! }
//! ```

pub mod error;
pub mod mfa;
pub mod password;
pub mod random;
pub mod security;
pub mod token;

pub use error::{Error, Result};

// ============================================================================
// 密码相关导出
// ============================================================================

pub use password::{Algorithm, PasswordHasher, hash_password, verify_password};

// ============================================================================
// 随机数生成函数导出
// ============================================================================

pub use random::{
    constant_time_compare, constant_time_compare_str, generate_api_key, generate_csrf_token,
    generate_random_alphanumeric, generate_random_base64_url, generate_random_bytes,
    generate_random_hex, generate_recovery_codes, generate_reset_token, generate_session_token,
};

// ============================================================================
// Token 相关导出
// ============================================================================

#[cfg(feature = "jwt")]
pub use token::jwt::{
    Claims, JwtAlgorithm, JwtBuilder, JwtValidator, TokenPair, TokenPairGenerator,
};
pub use token::refresh::{RefreshConfig, RefreshToken, RefreshTokenManager};
pub use token::session::{Session, SessionConfig, SessionManager, SessionStore};

// ============================================================================
// MFA 相关导出
// ============================================================================

#[cfg(feature = "mfa")]
pub use mfa::hotp::{HotpConfig, HotpGenerator};
#[cfg(feature = "mfa")]
pub use mfa::recovery::{RecoveryCodeManager, RecoveryCodeSet, RecoveryConfig};
#[cfg(feature = "mfa")]
pub use mfa::totp::{TotpConfig, TotpManager, TotpSecret};

// ============================================================================
// 安全防护相关导出
// ============================================================================

pub use security::csrf::{CsrfConfig, CsrfProtection, CsrfToken};
pub use security::rate_limit::{RateLimitConfig, RateLimitInfo, RateLimiter};
