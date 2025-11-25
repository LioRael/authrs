//! Token 模块
//!
//! 提供各种 Token 的生成、验证和管理功能。
//!
//! ## 子模块
//!
//! - **jwt**: JSON Web Token (JWT) 的生成和验证
//! - **session**: Session Token 管理
//! - **refresh**: Refresh Token 机制
//!
//! ## JWT 示例
//!
//! ```rust
//! use authrs::token::jwt::{JwtBuilder, JwtValidator};
//!
//! // 创建 JWT
//! let secret = b"my-secret-key-at-least-32-bytes!";
//! let token = JwtBuilder::new()
//!     .subject("user123")
//!     .issuer("my-app")
//!     .expires_in_hours(24)
//!     .claim("role", "admin")
//!     .build_with_secret(secret)
//!     .unwrap();
//!
//! // 验证 JWT
//! let validator = JwtValidator::new(secret);
//! let claims = validator.validate(&token).unwrap();
//! assert_eq!(claims.sub, Some("user123".to_string()));
//! ```
//!
//! ## Session Token 示例
//!
//! ```rust
//! use authrs::token::session::{SessionManager, SessionConfig};
//!
//! // 创建 session 管理器（使用内存存储）
//! let config = SessionConfig::default();
//! let manager = SessionManager::new(config);
//!
//! // 创建 session
//! let session = manager.create("user123").unwrap();
//!
//! // 验证 session
//! if let Some(s) = manager.get(&session.id) {
//!     assert_eq!(s.user_id, "user123");
//! }
//! ```
//!
//! ## Refresh Token 示例
//!
//! ```rust
//! use authrs::token::refresh::{RefreshTokenManager, RefreshConfig};
//!
//! // 创建 Refresh Token 管理器
//! let config = RefreshConfig::default();
//! let manager = RefreshTokenManager::new(config);
//!
//! // 生成 Refresh Token
//! let token = manager.generate("user123").unwrap();
//!
//! // 使用 Refresh Token（会自动轮换）
//! let result = manager.use_token(&token.token).unwrap();
//! if let Some(new_token) = result.new_token {
//!     println!("New token generated");
//! }
//! ```

pub mod jwt;
pub mod refresh;
pub mod session;

pub use jwt::{
    Claims, JwtAlgorithm, JwtBuilder, JwtValidator, JwtValidatorConfig, TokenPair,
    TokenPairGenerator,
};
pub use refresh::{RefreshConfig, RefreshToken, RefreshTokenManager};
pub use session::{Session, SessionConfig, SessionManager, SessionStore};
