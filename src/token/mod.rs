//! Token 模块
//!
//! 提供各种 Token 的生成、验证和管理功能。
//!
//! ## 子模块
//!
//! - **jwt**: JSON Web Token (JWT) 的生成和验证（需启用 `jwt` feature）
//! - **session**: Session Token 管理
//! - **refresh**: Refresh Token 机制
//!
//! ## Features
//!
//! - `jwt` - 启用 JWT 支持（默认启用）
//!
//! ## JWT 示例
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

#[cfg(feature = "jwt")]
pub mod jwt;
pub mod refresh;
pub mod session;

// JWT 导出
#[cfg(feature = "jwt")]
pub use jwt::{
    Claims, JwtAlgorithm, JwtBuilder, JwtValidator, JwtValidatorConfig, TokenPair,
    TokenPairGenerator,
};

// Refresh Token 导出
pub use refresh::{
    GenerateOptions as RefreshGenerateOptions, RefreshConfig, RefreshToken, RefreshTokenManager,
    RefreshTokenStore, TokenUseResult,
};

// Session 导出
pub use session::{
    CreateSessionOptions, InMemorySessionStore, Session, SessionConfig, SessionManager,
    SessionStore,
};
