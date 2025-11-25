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
//! - **OAuth 2.0**: OAuth 客户端、PKCE、Token 内省
//! - **API Key 管理**: 完整的 API Key 生命周期管理
//! - **账户安全**: 账户锁定、登录追踪、递增延迟
//! - **WebAuthn / Passkeys**: 无密码认证支持
//!
//! ## Features
//!
//! 本库使用 Cargo features 来允许用户选择性地启用功能：
//!
//! - `argon2` - 启用 Argon2id 密码哈希支持（默认启用）
//! - `bcrypt` - 启用 bcrypt 密码哈希支持
//! - `jwt` - 启用 JWT 支持（默认启用）
//! - `mfa` - 启用 TOTP/HOTP 多因素认证（默认启用）
//! - `webauthn` - 启用 WebAuthn / Passkeys 支持
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
//!
//! ## OAuth 2.0 示例
//!
//! ```rust
//! use authrs::oauth::{OAuthClient, ClientType, GrantType, PkceChallenge, PkceMethod};
//!
//! // 创建 OAuth 客户端
//! let (client, secret) = OAuthClient::builder()
//!     .name("My Application")
//!     .client_type(ClientType::Confidential)
//!     .redirect_uri("https://example.com/callback")
//!     .grant_type(GrantType::AuthorizationCode)
//!     .scope("read")
//!     .build()
//!     .unwrap();
//!
//! // 生成 PKCE challenge
//! let pkce = PkceChallenge::new(PkceMethod::S256).unwrap();
//! let (code_challenge, method) = pkce.authorization_params();
//! ```
//!
//! ## API Key 管理示例
//!
//! ```rust
//! use authrs::api_key::{ApiKeyManager, ApiKeyConfig};
//!
//! // 创建管理器
//! let mut manager = ApiKeyManager::with_default_config();
//!
//! // 创建 API Key
//! let (key, plain_key) = manager.create_key("my-service")
//!     .with_prefix("sk_live")
//!     .with_scope("read")
//!     .with_expires_in_days(90)
//!     .build()
//!     .unwrap();
//!
//! manager.add_key(key);
//!
//! // 验证 API Key
//! if let Some(validated) = manager.validate(&plain_key) {
//!     println!("Key is valid, owner: {}", validated.owner);
//! }
//! ```
//!
//! ## 账户锁定示例
//!
//! ```rust
//! use authrs::security::account::{LoginAttemptTracker, AccountLockoutConfig, LoginCheckResult};
//!
//! // 创建追踪器
//! let mut tracker = LoginAttemptTracker::with_default_config();
//!
//! // 检查是否允许登录
//! match tracker.check_login_allowed("user123", None) {
//!     LoginCheckResult::Allowed => {
//!         // 允许登录尝试
//!         // 如果登录失败：
//!         tracker.record_failed_attempt("user123", None);
//!         // 如果登录成功：
//!         // tracker.record_successful_login("user123", None);
//!     }
//!     LoginCheckResult::Locked { reason, remaining } => {
//!         println!("账户已锁定: {:?}", reason);
//!     }
//!     LoginCheckResult::DelayRequired { wait_time } => {
//!         println!("请等待 {:?} 后重试", wait_time);
//!     }
//!     LoginCheckResult::IpBanned { ip } => {
//!         println!("IP {} 已被封禁", ip);
//!     }
//! }
//! ```
//!
//! ## WebAuthn / Passkeys 示例
//!
#![cfg_attr(feature = "webauthn", doc = "```rust,ignore")]
#![cfg_attr(not(feature = "webauthn"), doc = "```rust,ignore")]
//! use authrs::webauthn::{WebAuthnService, RegistrationManager, InMemoryCredentialStore};
//!
//! // 创建 WebAuthn 服务
//! let service = WebAuthnService::new(
//!     "example.com",
//!     "https://example.com",
//!     "My Application",
//! ).unwrap();
//!
//! // 开始注册流程
//! let reg_manager = service.registration_manager();
//! let (challenge, state) = reg_manager.start_registration(
//!     "user123",
//!     "alice",
//!     "Alice",
//!     "My Passkey",
//!     None,
//! ).unwrap();
//!
//! // 将 challenge 发送给客户端进行处理...
//! // 客户端完成后，使用 finish_registration 完成注册
//! ```

pub mod api_key;
pub mod error;
pub mod mfa;
pub mod oauth;
pub mod password;
pub mod random;
pub mod security;
pub mod token;
#[cfg(feature = "webauthn")]
pub mod webauthn;

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
pub use token::refresh::{
    RefreshConfig, RefreshToken, RefreshTokenManager, RefreshTokenStore, TokenUseResult,
};
pub use token::session::{
    CreateSessionOptions, InMemorySessionStore, Session, SessionConfig, SessionManager,
    SessionStore,
};

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

pub use security::account::{
    AccountLockStatus, AccountLockStore, AccountLockoutConfig, InMemoryAccountLockStore,
    LockReason, LoginAttempt, LoginAttemptTracker, LoginCheckResult, TrackerStats,
};
pub use security::csrf::{CsrfConfig, CsrfProtection, CsrfToken};
pub use security::rate_limit::{RateLimitConfig, RateLimitInfo, RateLimiter};

// ============================================================================
// OAuth 2.0 相关导出
// ============================================================================

pub use oauth::{
    // Token
    AccessToken,
    // Client
    ClientType,
    GrantType,
    InMemoryClientStore,
    // Introspection
    IntrospectionRequest,
    IntrospectionResponse,
    IntrospectionResponseBuilder,
    OAuthClient,
    OAuthClientBuilder,
    OAuthClientStore,
    OAuthError,
    OAuthErrorCode,
    OAuthRefreshToken,
    // PKCE
    PkceChallenge,
    PkceCodeChallenge,
    PkceConfig,
    PkceMethod,
    PkceVerifier,
    TokenIntrospector,
    TokenResponse,
    TokenType,
    TokenTypeHint,
};

// ============================================================================
// API Key 管理相关导出
// ============================================================================

pub use api_key::{
    ApiKey, ApiKeyBuilder, ApiKeyConfig, ApiKeyManager, ApiKeyStats, ApiKeyStatus, ApiKeyStore,
    InMemoryApiKeyStore,
};

// ============================================================================
// WebAuthn / Passkeys 相关导出
// ============================================================================

#[cfg(feature = "webauthn")]
pub use webauthn::{
    // 认证流程
    AuthenticationConfig,
    AuthenticationError,
    AuthenticationManager,
    AuthenticationState,
    AuthenticationStateStore,
    // Re-exports from webauthn-rs
    AuthenticatorAttachment,
    CreationChallengeResponse,
    // 凭证管理
    CredentialStore,
    CredentialStoreError,
    InMemoryAuthenticationStateStore,
    InMemoryCredentialStore,
    // 注册流程
    InMemoryRegistrationStateStore,
    Passkey,
    PublicKeyCredential,
    RegisterPublicKeyCredential,
    RegistrationConfig,
    RegistrationError,
    RegistrationManager,
    RegistrationState,
    RegistrationStateStore,
    RequestChallengeResponse,
    StoredCredential,
    UserVerification,
    Uuid,
    WebAuthnAuthenticationResult,
    // 服务封装
    WebAuthnService,
    WebAuthnServiceError,
    Webauthn,
    WebauthnBuilder,
};
