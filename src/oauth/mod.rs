//! OAuth 2.0 模块
//!
//! 提供 OAuth 2.0 协议相关的功能实现，包括：
//!
//! - **客户端管理** (`client`): OAuth 客户端的创建、验证和存储
//! - **PKCE** (`pkce`): Proof Key for Code Exchange 支持
//! - **Token** (`token`): OAuth Token 结构和响应类型
//! - **Token 内省** (`introspection`): RFC 7662 Token Introspection
//!
//! ## 功能概述
//!
//! ### 客户端凭证
//!
//! ```rust
//! use authrs::oauth::{OAuthClient, ClientType, GrantType};
//!
//! // 创建机密客户端
//! let (client, secret) = OAuthClient::builder()
//!     .name("My Application")
//!     .client_type(ClientType::Confidential)
//!     .redirect_uri("https://example.com/callback")
//!     .grant_type(GrantType::AuthorizationCode)
//!     .scope("read")
//!     .scope("write")
//!     .build()
//!     .unwrap();
//!
//! // 保存明文密钥（仅此一次机会）
//! let client_secret = secret.unwrap();
//!
//! // 验证客户端密钥
//! assert!(client.verify_secret(&client_secret));
//! ```
//!
//! ### PKCE (Proof Key for Code Exchange)
//!
//! ```rust
//! use authrs::oauth::{PkceChallenge, PkceMethod};
//!
//! // 生成 PKCE challenge
//! let challenge = PkceChallenge::new(PkceMethod::S256).unwrap();
//!
//! // 获取授权请求参数
//! let (code_challenge, method) = challenge.authorization_params();
//!
//! // 保存 verifier 用于 token 请求
//! let code_verifier = challenge.verifier();
//!
//! // 服务端验证
//! let is_valid = PkceChallenge::verify(code_verifier, code_challenge, PkceMethod::S256);
//! assert!(is_valid);
//! ```
//!
//! ### Token 响应
//!
//! ```rust
//! use authrs::oauth::TokenResponse;
//!
//! let response = TokenResponse::new("access_token_here")
//!     .with_expires_in(3600)
//!     .with_refresh_token("refresh_token_here")
//!     .with_scope("read write");
//! ```
//!
//! ### Token 内省
//!
//! ```rust
//! use authrs::oauth::{IntrospectionRequest, IntrospectionResponse};
//!
//! // 创建内省请求
//! let request = IntrospectionRequest::new("token_to_check");
//!
//! // 创建活跃 token 响应
//! let response = IntrospectionResponse::active()
//!     .scope("read write")
//!     .client_id("client_123")
//!     .subject("user_456")
//!     .build();
//! ```

pub mod client;
pub mod introspection;
pub mod pkce;
pub mod token;

// ============================================================================
// Client 模块导出
// ============================================================================

pub use client::{
    ClientType, GrantType, InMemoryClientStore, OAuthClient, OAuthClientBuilder, OAuthClientStore,
};

// ============================================================================
// PKCE 模块导出
// ============================================================================

pub use pkce::{PkceChallenge, PkceCodeChallenge, PkceConfig, PkceMethod, PkceVerifier};

// ============================================================================
// Token 模块导出
// ============================================================================

pub use token::{
    AccessToken, IntrospectionResponse as TokenIntrospectionResponse, OAuthError, OAuthErrorCode,
    OAuthRefreshToken, TokenResponse, TokenType,
};

// ============================================================================
// Introspection 模块导出
// ============================================================================

pub use introspection::{
    IntrospectionRequest, IntrospectionResponse, IntrospectionResponseBuilder, TokenIntrospector,
    TokenTypeHint,
};
