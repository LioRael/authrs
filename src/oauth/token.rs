//! OAuth Token 结构定义
//!
//! 提供 OAuth 2.0 规范中定义的 token 结构和响应类型。

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

/// OAuth Token 类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    /// Bearer Token（最常见的类型）
    #[default]
    Bearer,
    /// MAC Token
    Mac,
}

impl std::fmt::Display for TokenType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenType::Bearer => write!(f, "Bearer"),
            TokenType::Mac => write!(f, "MAC"),
        }
    }
}

/// OAuth 2.0 Token 响应
///
/// 符合 RFC 6749 Section 5.1 的 token 响应结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// 访问令牌
    pub access_token: String,

    /// Token 类型（通常为 "Bearer"）
    pub token_type: TokenType,

    /// 过期时间（秒）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,

    /// 刷新令牌（可选）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,

    /// 授权范围（空格分隔）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl TokenResponse {
    /// 创建新的 Token 响应
    pub fn new(access_token: impl Into<String>) -> Self {
        Self {
            access_token: access_token.into(),
            token_type: TokenType::Bearer,
            expires_in: None,
            refresh_token: None,
            scope: None,
        }
    }

    /// 设置过期时间
    pub fn with_expires_in(mut self, seconds: u64) -> Self {
        self.expires_in = Some(seconds);
        self
    }

    /// 设置刷新令牌
    pub fn with_refresh_token(mut self, refresh_token: impl Into<String>) -> Self {
        self.refresh_token = Some(refresh_token.into());
        self
    }

    /// 设置授权范围
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// 设置 token 类型
    pub fn with_token_type(mut self, token_type: TokenType) -> Self {
        self.token_type = token_type;
        self
    }
}

/// OAuth 访问令牌详情
///
/// 包含访问令牌的完整信息，用于服务端存储和验证
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    /// Token 值
    pub token: String,

    /// 关联的客户端 ID
    pub client_id: String,

    /// 关联的用户 ID（可选，客户端凭证授权时为空）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,

    /// 授权范围列表
    pub scopes: Vec<String>,

    /// 创建时间
    pub created_at: DateTime<Utc>,

    /// 过期时间
    pub expires_at: DateTime<Utc>,

    /// Token 是否已被撤销
    #[serde(default)]
    pub revoked: bool,
}

impl AccessToken {
    /// 创建新的访问令牌
    pub fn new(
        token: impl Into<String>,
        client_id: impl Into<String>,
        scopes: Vec<String>,
        expires_in: Duration,
    ) -> Self {
        let now = Utc::now();
        Self {
            token: token.into(),
            client_id: client_id.into(),
            user_id: None,
            scopes,
            created_at: now,
            expires_at: now + expires_in,
            revoked: false,
        }
    }

    /// 设置用户 ID
    pub fn with_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// 检查 token 是否有效
    pub fn is_valid(&self) -> bool {
        !self.revoked && self.expires_at > Utc::now()
    }

    /// 检查 token 是否已过期
    pub fn is_expired(&self) -> bool {
        self.expires_at <= Utc::now()
    }

    /// 检查是否具有指定的 scope
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    /// 检查是否具有所有指定的 scopes
    pub fn has_all_scopes(&self, scopes: &[&str]) -> bool {
        scopes.iter().all(|s| self.has_scope(s))
    }

    /// 撤销 token
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// 获取剩余有效时间（秒）
    pub fn remaining_lifetime(&self) -> Option<i64> {
        if self.is_valid() {
            Some((self.expires_at - Utc::now()).num_seconds())
        } else {
            None
        }
    }
}

/// OAuth 刷新令牌详情
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthRefreshToken {
    /// Token 值
    pub token: String,

    /// 关联的客户端 ID
    pub client_id: String,

    /// 关联的用户 ID
    pub user_id: String,

    /// 授权范围列表
    pub scopes: Vec<String>,

    /// 创建时间
    pub created_at: DateTime<Utc>,

    /// 过期时间（可选，某些实现中刷新令牌不过期）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// Token 是否已被撤销
    #[serde(default)]
    pub revoked: bool,

    /// 关联的访问令牌 ID（用于级联撤销）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_id: Option<String>,
}

impl OAuthRefreshToken {
    /// 创建新的刷新令牌
    pub fn new(
        token: impl Into<String>,
        client_id: impl Into<String>,
        user_id: impl Into<String>,
        scopes: Vec<String>,
    ) -> Self {
        Self {
            token: token.into(),
            client_id: client_id.into(),
            user_id: user_id.into(),
            scopes,
            created_at: Utc::now(),
            expires_at: None,
            revoked: false,
            access_token_id: None,
        }
    }

    /// 设置过期时间
    pub fn with_expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// 设置过期时间（从现在开始计算）
    pub fn with_expires_in(mut self, duration: Duration) -> Self {
        self.expires_at = Some(Utc::now() + duration);
        self
    }

    /// 设置关联的访问令牌 ID
    pub fn with_access_token_id(mut self, access_token_id: impl Into<String>) -> Self {
        self.access_token_id = Some(access_token_id.into());
        self
    }

    /// 检查 token 是否有效
    pub fn is_valid(&self) -> bool {
        if self.revoked {
            return false;
        }
        if let Some(expires_at) = self.expires_at {
            expires_at > Utc::now()
        } else {
            true // 没有过期时间则永不过期
        }
    }

    /// 撤销 token
    pub fn revoke(&mut self) {
        self.revoked = true;
    }
}

/// Token 内省响应
///
/// 符合 RFC 7662 的 token 内省响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    /// Token 是否活跃
    pub active: bool,

    /// Token 类型
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<TokenType>,

    /// 授权范围（空格分隔）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// 客户端 ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    /// 用户名
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// 过期时间（Unix 时间戳）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// 签发时间（Unix 时间戳）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// 生效时间（Unix 时间戳）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// 主题（通常是用户 ID）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// 受众
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    /// 签发者
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// JWT ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

impl IntrospectionResponse {
    /// 创建一个表示无效 token 的响应
    pub fn inactive() -> Self {
        Self {
            active: false,
            token_type: None,
            scope: None,
            client_id: None,
            username: None,
            exp: None,
            iat: None,
            nbf: None,
            sub: None,
            aud: None,
            iss: None,
            jti: None,
        }
    }

    /// 从访问令牌创建内省响应
    pub fn from_access_token(token: &AccessToken) -> Self {
        Self {
            active: token.is_valid(),
            token_type: Some(TokenType::Bearer),
            scope: if token.scopes.is_empty() {
                None
            } else {
                Some(token.scopes.join(" "))
            },
            client_id: Some(token.client_id.clone()),
            username: None,
            exp: Some(token.expires_at.timestamp()),
            iat: Some(token.created_at.timestamp()),
            nbf: Some(token.created_at.timestamp()),
            sub: token.user_id.clone(),
            aud: None,
            iss: None,
            jti: None,
        }
    }
}

/// OAuth 错误响应
///
/// 符合 RFC 6749 Section 5.2 的错误响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthError {
    /// 错误代码
    pub error: OAuthErrorCode,

    /// 错误描述
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,

    /// 错误信息 URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,
}

/// OAuth 错误代码
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthErrorCode {
    /// 请求缺少必需参数、包含无效参数值、多次包含某参数或格式错误
    InvalidRequest,
    /// 客户端认证失败
    InvalidClient,
    /// 提供的授权许可或刷新令牌无效、已过期、已撤销
    InvalidGrant,
    /// 客户端没有使用此方法请求授权的权限
    UnauthorizedClient,
    /// 授权服务器不支持此授权类型
    UnsupportedGrantType,
    /// 请求的范围无效、未知或格式错误
    InvalidScope,
    /// 授权服务器遇到意外情况
    ServerError,
    /// 授权服务器暂时无法处理请求
    TemporarilyUnavailable,
    /// 访问被拒绝
    AccessDenied,
    /// 不支持的响应类型
    UnsupportedResponseType,
}

impl OAuthError {
    /// 创建新的 OAuth 错误
    pub fn new(error: OAuthErrorCode) -> Self {
        Self {
            error,
            error_description: None,
            error_uri: None,
        }
    }

    /// 设置错误描述
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.error_description = Some(description.into());
        self
    }

    /// 设置错误 URI
    pub fn with_uri(mut self, uri: impl Into<String>) -> Self {
        self.error_uri = Some(uri.into());
        self
    }

    /// 创建无效请求错误
    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self::new(OAuthErrorCode::InvalidRequest).with_description(description)
    }

    /// 创建无效客户端错误
    pub fn invalid_client(description: impl Into<String>) -> Self {
        Self::new(OAuthErrorCode::InvalidClient).with_description(description)
    }

    /// 创建无效授权错误
    pub fn invalid_grant(description: impl Into<String>) -> Self {
        Self::new(OAuthErrorCode::InvalidGrant).with_description(description)
    }

    /// 创建无效范围错误
    pub fn invalid_scope(description: impl Into<String>) -> Self {
        Self::new(OAuthErrorCode::InvalidScope).with_description(description)
    }

    /// 创建不支持的授权类型错误
    pub fn unsupported_grant_type() -> Self {
        Self::new(OAuthErrorCode::UnsupportedGrantType)
            .with_description("The authorization grant type is not supported")
    }
}

impl std::fmt::Display for OAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.error)?;
        if let Some(desc) = &self.error_description {
            write!(f, ": {}", desc)?;
        }
        Ok(())
    }
}

impl std::error::Error for OAuthError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_response_builder() {
        let response = TokenResponse::new("access_token_123")
            .with_expires_in(3600)
            .with_refresh_token("refresh_token_456")
            .with_scope("read write");

        assert_eq!(response.access_token, "access_token_123");
        assert_eq!(response.token_type, TokenType::Bearer);
        assert_eq!(response.expires_in, Some(3600));
        assert_eq!(
            response.refresh_token,
            Some("refresh_token_456".to_string())
        );
        assert_eq!(response.scope, Some("read write".to_string()));
    }

    #[test]
    fn test_access_token_validity() {
        let token = AccessToken::new(
            "test_token",
            "client_123",
            vec!["read".to_string()],
            Duration::hours(1),
        );

        assert!(token.is_valid());
        assert!(!token.is_expired());
        assert!(token.has_scope("read"));
        assert!(!token.has_scope("write"));
    }

    #[test]
    fn test_access_token_expired() {
        let token = AccessToken::new(
            "test_token",
            "client_123",
            vec![],
            Duration::seconds(-10), // 已过期
        );

        assert!(!token.is_valid());
        assert!(token.is_expired());
    }

    #[test]
    fn test_access_token_revoked() {
        let mut token = AccessToken::new("test_token", "client_123", vec![], Duration::hours(1));

        assert!(token.is_valid());
        token.revoke();
        assert!(!token.is_valid());
    }

    #[test]
    fn test_introspection_inactive() {
        let response = IntrospectionResponse::inactive();
        assert!(!response.active);
    }

    #[test]
    fn test_introspection_from_token() {
        let token = AccessToken::new(
            "test_token",
            "client_123",
            vec!["read".to_string(), "write".to_string()],
            Duration::hours(1),
        )
        .with_user_id("user_456");

        let response = IntrospectionResponse::from_access_token(&token);

        assert!(response.active);
        assert_eq!(response.client_id, Some("client_123".to_string()));
        assert_eq!(response.sub, Some("user_456".to_string()));
        assert_eq!(response.scope, Some("read write".to_string()));
    }

    #[test]
    fn test_oauth_error() {
        let error = OAuthError::invalid_request("Missing required parameter: client_id");

        assert_eq!(error.error, OAuthErrorCode::InvalidRequest);
        assert!(error.error_description.is_some());
    }

    #[test]
    fn test_refresh_token() {
        let token = OAuthRefreshToken::new(
            "refresh_123",
            "client_123",
            "user_456",
            vec!["read".to_string()],
        )
        .with_expires_in(Duration::days(30));

        assert!(token.is_valid());
        assert!(token.expires_at.is_some());
    }

    #[test]
    fn test_token_type_display() {
        assert_eq!(TokenType::Bearer.to_string(), "Bearer");
        assert_eq!(TokenType::Mac.to_string(), "MAC");
    }

    #[test]
    fn test_token_response_serialization() {
        let response = TokenResponse::new("test_token")
            .with_expires_in(3600)
            .with_scope("read");

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("access_token"));
        assert!(json.contains("token_type"));

        let deserialized: TokenResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.access_token, "test_token");
    }
}
