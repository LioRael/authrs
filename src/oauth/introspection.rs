//! OAuth 2.0 Token 内省 (RFC 7662)
//!
//! 本模块提供 RFC 7662 定义的 Token 内省功能。
//! Token 内省允许资源服务器向授权服务器查询访问令牌的状态。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Token 内省请求
///
/// 资源服务器用于向授权服务器查询 OAuth 2.0 令牌的活跃状态。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectionRequest {
    /// 要内省的令牌（必需）
    pub token: String,

    /// 令牌类型提示
    /// 可选值: "access_token", "refresh_token"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type_hint: Option<TokenTypeHint>,
}

impl IntrospectionRequest {
    /// 为给定令牌创建新的内省请求
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            token_type_hint: None,
        }
    }

    /// 设置令牌类型提示
    pub fn with_type_hint(mut self, hint: TokenTypeHint) -> Self {
        self.token_type_hint = Some(hint);
        self
    }
}

/// 被内省令牌的类型提示
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenTypeHint {
    /// 访问令牌
    AccessToken,
    /// 刷新令牌
    RefreshToken,
}

/// Token 内省响应
///
/// 包含令牌状态和元数据信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrospectionResponse {
    /// 布尔值，指示令牌是否活跃
    /// 这是响应中唯一必需的字段
    pub active: bool,

    /// JSON 字符串，包含以空格分隔的权限范围列表
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// OAuth 2.0 客户端标识符
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,

    /// 资源所有者的可读标识符
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// 令牌类型（如 "Bearer"）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,

    /// 令牌过期的整数时间戳（自 epoch 以来的秒数）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// 令牌签发的整数时间戳
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// 令牌生效前不可使用的整数时间戳
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// 令牌主题（通常是用户 ID）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// 令牌的预期受众
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    /// 令牌签发者
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// 令牌的唯一标识符
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// 额外的自定义声明
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl IntrospectionResponse {
    /// 创建表示令牌无效的响应
    pub fn inactive() -> Self {
        Self {
            active: false,
            scope: None,
            client_id: None,
            username: None,
            token_type: None,
            exp: None,
            iat: None,
            nbf: None,
            sub: None,
            aud: None,
            iss: None,
            jti: None,
            extra: HashMap::new(),
        }
    }

    /// 创建表示令牌有效的响应
    pub fn active() -> IntrospectionResponseBuilder {
        IntrospectionResponseBuilder::new()
    }

    /// 根据 `exp` 声明检查令牌是否已过期
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.exp {
            let now = Utc::now().timestamp();
            exp < now
        } else {
            false
        }
    }

    /// 获取过期时间（DateTime 格式）
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.exp.and_then(|ts| DateTime::from_timestamp(ts, 0))
    }

    /// 获取签发时间（DateTime 格式）
    pub fn issued_at(&self) -> Option<DateTime<Utc>> {
        self.iat.and_then(|ts| DateTime::from_timestamp(ts, 0))
    }

    /// 获取权限范围（字符串向量）
    pub fn scopes(&self) -> Vec<&str> {
        self.scope
            .as_ref()
            .map(|s| s.split_whitespace().collect())
            .unwrap_or_default()
    }

    /// 检查令牌是否具有指定的权限范围
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes().contains(&scope)
    }
}

impl Default for IntrospectionResponse {
    fn default() -> Self {
        Self::inactive()
    }
}

/// 用于创建活跃令牌内省响应的构建器
#[derive(Debug, Default)]
pub struct IntrospectionResponseBuilder {
    scope: Option<String>,
    client_id: Option<String>,
    username: Option<String>,
    token_type: Option<String>,
    exp: Option<i64>,
    iat: Option<i64>,
    nbf: Option<i64>,
    sub: Option<String>,
    aud: Option<String>,
    iss: Option<String>,
    jti: Option<String>,
    extra: HashMap<String, serde_json::Value>,
}

impl IntrospectionResponseBuilder {
    /// 创建新的活跃令牌响应构建器
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置权限范围（以空格分隔的字符串）
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// 从切片设置权限范围
    pub fn scopes(mut self, scopes: &[&str]) -> Self {
        self.scope = Some(scopes.join(" "));
        self
    }

    /// 设置客户端 ID
    pub fn client_id(mut self, client_id: impl Into<String>) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// 设置用户名
    pub fn username(mut self, username: impl Into<String>) -> Self {
        self.username = Some(username.into());
        self
    }

    /// 设置令牌类型
    pub fn token_type(mut self, token_type: impl Into<String>) -> Self {
        self.token_type = Some(token_type.into());
        self
    }

    /// 设置过期时间戳
    pub fn exp(mut self, exp: i64) -> Self {
        self.exp = Some(exp);
        self
    }

    /// 从 DateTime 设置过期时间
    pub fn expires_at(mut self, dt: DateTime<Utc>) -> Self {
        self.exp = Some(dt.timestamp());
        self
    }

    /// 设置签发时间戳
    pub fn iat(mut self, iat: i64) -> Self {
        self.iat = Some(iat);
        self
    }

    /// 从 DateTime 设置签发时间
    pub fn issued_at(mut self, dt: DateTime<Utc>) -> Self {
        self.iat = Some(dt.timestamp());
        self
    }

    /// 设置生效时间戳
    pub fn nbf(mut self, nbf: i64) -> Self {
        self.nbf = Some(nbf);
        self
    }

    /// 设置主题
    pub fn sub(mut self, sub: impl Into<String>) -> Self {
        self.sub = Some(sub.into());
        self
    }

    /// 设置受众
    pub fn aud(mut self, aud: impl Into<String>) -> Self {
        self.aud = Some(aud.into());
        self
    }

    /// 设置签发者
    pub fn iss(mut self, iss: impl Into<String>) -> Self {
        self.iss = Some(iss.into());
        self
    }

    /// 设置 JWT ID
    pub fn jti(mut self, jti: impl Into<String>) -> Self {
        self.jti = Some(jti.into());
        self
    }

    /// 添加自定义声明
    pub fn claim(mut self, key: impl Into<String>, value: impl Serialize) -> Self {
        if let Ok(v) = serde_json::to_value(value) {
            self.extra.insert(key.into(), v);
        }
        self
    }

    /// 构建内省响应
    pub fn build(self) -> IntrospectionResponse {
        IntrospectionResponse {
            active: true,
            scope: self.scope,
            client_id: self.client_id,
            username: self.username,
            token_type: self.token_type,
            exp: self.exp,
            iat: self.iat,
            nbf: self.nbf,
            sub: self.sub,
            aud: self.aud,
            iss: self.iss,
            jti: self.jti,
            extra: self.extra,
        }
    }
}

/// Token 内省 trait
///
/// 实现此 trait 以提供自定义的令牌内省逻辑。
pub trait TokenIntrospector: Send + Sync {
    /// 内省令牌并返回其元数据
    ///
    /// # 参数
    ///
    /// * `request` - 包含令牌的内省请求
    ///
    /// # 返回
    ///
    /// 包含令牌元数据的内省响应
    fn introspect(&self, request: &IntrospectionRequest) -> IntrospectionResponse;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inactive_response() {
        let response = IntrospectionResponse::inactive();
        assert!(!response.active);
        assert!(response.scope.is_none());
        assert!(response.client_id.is_none());
    }

    #[test]
    fn test_active_response_builder() {
        let response = IntrospectionResponse::active()
            .scope("read write")
            .client_id("test-client")
            .username("testuser")
            .token_type("Bearer")
            .sub("user123")
            .iss("https://auth.example.com")
            .build();

        assert!(response.active);
        assert_eq!(response.scope.as_deref(), Some("read write"));
        assert_eq!(response.client_id.as_deref(), Some("test-client"));
        assert_eq!(response.username.as_deref(), Some("testuser"));
        assert_eq!(response.token_type.as_deref(), Some("Bearer"));
        assert_eq!(response.sub.as_deref(), Some("user123"));
        assert_eq!(response.iss.as_deref(), Some("https://auth.example.com"));
    }

    #[test]
    fn test_scopes_parsing() {
        let response = IntrospectionResponse::active()
            .scope("read write admin")
            .build();

        let scopes = response.scopes();
        assert_eq!(scopes, vec!["read", "write", "admin"]);
        assert!(response.has_scope("read"));
        assert!(response.has_scope("write"));
        assert!(response.has_scope("admin"));
        assert!(!response.has_scope("delete"));
    }

    #[test]
    fn test_scopes_from_slice() {
        let response = IntrospectionResponse::active()
            .scopes(&["read", "write", "admin"])
            .build();

        assert_eq!(response.scope.as_deref(), Some("read write admin"));
    }

    #[test]
    fn test_expiration() {
        let now = Utc::now();
        let past = now - chrono::Duration::hours(1);
        let future = now + chrono::Duration::hours(1);

        let expired = IntrospectionResponse::active().expires_at(past).build();
        assert!(expired.is_expired());

        let valid = IntrospectionResponse::active().expires_at(future).build();
        assert!(!valid.is_expired());
    }

    #[test]
    fn test_introspection_request() {
        let request =
            IntrospectionRequest::new("test-token").with_type_hint(TokenTypeHint::AccessToken);

        assert_eq!(request.token, "test-token");
        assert_eq!(request.token_type_hint, Some(TokenTypeHint::AccessToken));
    }

    #[test]
    fn test_custom_claims() {
        let response = IntrospectionResponse::active()
            .claim("tenant_id", "tenant123")
            .claim("permissions", vec!["read", "write"])
            .build();

        assert!(response.active);
        assert_eq!(
            response.extra.get("tenant_id"),
            Some(&serde_json::json!("tenant123"))
        );
        assert_eq!(
            response.extra.get("permissions"),
            Some(&serde_json::json!(["read", "write"]))
        );
    }

    #[test]
    fn test_serialization() {
        let response = IntrospectionResponse::active()
            .scope("read write")
            .client_id("test-client")
            .sub("user123")
            .exp(1234567890)
            .build();

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"active\":true"));
        assert!(json.contains("\"scope\":\"read write\""));
        assert!(json.contains("\"client_id\":\"test-client\""));
    }

    #[test]
    fn test_deserialization() {
        let json = r#"{
            "active": true,
            "scope": "read write",
            "client_id": "test-client",
            "username": "testuser",
            "token_type": "Bearer",
            "exp": 1234567890,
            "custom_field": "custom_value"
        }"#;

        let response: IntrospectionResponse = serde_json::from_str(json).unwrap();
        assert!(response.active);
        assert_eq!(response.scope.as_deref(), Some("read write"));
        assert_eq!(response.client_id.as_deref(), Some("test-client"));
        assert_eq!(
            response.extra.get("custom_field"),
            Some(&serde_json::json!("custom_value"))
        );
    }
}
