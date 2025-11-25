//! OAuth 2.0 客户端凭证管理模块
//!
//! 提供 OAuth 客户端的创建、验证和管理功能。

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::{Error, Result, StorageError, ValidationError};
use crate::random::{generate_random_alphanumeric, generate_random_base64_url};

/// OAuth 客户端类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ClientType {
    /// 机密客户端（可以安全存储密钥的服务端应用）
    #[default]
    Confidential,
    /// 公开客户端（无法安全存储密钥的客户端应用，如 SPA、移动 App）
    Public,
}

/// OAuth 客户端配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthClient {
    /// 客户端 ID
    pub client_id: String,

    /// 客户端密钥哈希（仅 Confidential 客户端）
    /// 存储哈希而非明文以增强安全性
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_hash: Option<String>,

    /// 客户端名称
    pub name: String,

    /// 客户端类型
    pub client_type: ClientType,

    /// 允许的重定向 URI 列表
    pub redirect_uris: Vec<String>,

    /// 允许的授权类型
    pub grant_types: Vec<GrantType>,

    /// 允许的权限范围
    pub scopes: Vec<String>,

    /// 客户端元数据
    #[serde(default)]
    pub metadata: HashMap<String, String>,

    /// 创建时间
    pub created_at: DateTime<Utc>,

    /// 更新时间
    pub updated_at: DateTime<Utc>,

    /// 是否启用
    pub enabled: bool,
}

/// OAuth 授权类型
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GrantType {
    /// 授权码模式
    AuthorizationCode,
    /// 客户端凭证模式
    ClientCredentials,
    /// 刷新令牌
    RefreshToken,
    /// 隐式授权（不推荐）
    Implicit,
    /// 资源所有者密码凭证（不推荐）
    Password,
}

impl std::fmt::Display for GrantType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GrantType::AuthorizationCode => write!(f, "authorization_code"),
            GrantType::ClientCredentials => write!(f, "client_credentials"),
            GrantType::RefreshToken => write!(f, "refresh_token"),
            GrantType::Implicit => write!(f, "implicit"),
            GrantType::Password => write!(f, "password"),
        }
    }
}

impl std::str::FromStr for GrantType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "authorization_code" => Ok(GrantType::AuthorizationCode),
            "client_credentials" => Ok(GrantType::ClientCredentials),
            "refresh_token" => Ok(GrantType::RefreshToken),
            "implicit" => Ok(GrantType::Implicit),
            "password" => Ok(GrantType::Password),
            _ => Err(Error::Validation(ValidationError::Custom(format!(
                "Unknown grant type: {}",
                s
            )))),
        }
    }
}

/// OAuth 客户端构建器
#[derive(Debug, Default)]
pub struct OAuthClientBuilder {
    name: Option<String>,
    client_type: ClientType,
    redirect_uris: Vec<String>,
    grant_types: Vec<GrantType>,
    scopes: Vec<String>,
    metadata: HashMap<String, String>,
}

impl OAuthClientBuilder {
    /// 创建新的构建器
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置客户端名称
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// 设置客户端类型
    pub fn client_type(mut self, client_type: ClientType) -> Self {
        self.client_type = client_type;
        self
    }

    /// 添加重定向 URI
    pub fn redirect_uri(mut self, uri: impl Into<String>) -> Self {
        self.redirect_uris.push(uri.into());
        self
    }

    /// 设置多个重定向 URI
    pub fn redirect_uris(mut self, uris: Vec<String>) -> Self {
        self.redirect_uris = uris;
        self
    }

    /// 添加授权类型
    pub fn grant_type(mut self, grant_type: GrantType) -> Self {
        if !self.grant_types.contains(&grant_type) {
            self.grant_types.push(grant_type);
        }
        self
    }

    /// 设置多个授权类型
    pub fn grant_types(mut self, grant_types: Vec<GrantType>) -> Self {
        self.grant_types = grant_types;
        self
    }

    /// 添加权限范围
    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    /// 设置多个权限范围
    pub fn scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// 添加元数据
    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// 构建客户端（返回客户端和明文密钥）
    ///
    /// 对于 Confidential 客户端，会生成并返回明文密钥（仅此一次机会获取）
    /// 对于 Public 客户端，密钥为 None
    pub fn build(self) -> Result<(OAuthClient, Option<String>)> {
        let name = self
            .name
            .ok_or_else(|| Error::Validation(ValidationError::EmptyField("name".to_string())))?;

        if self.redirect_uris.is_empty() {
            return Err(Error::Validation(ValidationError::Custom(
                "At least one redirect URI is required".to_string(),
            )));
        }

        // 验证重定向 URI 格式
        for uri in &self.redirect_uris {
            validate_redirect_uri(uri)?;
        }

        let client_id = generate_client_id()?;
        let now = Utc::now();

        // 为 Confidential 客户端生成密钥
        let (client_secret_hash, plain_secret) = if self.client_type == ClientType::Confidential {
            let secret = generate_client_secret()?;
            let hash = hash_client_secret(&secret);
            (Some(hash), Some(secret))
        } else {
            (None, None)
        };

        let grant_types = if self.grant_types.is_empty() {
            vec![GrantType::AuthorizationCode]
        } else {
            self.grant_types
        };

        let client = OAuthClient {
            client_id,
            client_secret_hash,
            name,
            client_type: self.client_type,
            redirect_uris: self.redirect_uris,
            grant_types,
            scopes: self.scopes,
            metadata: self.metadata,
            created_at: now,
            updated_at: now,
            enabled: true,
        };

        Ok((client, plain_secret))
    }
}

impl OAuthClient {
    /// 创建构建器
    pub fn builder() -> OAuthClientBuilder {
        OAuthClientBuilder::new()
    }

    /// 验证客户端密钥
    pub fn verify_secret(&self, secret: &str) -> bool {
        match &self.client_secret_hash {
            Some(hash) => verify_client_secret(secret, hash),
            None => false, // Public 客户端没有密钥
        }
    }

    /// 检查是否允许指定的授权类型
    pub fn allows_grant_type(&self, grant_type: GrantType) -> bool {
        self.grant_types.contains(&grant_type)
    }

    /// 检查是否允许指定的重定向 URI
    pub fn allows_redirect_uri(&self, uri: &str) -> bool {
        self.redirect_uris.iter().any(|allowed| allowed == uri)
    }

    /// 检查是否允许指定的权限范围
    pub fn allows_scope(&self, scope: &str) -> bool {
        self.scopes.is_empty() || self.scopes.iter().any(|s| s == scope)
    }

    /// 检查是否允许所有请求的权限范围
    pub fn allows_scopes(&self, scopes: &[String]) -> bool {
        scopes.iter().all(|s| self.allows_scope(s))
    }

    /// 过滤并返回允许的权限范围
    pub fn filter_scopes(&self, requested: &[String]) -> Vec<String> {
        if self.scopes.is_empty() {
            requested.to_vec()
        } else {
            requested
                .iter()
                .filter(|s| self.scopes.contains(s))
                .cloned()
                .collect()
        }
    }

    /// 轮换客户端密钥
    ///
    /// 生成新密钥并返回明文（仅此一次机会获取）
    pub fn rotate_secret(&mut self) -> Result<Option<String>> {
        if self.client_type == ClientType::Public {
            return Ok(None);
        }

        let new_secret = generate_client_secret()?;
        self.client_secret_hash = Some(hash_client_secret(&new_secret));
        self.updated_at = Utc::now();

        Ok(Some(new_secret))
    }

    /// 禁用客户端
    pub fn disable(&mut self) {
        self.enabled = false;
        self.updated_at = Utc::now();
    }

    /// 启用客户端
    pub fn enable(&mut self) {
        self.enabled = true;
        self.updated_at = Utc::now();
    }
}

/// OAuth 客户端存储 trait
#[async_trait]
pub trait OAuthClientStore: Send + Sync {
    /// 保存客户端
    async fn save(&mut self, client: &OAuthClient) -> Result<()>;

    /// 根据 client_id 查找客户端
    async fn find_by_id(&self, client_id: &str) -> Result<Option<OAuthClient>>;

    /// 删除客户端
    async fn delete(&mut self, client_id: &str) -> Result<()>;

    /// 列出所有客户端
    async fn list(&self) -> Result<Vec<OAuthClient>>;
}

/// 内存客户端存储实现
#[derive(Debug, Default)]
pub struct InMemoryClientStore {
    clients: HashMap<String, OAuthClient>,
}

impl InMemoryClientStore {
    /// 创建新的内存存储
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl OAuthClientStore for InMemoryClientStore {
    async fn save(&mut self, client: &OAuthClient) -> Result<()> {
        self.clients
            .insert(client.client_id.clone(), client.clone());
        Ok(())
    }

    async fn find_by_id(&self, client_id: &str) -> Result<Option<OAuthClient>> {
        Ok(self.clients.get(client_id).cloned())
    }

    async fn delete(&mut self, client_id: &str) -> Result<()> {
        self.clients
            .remove(client_id)
            .ok_or_else(|| Error::Storage(StorageError::NotFound(client_id.to_string())))?;
        Ok(())
    }

    async fn list(&self) -> Result<Vec<OAuthClient>> {
        Ok(self.clients.values().cloned().collect())
    }
}

// ============================================================================
// 辅助函数
// ============================================================================

/// 生成客户端 ID
fn generate_client_id() -> Result<String> {
    // 格式: oa_<随机字符串>
    let random = generate_random_alphanumeric(24)?;
    Ok(format!("oa_{}", random))
}

/// 生成客户端密钥
fn generate_client_secret() -> Result<String> {
    // 生成 32 字节的 base64url 编码密钥
    generate_random_base64_url(32)
}

/// 哈希客户端密钥
///
/// 使用 SHA-256 进行简单哈希（生产环境可考虑 Argon2）
fn hash_client_secret(secret: &str) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let result = hasher.finalize();

    // 返回十六进制编码
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

/// 验证客户端密钥
fn verify_client_secret(secret: &str, hash: &str) -> bool {
    use crate::random::constant_time_compare_str;

    let computed_hash = hash_client_secret(secret);
    constant_time_compare_str(&computed_hash, hash)
}

/// 验证重定向 URI 格式
fn validate_redirect_uri(uri: &str) -> Result<()> {
    // 基本验证：必须是有效的 URL 格式
    if uri.is_empty() {
        return Err(Error::Validation(ValidationError::Custom(
            "Redirect URI cannot be empty".to_string(),
        )));
    }

    // 允许 localhost 用于开发
    if uri.starts_with("http://localhost") || uri.starts_with("http://127.0.0.1") {
        return Ok(());
    }

    // 生产环境应使用 HTTPS
    if !uri.starts_with("https://") && !uri.starts_with("http://") {
        // 允许自定义 scheme（用于移动应用）
        if !uri.contains("://") {
            return Err(Error::Validation(ValidationError::Custom(
                "Redirect URI must have a valid scheme".to_string(),
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_confidential_client() {
        let (client, secret) = OAuthClient::builder()
            .name("Test App")
            .client_type(ClientType::Confidential)
            .redirect_uri("https://example.com/callback")
            .grant_type(GrantType::AuthorizationCode)
            .scope("read")
            .scope("write")
            .build()
            .unwrap();

        assert!(client.client_id.starts_with("oa_"));
        assert!(client.client_secret_hash.is_some());
        assert!(secret.is_some());
        assert_eq!(client.name, "Test App");
        assert!(client.enabled);

        // 验证密钥
        assert!(client.verify_secret(&secret.unwrap()));
        assert!(!client.verify_secret("wrong_secret"));
    }

    #[test]
    fn test_create_public_client() {
        let (client, secret) = OAuthClient::builder()
            .name("Mobile App")
            .client_type(ClientType::Public)
            .redirect_uri("myapp://callback")
            .build()
            .unwrap();

        assert!(client.client_secret_hash.is_none());
        assert!(secret.is_none());
        assert!(!client.verify_secret("any_secret"));
    }

    #[test]
    fn test_grant_type_check() {
        let (client, _) = OAuthClient::builder()
            .name("Test")
            .redirect_uri("https://example.com/cb")
            .grant_type(GrantType::AuthorizationCode)
            .grant_type(GrantType::RefreshToken)
            .build()
            .unwrap();

        assert!(client.allows_grant_type(GrantType::AuthorizationCode));
        assert!(client.allows_grant_type(GrantType::RefreshToken));
        assert!(!client.allows_grant_type(GrantType::ClientCredentials));
    }

    #[test]
    fn test_scope_validation() {
        let (client, _) = OAuthClient::builder()
            .name("Test")
            .redirect_uri("https://example.com/cb")
            .scope("read")
            .scope("write")
            .build()
            .unwrap();

        assert!(client.allows_scope("read"));
        assert!(client.allows_scope("write"));
        assert!(!client.allows_scope("admin"));

        let filtered = client.filter_scopes(&["read".to_string(), "admin".to_string()]);
        assert_eq!(filtered, vec!["read".to_string()]);
    }

    #[test]
    fn test_redirect_uri_validation() {
        // 有效的 URI
        assert!(validate_redirect_uri("https://example.com/callback").is_ok());
        assert!(validate_redirect_uri("http://localhost:3000/cb").is_ok());
        assert!(validate_redirect_uri("myapp://callback").is_ok());

        // 无效的 URI
        assert!(validate_redirect_uri("").is_err());
        assert!(validate_redirect_uri("not-a-uri").is_err());
    }

    #[test]
    fn test_secret_rotation() {
        let (mut client, original_secret) = OAuthClient::builder()
            .name("Test")
            .client_type(ClientType::Confidential)
            .redirect_uri("https://example.com/cb")
            .build()
            .unwrap();

        let original_secret = original_secret.unwrap();
        assert!(client.verify_secret(&original_secret));

        // 轮换密钥
        let new_secret = client.rotate_secret().unwrap().unwrap();
        assert!(!client.verify_secret(&original_secret));
        assert!(client.verify_secret(&new_secret));
    }

    #[test]
    fn test_grant_type_parsing() {
        assert_eq!(
            "authorization_code".parse::<GrantType>().unwrap(),
            GrantType::AuthorizationCode
        );
        assert_eq!(
            "client_credentials".parse::<GrantType>().unwrap(),
            GrantType::ClientCredentials
        );
        assert!("invalid".parse::<GrantType>().is_err());
    }

    #[test]
    fn test_in_memory_store() {
        let mut store = InMemoryClientStore::new();

        let (client, _) = OAuthClient::builder()
            .name("Test")
            .redirect_uri("https://example.com/cb")
            .build()
            .unwrap();

        let client_id = client.client_id.clone();

        store.save(&client).unwrap();
        assert!(store.find_by_id(&client_id).unwrap().is_some());
        assert_eq!(store.list().unwrap().len(), 1);

        store.delete(&client_id).unwrap();
        assert!(store.find_by_id(&client_id).unwrap().is_none());
    }
}
