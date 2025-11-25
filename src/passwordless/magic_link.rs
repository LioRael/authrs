//! Magic Link（魔法链接）实现
//!
//! 提供基于一次性 Token 的无密码登录功能。
//!
//! ## 工作流程
//!
//! 1. 用户输入邮箱请求登录
//! 2. 系统生成安全的一次性 Token
//! 3. 应用层将 Token 嵌入 URL 发送到用户邮箱
//! 4. 用户点击链接，系统验证 Token
//! 5. 验证成功后，Token 失效，用户登录成功
//!
//! ## 示例
//!
//! ```rust
//! use authrs::passwordless::{MagicLinkManager, MagicLinkConfig};
//!
//! // 使用默认配置
//! let manager = MagicLinkManager::new(MagicLinkConfig::default());
//!
//! // 生成 magic link token
//! let data = manager.generate("user@example.com").unwrap();
//! println!("Token: {}", data.token);
//! println!("过期时间: {:?}", data.expires_at);
//!
//! // 验证 token
//! match manager.verify(&data.token) {
//!     Ok(email) => println!("用户 {} 验证成功", email),
//!     Err(e) => println!("验证失败: {}", e),
//! }
//! ```
//!
//! ## 自定义配置
//!
//! ```rust
//! use authrs::passwordless::MagicLinkConfig;
//! use std::time::Duration;
//!
//! let config = MagicLinkConfig::default()
//!     .with_token_length(48)           // Token 长度（字节）
//!     .with_ttl(Duration::from_secs(600))  // 10 分钟过期
//!     .with_max_active_per_user(3);    // 每用户最多 3 个活跃 token
//! ```

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::error::{Error, Result};
use crate::random::generate_random_base64_url;

// ============================================================================
// 配置
// ============================================================================

/// Magic Link 配置
#[derive(Debug, Clone)]
pub struct MagicLinkConfig {
    /// Token 长度（字节数，Base64 编码后会更长）
    pub token_length: usize,

    /// Token 有效期
    pub ttl: std::time::Duration,

    /// 每个用户最多允许的活跃 token 数量
    /// 超过此数量时，最旧的 token 会被删除
    pub max_active_per_user: usize,

    /// 是否在验证成功后自动删除 token
    pub consume_on_verify: bool,
}

impl Default for MagicLinkConfig {
    fn default() -> Self {
        Self {
            token_length: 32,                             // 256 bits
            ttl: std::time::Duration::from_secs(15 * 60), // 15 分钟
            max_active_per_user: 3,
            consume_on_verify: true,
        }
    }
}

impl MagicLinkConfig {
    /// 创建新配置
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置 token 长度
    pub fn with_token_length(mut self, length: usize) -> Self {
        self.token_length = length;
        self
    }

    /// 设置有效期
    pub fn with_ttl(mut self, ttl: std::time::Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// 设置每用户最大活跃 token 数
    pub fn with_max_active_per_user(mut self, max: usize) -> Self {
        self.max_active_per_user = max;
        self
    }

    /// 设置是否在验证后消费 token
    pub fn with_consume_on_verify(mut self, consume: bool) -> Self {
        self.consume_on_verify = consume;
        self
    }

    /// 高安全性配置
    ///
    /// - 48 字节 token（384 bits）
    /// - 5 分钟过期
    /// - 每用户最多 1 个活跃 token
    pub fn high_security() -> Self {
        Self {
            token_length: 48,
            ttl: std::time::Duration::from_secs(5 * 60),
            max_active_per_user: 1,
            consume_on_verify: true,
        }
    }

    /// 宽松配置（适用于开发/测试）
    ///
    /// - 24 字节 token
    /// - 1 小时过期
    /// - 每用户最多 10 个活跃 token
    pub fn relaxed() -> Self {
        Self {
            token_length: 24,
            ttl: std::time::Duration::from_secs(60 * 60),
            max_active_per_user: 10,
            consume_on_verify: true,
        }
    }
}

// ============================================================================
// 数据结构
// ============================================================================

/// Magic Link Token 数据
#[derive(Debug, Clone)]
pub struct MagicLinkData {
    /// 生成的 token（用于构建 URL）
    pub token: String,

    /// 关联的用户标识（通常是邮箱）
    pub identifier: String,

    /// 创建时间
    pub created_at: DateTime<Utc>,

    /// 过期时间
    pub expires_at: DateTime<Utc>,
}

impl MagicLinkData {
    /// 检查 token 是否已过期
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// 获取剩余有效时间（秒）
    pub fn remaining_seconds(&self) -> i64 {
        let remaining = self.expires_at - Utc::now();
        remaining.num_seconds().max(0)
    }
}

/// 内部存储的 token 记录
#[derive(Debug, Clone)]
struct StoredToken {
    /// 用户标识
    identifier: String,

    /// 过期时间
    expires_at: DateTime<Utc>,

    /// 创建时间
    created_at: DateTime<Utc>,
}

// ============================================================================
// 存储接口
// ============================================================================

/// Magic Link 存储接口
///
/// 实现此 trait 以提供自定义的存储后端（如 Redis、数据库等）
#[async_trait]
pub trait MagicLinkStore: Send + Sync {
    /// 保存 token
    async fn save(&self, token: &str, identifier: &str, expires_at: DateTime<Utc>) -> Result<()>;

    /// 获取 token 对应的用户标识
    async fn get(&self, token: &str) -> Result<Option<(String, DateTime<Utc>)>>;

    /// 删除 token
    async fn delete(&self, token: &str) -> Result<()>;

    /// 获取用户的所有活跃 token
    async fn get_user_tokens(&self, identifier: &str) -> Result<Vec<String>>;

    /// 删除用户最旧的 token
    async fn delete_oldest_user_token(&self, identifier: &str) -> Result<()>;

    /// 清理过期的 token
    async fn cleanup_expired(&self) -> Result<usize>;
}

// ============================================================================
// 内存存储实现
// ============================================================================

/// 内存存储实现
///
/// 适用于单实例部署或测试环境。
/// 生产环境建议使用 Redis 等分布式存储。
#[derive(Debug, Clone, Default)]
pub struct InMemoryMagicLinkStore {
    /// token -> 记录
    tokens: Arc<RwLock<HashMap<String, StoredToken>>>,
}

impl InMemoryMagicLinkStore {
    /// 创建新的内存存储
    pub fn new() -> Self {
        Self::default()
    }

    /// 获取当前存储的 token 数量
    pub fn len(&self) -> usize {
        self.tokens.read().unwrap().len()
    }

    /// 检查存储是否为空
    pub fn is_empty(&self) -> bool {
        self.tokens.read().unwrap().is_empty()
    }
}

#[async_trait]
impl MagicLinkStore for InMemoryMagicLinkStore {
    async fn save(&self, token: &str, identifier: &str, expires_at: DateTime<Utc>) -> Result<()> {
        let mut tokens = self.tokens.write().unwrap();
        tokens.insert(
            token.to_string(),
            StoredToken {
                identifier: identifier.to_string(),
                expires_at,
                created_at: Utc::now(),
            },
        );
        Ok(())
    }

    async fn get(&self, token: &str) -> Result<Option<(String, DateTime<Utc>)>> {
        let tokens = self.tokens.read().unwrap();
        Ok(tokens
            .get(token)
            .map(|record| (record.identifier.clone(), record.expires_at)))
    }

    async fn delete(&self, token: &str) -> Result<()> {
        let mut tokens = self.tokens.write().unwrap();
        tokens.remove(token);
        Ok(())
    }

    async fn get_user_tokens(&self, identifier: &str) -> Result<Vec<String>> {
        let tokens = self.tokens.read().unwrap();
        let user_tokens: Vec<String> = tokens
            .iter()
            .filter(|(_, record)| record.identifier == identifier)
            .map(|(token, _)| token.clone())
            .collect();
        Ok(user_tokens)
    }

    async fn delete_oldest_user_token(&self, identifier: &str) -> Result<()> {
        let mut tokens = self.tokens.write().unwrap();

        // 找到该用户最旧的 token
        let oldest = tokens
            .iter()
            .filter(|(_, record)| record.identifier == identifier)
            .min_by_key(|(_, record)| record.created_at)
            .map(|(token, _)| token.clone());

        if let Some(token) = oldest {
            tokens.remove(&token);
        }

        Ok(())
    }

    async fn cleanup_expired(&self) -> Result<usize> {
        let mut tokens = self.tokens.write().unwrap();
        let now = Utc::now();
        let before = tokens.len();
        tokens.retain(|_, record| record.expires_at > now);
        Ok(before - tokens.len())
    }
}

// ============================================================================
// Magic Link 管理器
// ============================================================================

/// Magic Link 管理器
///
/// 负责生成和验证 magic link token。
///
/// ## 示例
///
/// ```rust
/// use authrs::passwordless::{MagicLinkManager, MagicLinkConfig};
///
/// let manager = MagicLinkManager::new(MagicLinkConfig::default());
///
/// // 生成 token
/// let data = manager.generate("user@example.com").unwrap();
///
/// // 验证 token
/// let email = manager.verify(&data.token).unwrap();
/// assert_eq!(email, "user@example.com");
/// ```
pub struct MagicLinkManager<S: MagicLinkStore = InMemoryMagicLinkStore> {
    store: S,
    config: MagicLinkConfig,
}

impl MagicLinkManager<InMemoryMagicLinkStore> {
    /// 使用默认内存存储创建管理器
    pub fn new(config: MagicLinkConfig) -> Self {
        Self {
            store: InMemoryMagicLinkStore::new(),
            config,
        }
    }

    /// 使用默认配置创建管理器
    pub fn with_default_config() -> Self {
        Self::new(MagicLinkConfig::default())
    }
}

impl<S: MagicLinkStore> MagicLinkManager<S> {
    /// 使用自定义存储创建管理器
    pub fn with_store(store: S, config: MagicLinkConfig) -> Self {
        Self { store, config }
    }

    /// 为用户生成 magic link token
    ///
    /// # Arguments
    ///
    /// * `identifier` - 用户标识（通常是邮箱地址）
    ///
    /// # Returns
    ///
    /// 返回包含 token 和元数据的 `MagicLinkData`
    ///
    /// # Example
    ///
    /// ```rust
    /// use authrs::passwordless::{MagicLinkManager, MagicLinkConfig};
    ///
    /// let manager = MagicLinkManager::new(MagicLinkConfig::default());
    /// let data = manager.generate("user@example.com").unwrap();
    ///
    /// // 构建完整 URL
    /// let url = format!("https://example.com/login?token={}", data.token);
    /// ```
    pub async fn generate(&self, identifier: impl Into<String>) -> Result<MagicLinkData> {
        let identifier = identifier.into();

        // 检查并限制用户的活跃 token 数量
        let user_tokens = self.store.get_user_tokens(&identifier).await?;
        if user_tokens.len() >= self.config.max_active_per_user {
            // 删除最旧的 token
            self.store.delete_oldest_user_token(&identifier).await?;
        }

        // 生成安全的随机 token
        let token = generate_random_base64_url(self.config.token_length)?;

        // 计算过期时间
        let created_at = Utc::now();
        let expires_at = created_at + Duration::seconds(self.config.ttl.as_secs() as i64);

        // 保存 token
        self.store.save(&token, &identifier, expires_at).await?;

        Ok(MagicLinkData {
            token,
            identifier,
            created_at,
            expires_at,
        })
    }

    /// 验证 magic link token
    ///
    /// 验证成功后，根据配置可能会自动消费（删除）token。
    ///
    /// # Arguments
    ///
    /// * `token` - 要验证的 token
    ///
    /// # Returns
    ///
    /// 成功返回关联的用户标识，失败返回错误
    ///
    /// # Errors
    ///
    /// - Token 不存在
    /// - Token 已过期
    ///
    /// # Example
    ///
    /// ```rust
    /// use authrs::passwordless::{MagicLinkManager, MagicLinkConfig};
    ///
    /// let manager = MagicLinkManager::new(MagicLinkConfig::default());
    /// let data = manager.generate("user@example.com").unwrap();
    ///
    /// // 验证 token
    /// let email = manager.verify(&data.token).unwrap();
    /// assert_eq!(email, "user@example.com");
    ///
    /// // token 已被消费，再次验证会失败
    /// assert!(manager.verify(&data.token).is_err());
    /// ```
    pub async fn verify(&self, token: &str) -> Result<String> {
        // 获取 token 记录
        let (identifier, expires_at) = self
            .store
            .get(token)
            .await?
            .ok_or_else(|| Error::validation("invalid or expired magic link token"))?;

        // 检查是否过期
        if Utc::now() > expires_at {
            // 清理过期的 token
            self.store.delete(token).await?;
            return Err(Error::validation("magic link token has expired"));
        }

        // 根据配置决定是否消费 token
        if self.config.consume_on_verify {
            self.store.delete(token).await?;
        }

        Ok(identifier)
    }

    /// 撤销 token
    ///
    /// 手动使 token 失效。
    pub async fn revoke(&self, token: &str) -> Result<()> {
        self.store.delete(token).await
    }

    /// 撤销用户的所有 token
    ///
    /// 当用户请求登出所有设备或更改密码时使用。
    pub async fn revoke_all_for_user(&self, identifier: &str) -> Result<usize> {
        let tokens = self.store.get_user_tokens(identifier).await?;
        let count = tokens.len();
        for token in tokens {
            self.store.delete(&token).await?;
        }
        Ok(count)
    }

    /// 清理过期的 token
    ///
    /// 建议定期调用此方法以清理存储。
    pub async fn cleanup(&self) -> Result<usize> {
        self.store.cleanup_expired().await
    }

    /// 获取配置
    pub fn config(&self) -> &MagicLinkConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration as StdDuration;

    #[tokio::test]
    async fn test_generate_and_verify() {
        let manager = MagicLinkManager::new(MagicLinkConfig::default());

        let data = manager.generate("test@example.com").await.unwrap();
        assert!(!data.token.is_empty());
        assert_eq!(data.identifier, "test@example.com");
        assert!(!data.is_expired());

        // 验证成功
        let email = manager.verify(&data.token).await.unwrap();
        assert_eq!(email, "test@example.com");
    }

    #[tokio::test]
    async fn test_token_consumed_after_verify() {
        let manager = MagicLinkManager::new(MagicLinkConfig::default());

        let data = manager.generate("test@example.com").await.unwrap();

        // 第一次验证成功
        assert!(manager.verify(&data.token).await.is_ok());

        // 第二次验证失败（已消费）
        assert!(manager.verify(&data.token).await.is_err());
    }

    #[tokio::test]
    async fn test_token_not_consumed_when_disabled() {
        let config = MagicLinkConfig::default().with_consume_on_verify(false);
        let manager = MagicLinkManager::new(config);

        let data = manager.generate("test@example.com").await.unwrap();

        // 多次验证都成功
        assert!(manager.verify(&data.token).await.is_ok());
        assert!(manager.verify(&data.token).await.is_ok());
        assert!(manager.verify(&data.token).await.is_ok());
    }

    #[tokio::test]
    async fn test_token_expiration() {
        let config = MagicLinkConfig::default().with_ttl(StdDuration::from_secs(1));
        let manager = MagicLinkManager::new(config);

        let data = manager.generate("test@example.com").await.unwrap();

        // 立即验证成功（在过期前）
        assert!(!data.is_expired());

        // 等待过期
        sleep(StdDuration::from_millis(1100));

        // 验证失败（已过期）
        assert!(manager.verify(&data.token).await.is_err());
    }

    #[tokio::test]
    async fn test_max_active_tokens_per_user() {
        let config = MagicLinkConfig::default().with_max_active_per_user(2);
        let manager = MagicLinkManager::new(config);

        let token1 = manager.generate("user@example.com").await.unwrap();
        let token2 = manager.generate("user@example.com").await.unwrap();
        let token3 = manager.generate("user@example.com").await.unwrap();

        // token1 应该被删除了
        assert!(manager.verify(&token1.token).await.is_err());

        // token2 和 token3 仍然有效
        assert!(manager.verify(&token2.token).await.is_ok());
        assert!(manager.verify(&token3.token).await.is_ok());
    }

    #[tokio::test]
    async fn test_revoke_token() {
        let manager = MagicLinkManager::new(MagicLinkConfig::default());

        let data = manager.generate("test@example.com").await.unwrap();

        // 撤销 token
        manager.revoke(&data.token).await.unwrap();

        // 验证失败
        assert!(manager.verify(&data.token).await.is_err());
    }

    #[tokio::test]
    async fn test_revoke_all_for_user() {
        let config = MagicLinkConfig::default()
            .with_max_active_per_user(10)
            .with_consume_on_verify(false);
        let manager = MagicLinkManager::new(config);

        // 生成多个 token
        let t1 = manager.generate("user@example.com").await.unwrap();
        let t2 = manager.generate("user@example.com").await.unwrap();
        let t3 = manager.generate("other@example.com").await.unwrap();

        // 撤销 user@example.com 的所有 token
        let count = manager
            .revoke_all_for_user("user@example.com")
            .await
            .unwrap();
        assert_eq!(count, 2);

        // user@example.com 的 token 都失效了
        assert!(manager.verify(&t1.token).await.is_err());
        assert!(manager.verify(&t2.token).await.is_err());

        // other@example.com 的 token 仍然有效
        assert!(manager.verify(&t3.token).await.is_ok());
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let config = MagicLinkConfig::default()
            .with_ttl(StdDuration::from_secs(1))
            .with_max_active_per_user(10);
        let manager = MagicLinkManager::new(config);

        // 生成一些 token
        manager.generate("user1@example.com").await.unwrap();
        manager.generate("user2@example.com").await.unwrap();
        manager.generate("user3@example.com").await.unwrap();

        // 等待过期
        sleep(StdDuration::from_millis(1100));

        // 清理
        let cleaned = manager.cleanup().await.unwrap();
        assert_eq!(cleaned, 3);
    }

    #[tokio::test]
    async fn test_different_users_independent() {
        let manager = MagicLinkManager::new(MagicLinkConfig::default());

        let data1 = manager.generate("user1@example.com").await.unwrap();
        let data2 = manager.generate("user2@example.com").await.unwrap();

        // 验证 user1 的 token
        let email1 = manager.verify(&data1.token).await.unwrap();
        assert_eq!(email1, "user1@example.com");

        // user2 的 token 仍然有效
        let email2 = manager.verify(&data2.token).await.unwrap();
        assert_eq!(email2, "user2@example.com");
    }

    #[tokio::test]
    async fn test_remaining_seconds() {
        let config = MagicLinkConfig::default().with_ttl(StdDuration::from_secs(300));
        let manager = MagicLinkManager::new(config);

        let data = manager.generate("test@example.com").await.unwrap();

        // 剩余时间应该接近 300 秒
        let remaining = data.remaining_seconds();
        assert!(remaining > 295 && remaining <= 300);
    }

    #[test]
    fn test_high_security_config() {
        let config = MagicLinkConfig::high_security();
        assert_eq!(config.token_length, 48);
        assert_eq!(config.ttl, StdDuration::from_secs(5 * 60));
        assert_eq!(config.max_active_per_user, 1);
    }

    #[test]
    fn test_relaxed_config() {
        let config = MagicLinkConfig::relaxed();
        assert_eq!(config.token_length, 24);
        assert_eq!(config.ttl, StdDuration::from_secs(60 * 60));
        assert_eq!(config.max_active_per_user, 10);
    }

    #[tokio::test]
    async fn test_invalid_token() {
        let manager = MagicLinkManager::new(MagicLinkConfig::default());

        // 验证不存在的 token
        assert!(manager.verify("invalid-token").await.is_err());
    }

    #[tokio::test]
    async fn test_store_len_and_is_empty() {
        let store = InMemoryMagicLinkStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);

        store
            .save(
                "token1",
                "user@example.com",
                Utc::now() + Duration::hours(1),
            )
            .await
            .unwrap();
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
    }
}
