//! Refresh Token 实现模块
//!
//! 提供 Refresh Token 的生成、验证、存储和轮换功能。
//!
//! ## 特性
//!
//! - 安全的 Refresh Token 生成
//! - Token 轮换（每次使用后生成新 Token）
//! - Token 家族追踪（检测 Token 重用攻击）
//! - 可配置的过期策略
//!
//! ## 示例
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
//! println!("Token: {}", token.token);
//!
//! // 使用 Refresh Token（会自动轮换）
//! let result = manager.use_token(&token.token).unwrap();
//! if let Some(new_token) = result.new_token {
//!     println!("New Token: {}", new_token.token);
//! }
//! ```

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::error::{Error, Result, StorageError, TokenError};
use crate::random::{generate_random_base64_url, generate_random_hex};

/// Refresh Token 数据结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshToken {
    /// Token 值（用于传输和验证）
    pub token: String,

    /// Token ID（用于存储和查找）
    pub token_id: String,

    /// 关联的用户 ID
    pub user_id: String,

    /// Token 家族 ID（用于检测重用攻击）
    pub family_id: String,

    /// 创建时间
    pub created_at: DateTime<Utc>,

    /// 过期时间
    pub expires_at: DateTime<Utc>,

    /// 是否已被使用（用于检测重用）
    pub used: bool,

    /// 使用时间
    pub used_at: Option<DateTime<Utc>>,

    /// 替代此 Token 的新 Token ID
    pub replaced_by: Option<String>,

    /// 设备信息
    pub device_info: Option<String>,

    /// IP 地址
    pub ip_address: Option<String>,

    /// 自定义数据
    pub metadata: HashMap<String, serde_json::Value>,
}

impl RefreshToken {
    /// 创建新的 Refresh Token
    fn new(user_id: impl Into<String>, family_id: String, expires_in: Duration) -> Result<Self> {
        let now = Utc::now();
        let token = generate_random_base64_url(48)?;
        let token_id = generate_random_hex(16)?;

        Ok(Self {
            token,
            token_id,
            user_id: user_id.into(),
            family_id,
            created_at: now,
            expires_at: now + expires_in,
            used: false,
            used_at: None,
            replaced_by: None,
            device_info: None,
            ip_address: None,
            metadata: HashMap::new(),
        })
    }

    /// 检查 Token 是否已过期
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// 检查 Token 是否有效（未过期且未被使用）
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.used
    }

    /// 获取剩余有效时间（秒）
    pub fn time_to_live(&self) -> i64 {
        let remaining = self.expires_at - Utc::now();
        remaining.num_seconds().max(0)
    }

    /// 标记 Token 为已使用
    fn mark_as_used(&mut self, replaced_by: Option<String>) {
        self.used = true;
        self.used_at = Some(Utc::now());
        self.replaced_by = replaced_by;
    }
}

/// Refresh Token 配置
#[derive(Debug, Clone)]
pub struct RefreshConfig {
    /// Token 有效期
    pub expiration: Duration,

    /// 是否启用 Token 轮换（每次使用生成新 Token）
    pub rotation_enabled: bool,

    /// 是否启用重用检测（检测到重用时撤销整个 Token 家族）
    pub reuse_detection: bool,

    /// Token 家族的最大 Token 数量（0 表示不限制）
    pub max_tokens_per_family: usize,

    /// 单用户最大 Token 家族数（0 表示不限制）
    pub max_families_per_user: usize,

    /// 宽限期（Token 使用后仍可在此期间内再次使用）
    pub grace_period: Duration,
}

impl Default for RefreshConfig {
    fn default() -> Self {
        Self {
            expiration: Duration::days(30),
            rotation_enabled: true,
            reuse_detection: true,
            max_tokens_per_family: 100,
            max_families_per_user: 5,
            grace_period: Duration::seconds(0),
        }
    }
}

impl RefreshConfig {
    /// 创建新的配置
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置有效期
    pub fn with_expiration(mut self, duration: Duration) -> Self {
        self.expiration = duration;
        self
    }

    /// 设置是否启用 Token 轮换
    pub fn with_rotation(mut self, enabled: bool) -> Self {
        self.rotation_enabled = enabled;
        self
    }

    /// 设置是否启用重用检测
    pub fn with_reuse_detection(mut self, enabled: bool) -> Self {
        self.reuse_detection = enabled;
        self
    }

    /// 设置单用户最大 Token 家族数
    pub fn with_max_families_per_user(mut self, max: usize) -> Self {
        self.max_families_per_user = max;
        self
    }

    /// 设置宽限期
    pub fn with_grace_period(mut self, duration: Duration) -> Self {
        self.grace_period = duration;
        self
    }

    /// 创建高安全性配置
    pub fn high_security() -> Self {
        Self {
            expiration: Duration::days(7),
            rotation_enabled: true,
            reuse_detection: true,
            max_tokens_per_family: 50,
            max_families_per_user: 3,
            grace_period: Duration::seconds(0),
        }
    }

    /// 创建宽松配置（适用于移动应用）
    pub fn relaxed() -> Self {
        Self {
            expiration: Duration::days(90),
            rotation_enabled: true,
            reuse_detection: true,
            max_tokens_per_family: 200,
            max_families_per_user: 10,
            grace_period: Duration::seconds(60),
        }
    }
}

/// Refresh Token 存储 trait
pub trait RefreshTokenStore: Send + Sync {
    /// 保存 Token
    fn save(&self, token: &RefreshToken) -> Result<()>;

    /// 通过 Token 值获取 Token
    fn get_by_token(&self, token: &str) -> Result<Option<RefreshToken>>;

    /// 通过 Token ID 获取 Token
    fn get_by_id(&self, token_id: &str) -> Result<Option<RefreshToken>>;

    /// 更新 Token
    fn update(&self, token: &RefreshToken) -> Result<()>;

    /// 删除 Token
    fn delete(&self, token_id: &str) -> Result<()>;

    /// 获取用户的所有 Token
    fn get_by_user(&self, user_id: &str) -> Result<Vec<RefreshToken>>;

    /// 获取 Token 家族的所有 Token
    fn get_by_family(&self, family_id: &str) -> Result<Vec<RefreshToken>>;

    /// 删除 Token 家族的所有 Token
    fn delete_family(&self, family_id: &str) -> Result<usize>;

    /// 删除用户的所有 Token
    fn delete_by_user(&self, user_id: &str) -> Result<usize>;

    /// 清理过期的 Token
    fn cleanup_expired(&self) -> Result<usize>;

    /// 获取 Token 总数
    fn count(&self) -> Result<usize>;
}

/// 内存 Refresh Token 存储
#[derive(Debug, Default)]
pub struct InMemoryRefreshTokenStore {
    tokens: RwLock<HashMap<String, RefreshToken>>,
    token_index: RwLock<HashMap<String, String>>, // token_value -> token_id
}

impl InMemoryRefreshTokenStore {
    /// 创建新的内存存储
    pub fn new() -> Self {
        Self::default()
    }
}

impl RefreshTokenStore for InMemoryRefreshTokenStore {
    fn save(&self, token: &RefreshToken) -> Result<()> {
        let mut tokens = self
            .tokens
            .write()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;
        let mut index = self
            .token_index
            .write()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;

        tokens.insert(token.token_id.clone(), token.clone());
        index.insert(token.token.clone(), token.token_id.clone());

        Ok(())
    }

    fn get_by_token(&self, token: &str) -> Result<Option<RefreshToken>> {
        let index = self
            .token_index
            .read()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;

        if let Some(token_id) = index.get(token) {
            let tokens = self.tokens.read().map_err(|_| {
                Error::Storage(StorageError::OperationFailed("lock poisoned".into()))
            })?;
            Ok(tokens.get(token_id).cloned())
        } else {
            Ok(None)
        }
    }

    fn get_by_id(&self, token_id: &str) -> Result<Option<RefreshToken>> {
        let tokens = self
            .tokens
            .read()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;
        Ok(tokens.get(token_id).cloned())
    }

    fn update(&self, token: &RefreshToken) -> Result<()> {
        let mut tokens = self
            .tokens
            .write()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;

        if tokens.contains_key(&token.token_id) {
            tokens.insert(token.token_id.clone(), token.clone());
            Ok(())
        } else {
            Err(Error::Storage(StorageError::NotFound(format!(
                "token {}",
                token.token_id
            ))))
        }
    }

    fn delete(&self, token_id: &str) -> Result<()> {
        let mut tokens = self
            .tokens
            .write()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;
        let mut index = self
            .token_index
            .write()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;

        if let Some(token) = tokens.remove(token_id) {
            index.remove(&token.token);
        }

        Ok(())
    }

    fn get_by_user(&self, user_id: &str) -> Result<Vec<RefreshToken>> {
        let tokens = self
            .tokens
            .read()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;

        Ok(tokens
            .values()
            .filter(|t| t.user_id == user_id)
            .cloned()
            .collect())
    }

    fn get_by_family(&self, family_id: &str) -> Result<Vec<RefreshToken>> {
        let tokens = self
            .tokens
            .read()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;

        Ok(tokens
            .values()
            .filter(|t| t.family_id == family_id)
            .cloned()
            .collect())
    }

    fn delete_family(&self, family_id: &str) -> Result<usize> {
        let mut tokens = self
            .tokens
            .write()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;
        let mut index = self
            .token_index
            .write()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;

        let to_remove: Vec<_> = tokens
            .iter()
            .filter(|(_, t)| t.family_id == family_id)
            .map(|(id, t)| (id.clone(), t.token.clone()))
            .collect();

        let count = to_remove.len();
        for (id, token) in to_remove {
            tokens.remove(&id);
            index.remove(&token);
        }

        Ok(count)
    }

    fn delete_by_user(&self, user_id: &str) -> Result<usize> {
        let mut tokens = self
            .tokens
            .write()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;
        let mut index = self
            .token_index
            .write()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;

        let to_remove: Vec<_> = tokens
            .iter()
            .filter(|(_, t)| t.user_id == user_id)
            .map(|(id, t)| (id.clone(), t.token.clone()))
            .collect();

        let count = to_remove.len();
        for (id, token) in to_remove {
            tokens.remove(&id);
            index.remove(&token);
        }

        Ok(count)
    }

    fn cleanup_expired(&self) -> Result<usize> {
        let mut tokens = self
            .tokens
            .write()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;
        let mut index = self
            .token_index
            .write()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;

        let to_remove: Vec<_> = tokens
            .iter()
            .filter(|(_, t)| t.is_expired())
            .map(|(id, t)| (id.clone(), t.token.clone()))
            .collect();

        let count = to_remove.len();
        for (id, token) in to_remove {
            tokens.remove(&id);
            index.remove(&token);
        }

        Ok(count)
    }

    fn count(&self) -> Result<usize> {
        let tokens = self
            .tokens
            .read()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;
        Ok(tokens.len())
    }
}

/// Token 使用结果
#[derive(Debug, Clone)]
pub struct TokenUseResult {
    /// 新的 Refresh Token（如果启用了轮换）
    pub new_token: Option<RefreshToken>,

    /// 关联的用户 ID
    pub user_id: String,

    /// Token 家族 ID
    pub family_id: String,

    /// 原 Token 是否在宽限期内被重用
    pub was_in_grace_period: bool,
}

/// Refresh Token 管理器
pub struct RefreshTokenManager {
    store: Arc<dyn RefreshTokenStore>,
    config: RefreshConfig,
}

impl RefreshTokenManager {
    /// 使用默认内存存储创建管理器
    pub fn new(config: RefreshConfig) -> Self {
        Self {
            store: Arc::new(InMemoryRefreshTokenStore::new()),
            config,
        }
    }

    /// 使用自定义存储创建管理器
    pub fn with_store(config: RefreshConfig, store: Arc<dyn RefreshTokenStore>) -> Self {
        Self { store, config }
    }

    /// 生成新的 Refresh Token
    ///
    /// 这会创建一个新的 Token 家族
    pub fn generate(&self, user_id: impl Into<String>) -> Result<RefreshToken> {
        let user_id = user_id.into();

        // 检查并清理超出限制的 Token 家族
        if self.config.max_families_per_user > 0 {
            self.enforce_max_families(&user_id)?;
        }

        // 生成新的 Token 家族 ID
        let family_id = generate_random_hex(16)?;

        let token = RefreshToken::new(&user_id, family_id, self.config.expiration)?;
        self.store.save(&token)?;

        Ok(token)
    }

    /// 生成带有元信息的 Refresh Token
    pub fn generate_with_metadata(
        &self,
        user_id: impl Into<String>,
        device_info: Option<String>,
        ip_address: Option<String>,
    ) -> Result<RefreshToken> {
        let user_id = user_id.into();

        if self.config.max_families_per_user > 0 {
            self.enforce_max_families(&user_id)?;
        }

        let family_id = generate_random_hex(16)?;
        let mut token = RefreshToken::new(&user_id, family_id, self.config.expiration)?;
        token.device_info = device_info;
        token.ip_address = ip_address;

        self.store.save(&token)?;

        Ok(token)
    }

    /// 使用 Refresh Token
    ///
    /// 如果启用了轮换，会返回新的 Token 并使旧 Token 失效
    pub fn use_token(&self, token_value: &str) -> Result<TokenUseResult> {
        let token = self
            .store
            .get_by_token(token_value)?
            .ok_or_else(|| Error::Token(TokenError::InvalidFormat("token not found".into())))?;

        // 检查是否过期
        if token.is_expired() {
            self.store.delete(&token.token_id)?;
            return Err(Error::Token(TokenError::Expired));
        }

        // 检查是否已被使用（重用检测）
        if token.used {
            if self.config.reuse_detection {
                // 检查是否在宽限期内
                if let Some(used_at) = token.used_at {
                    let grace_end = used_at + self.config.grace_period;
                    if Utc::now() <= grace_end {
                        // 在宽限期内，允许使用
                        return Ok(TokenUseResult {
                            new_token: None,
                            user_id: token.user_id.clone(),
                            family_id: token.family_id.clone(),
                            was_in_grace_period: true,
                        });
                    }
                }

                // Token 被重用！撤销整个 Token 家族
                self.store.delete_family(&token.family_id)?;
                return Err(Error::Token(TokenError::InvalidClaim(
                    "token reuse detected, all tokens in family have been revoked".into(),
                )));
            } else {
                return Err(Error::Token(TokenError::InvalidClaim(
                    "token already used".into(),
                )));
            }
        }

        let user_id = token.user_id.clone();
        let family_id = token.family_id.clone();
        let device_info = token.device_info.clone();
        let ip_address = token.ip_address.clone();

        // 如果启用了轮换，生成新 Token
        let new_token = if self.config.rotation_enabled {
            let mut new_token =
                RefreshToken::new(&user_id, family_id.clone(), self.config.expiration)?;
            new_token.device_info = device_info;
            new_token.ip_address = ip_address;

            // 标记旧 Token 为已使用
            let mut old_token = token;
            old_token.mark_as_used(Some(new_token.token_id.clone()));
            self.store.update(&old_token)?;

            // 保存新 Token
            self.store.save(&new_token)?;

            // 清理 Token 家族中的过多 Token
            if self.config.max_tokens_per_family > 0 {
                self.enforce_max_tokens_per_family(&family_id)?;
            }

            Some(new_token)
        } else {
            // 不轮换，只标记为已使用
            let mut old_token = token;
            old_token.mark_as_used(None);
            self.store.update(&old_token)?;
            None
        };

        Ok(TokenUseResult {
            new_token,
            user_id,
            family_id,
            was_in_grace_period: false,
        })
    }

    /// 验证 Token（不使用，仅检查有效性）
    pub fn validate(&self, token_value: &str) -> Result<RefreshToken> {
        let token = self
            .store
            .get_by_token(token_value)?
            .ok_or_else(|| Error::Token(TokenError::InvalidFormat("token not found".into())))?;

        if token.is_expired() {
            return Err(Error::Token(TokenError::Expired));
        }

        if token.used && self.config.grace_period.num_seconds() == 0 {
            return Err(Error::Token(TokenError::InvalidClaim(
                "token already used".into(),
            )));
        }

        Ok(token)
    }

    /// 撤销特定 Token
    pub fn revoke(&self, token_value: &str) -> Result<()> {
        let token = self.store.get_by_token(token_value)?;
        if let Some(t) = token {
            self.store.delete(&t.token_id)?;
        }
        Ok(())
    }

    /// 撤销 Token 家族
    pub fn revoke_family(&self, family_id: &str) -> Result<usize> {
        self.store.delete_family(family_id)
    }

    /// 撤销用户的所有 Token
    pub fn revoke_all_for_user(&self, user_id: &str) -> Result<usize> {
        self.store.delete_by_user(user_id)
    }

    /// 获取用户的所有有效 Token
    pub fn get_user_tokens(&self, user_id: &str) -> Result<Vec<RefreshToken>> {
        let tokens = self.store.get_by_user(user_id)?;
        Ok(tokens.into_iter().filter(|t| t.is_valid()).collect())
    }

    /// 获取 Token 家族的所有 Token
    pub fn get_family_tokens(&self, family_id: &str) -> Result<Vec<RefreshToken>> {
        self.store.get_by_family(family_id)
    }

    /// 清理过期的 Token
    pub fn cleanup(&self) -> Result<usize> {
        self.store.cleanup_expired()
    }

    /// 获取 Token 总数
    pub fn count(&self) -> Result<usize> {
        self.store.count()
    }

    /// 强制执行最大 Token 家族数限制
    fn enforce_max_families(&self, user_id: &str) -> Result<()> {
        let tokens = self.store.get_by_user(user_id)?;

        // 统计活跃的 Token 家族
        let mut families: HashMap<String, DateTime<Utc>> = HashMap::new();
        for token in tokens {
            if !token.is_expired() && !token.used {
                families
                    .entry(token.family_id.clone())
                    .and_modify(|t| {
                        if token.created_at > *t {
                            *t = token.created_at;
                        }
                    })
                    .or_insert(token.created_at);
            }
        }

        // 如果超出限制，删除最旧的家族
        if families.len() >= self.config.max_families_per_user {
            let mut family_list: Vec<_> = families.into_iter().collect();
            family_list.sort_by(|a, b| a.1.cmp(&b.1));

            // 删除最旧的家族
            if let Some((oldest_family_id, _)) = family_list.first() {
                self.store.delete_family(oldest_family_id)?;
            }
        }

        Ok(())
    }

    /// 强制执行 Token 家族内最大 Token 数限制
    fn enforce_max_tokens_per_family(&self, family_id: &str) -> Result<()> {
        let tokens = self.store.get_by_family(family_id)?;

        if tokens.len() > self.config.max_tokens_per_family {
            // 按创建时间排序，删除最旧的已使用 Token
            let mut used_tokens: Vec<_> = tokens.into_iter().filter(|t| t.used).collect();
            used_tokens.sort_by(|a, b| a.created_at.cmp(&b.created_at));

            // 删除超出限制的旧 Token
            let to_delete = used_tokens
                .len()
                .saturating_sub(self.config.max_tokens_per_family / 2);
            for token in used_tokens.into_iter().take(to_delete) {
                self.store.delete(&token.token_id)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_refresh_token_creation() {
        let token = RefreshToken::new("user123", "family1".into(), Duration::days(7)).unwrap();

        assert!(!token.token.is_empty());
        assert!(!token.token_id.is_empty());
        assert_eq!(token.user_id, "user123");
        assert_eq!(token.family_id, "family1");
        assert!(!token.is_expired());
        assert!(!token.used);
    }

    #[test]
    fn test_refresh_token_expiration() {
        let token = RefreshToken::new("user123", "family1".into(), Duration::seconds(-10)).unwrap();
        assert!(token.is_expired());
        assert!(!token.is_valid());
    }

    #[test]
    fn test_refresh_token_mark_as_used() {
        let mut token = RefreshToken::new("user123", "family1".into(), Duration::days(7)).unwrap();

        assert!(!token.used);
        token.mark_as_used(Some("new_token_id".into()));
        assert!(token.used);
        assert!(token.used_at.is_some());
        assert_eq!(token.replaced_by, Some("new_token_id".to_string()));
    }

    #[test]
    fn test_manager_generate() {
        let manager = RefreshTokenManager::new(RefreshConfig::default());
        let token = manager.generate("user123").unwrap();

        assert!(!token.token.is_empty());
        assert_eq!(token.user_id, "user123");
    }

    #[test]
    fn test_manager_use_token_with_rotation() {
        let config = RefreshConfig::default().with_rotation(true);
        let manager = RefreshTokenManager::new(config);

        let token = manager.generate("user123").unwrap();
        let result = manager.use_token(&token.token).unwrap();

        assert!(result.new_token.is_some());
        assert_eq!(result.user_id, "user123");

        // 旧 Token 不应该再可用
        let old_result = manager.use_token(&token.token);
        assert!(old_result.is_err());
    }

    #[test]
    fn test_manager_use_token_without_rotation() {
        let config = RefreshConfig::default()
            .with_rotation(false)
            .with_reuse_detection(false);
        let manager = RefreshTokenManager::new(config);

        let token = manager.generate("user123").unwrap();
        let result = manager.use_token(&token.token).unwrap();

        assert!(result.new_token.is_none());
    }

    #[test]
    fn test_manager_reuse_detection() {
        let config = RefreshConfig::default()
            .with_rotation(true)
            .with_reuse_detection(true);
        let manager = RefreshTokenManager::new(config);

        let token = manager.generate("user123").unwrap();
        let token_value = token.token.clone();
        let family_id = token.family_id.clone();

        // 第一次使用
        let result = manager.use_token(&token_value).unwrap();
        let new_token = result.new_token.unwrap();

        // 尝试重用旧 Token，应该撤销整个家族
        let reuse_result = manager.use_token(&token_value);
        assert!(reuse_result.is_err());

        // 新 Token 也应该被撤销
        let new_result = manager.use_token(&new_token.token);
        assert!(new_result.is_err());

        // 家族中不应该有任何 Token
        let family_tokens = manager.get_family_tokens(&family_id).unwrap();
        assert!(family_tokens.is_empty());
    }

    #[test]
    fn test_manager_revoke() {
        let manager = RefreshTokenManager::new(RefreshConfig::default());
        let token = manager.generate("user123").unwrap();
        let token_value = token.token.clone();

        manager.revoke(&token_value).unwrap();

        let result = manager.use_token(&token_value);
        assert!(result.is_err());
    }

    #[test]
    fn test_manager_revoke_all_for_user() {
        let config = RefreshConfig::default().with_max_families_per_user(10);
        let manager = RefreshTokenManager::new(config);

        manager.generate("user123").unwrap();
        manager.generate("user123").unwrap();
        manager.generate("user456").unwrap();

        let deleted = manager.revoke_all_for_user("user123").unwrap();
        assert_eq!(deleted, 2);

        let user123_tokens = manager.get_user_tokens("user123").unwrap();
        assert!(user123_tokens.is_empty());

        let user456_tokens = manager.get_user_tokens("user456").unwrap();
        assert_eq!(user456_tokens.len(), 1);
    }

    #[test]
    fn test_manager_max_families() {
        let config = RefreshConfig::default().with_max_families_per_user(2);
        let manager = RefreshTokenManager::new(config);

        let token1 = manager.generate("user123").unwrap();
        let _token2 = manager.generate("user123").unwrap();
        let _token3 = manager.generate("user123").unwrap();

        // token1 的家族应该被删除
        let result = manager.use_token(&token1.token);
        assert!(result.is_err());

        // 用户应该只有 2 个 Token 家族
        let tokens = manager.get_user_tokens("user123").unwrap();
        let families: std::collections::HashSet<_> =
            tokens.iter().map(|t| t.family_id.clone()).collect();
        assert_eq!(families.len(), 2);
    }

    #[test]
    fn test_manager_validate() {
        let manager = RefreshTokenManager::new(RefreshConfig::default());
        let token = manager.generate("user123").unwrap();

        let validated = manager.validate(&token.token).unwrap();
        assert_eq!(validated.user_id, "user123");
    }

    #[test]
    fn test_manager_cleanup() {
        let config = RefreshConfig::default().with_expiration(Duration::seconds(-1));
        let manager = RefreshTokenManager::new(config);

        manager.generate("user123").unwrap();
        manager.generate("user456").unwrap();

        let cleaned = manager.cleanup().unwrap();
        assert_eq!(cleaned, 2);
        assert_eq!(manager.count().unwrap(), 0);
    }

    #[test]
    fn test_config_presets() {
        let high_security = RefreshConfig::high_security();
        assert_eq!(high_security.expiration, Duration::days(7));
        assert!(high_security.rotation_enabled);
        assert!(high_security.reuse_detection);

        let relaxed = RefreshConfig::relaxed();
        assert_eq!(relaxed.expiration, Duration::days(90));
        assert!(relaxed.grace_period.num_seconds() > 0);
    }

    #[test]
    fn test_generate_with_metadata() {
        let manager = RefreshTokenManager::new(RefreshConfig::default());
        let token = manager
            .generate_with_metadata(
                "user123",
                Some("Mozilla/5.0".into()),
                Some("192.168.1.1".into()),
            )
            .unwrap();

        assert_eq!(token.device_info, Some("Mozilla/5.0".to_string()));
        assert_eq!(token.ip_address, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_token_time_to_live() {
        let token = RefreshToken::new("user123", "family1".into(), Duration::hours(1)).unwrap();
        let ttl = token.time_to_live();

        assert!(ttl > 3500);
        assert!(ttl <= 3600);
    }

    #[test]
    fn test_in_memory_store() {
        let store = InMemoryRefreshTokenStore::new();
        let token = RefreshToken::new("user123", "family1".into(), Duration::days(7)).unwrap();

        store.save(&token).unwrap();
        assert_eq!(store.count().unwrap(), 1);

        let retrieved = store.get_by_token(&token.token).unwrap();
        assert!(retrieved.is_some());

        store.delete(&token.token_id).unwrap();
        assert_eq!(store.count().unwrap(), 0);
    }
}
