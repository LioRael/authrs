//! API Key 管理模块
//!
//! 提供完整的 API Key 生命周期管理功能，包括：
//!
//! - API Key 创建与验证
//! - Key 哈希存储（不存明文）
//! - 权限范围 (Scopes)
//! - 过期时间支持
//! - Key 轮换
//!
//! ## 设计原则
//!
//! 1. **安全存储**: API Key 明文仅在创建时返回一次，存储时使用哈希
//! 2. **前缀识别**: 使用可见前缀（如 `sk_live_`）便于识别 Key 类型
//! 3. **细粒度权限**: 支持为每个 Key 分配不同的权限范围
//! 4. **自动过期**: 支持设置过期时间，增强安全性
//! 5. **密钥轮换**: 支持在不中断服务的情况下更换 Key
//!
//! ## 示例
//!
//! ```rust
//! use authrs::api_key::{ApiKeyManager, ApiKeyConfig, ApiKey};
//!
//! // 创建管理器
//! let mut manager = ApiKeyManager::new(ApiKeyConfig::default());
//!
//! // 创建 API Key
//! let (api_key, plain_key) = manager.create_key("my-service")
//!     .with_prefix("sk_live")
//!     .with_scope("read")
//!     .with_scope("write")
//!     .with_expires_in_days(90)
//!     .build()
//!     .unwrap();
//!
//! // 保存明文 key（仅此一次机会）
//! println!("Your API Key: {}", plain_key);
//!
//! // 验证 API Key
//! if let Some(key) = manager.validate(&plain_key) {
//!     println!("Key is valid, owner: {}", key.owner);
//! }
//! ```

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::error::{Error, Result, StorageError, ValidationError};
use crate::random::{generate_random_alphanumeric, generate_random_bytes};

/// API Key 配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    /// Key 随机部分的长度（字节）
    pub key_length: usize,

    /// 默认前缀
    pub default_prefix: String,

    /// 是否要求设置过期时间
    pub require_expiration: bool,

    /// 最大过期时间（天）
    pub max_expiration_days: Option<u32>,

    /// 是否允许无权限范围的 Key
    pub allow_empty_scopes: bool,
}

impl Default for ApiKeyConfig {
    fn default() -> Self {
        Self {
            key_length: 32,
            default_prefix: "sk".to_string(),
            require_expiration: false,
            max_expiration_days: None,
            allow_empty_scopes: true,
        }
    }
}

impl ApiKeyConfig {
    /// 创建生产环境配置
    pub fn production() -> Self {
        Self {
            key_length: 32,
            default_prefix: "sk_live".to_string(),
            require_expiration: true,
            max_expiration_days: Some(365),
            allow_empty_scopes: false,
        }
    }

    /// 创建测试环境配置
    pub fn test() -> Self {
        Self {
            key_length: 32,
            default_prefix: "sk_test".to_string(),
            require_expiration: false,
            max_expiration_days: None,
            allow_empty_scopes: true,
        }
    }
}

/// API Key 状态
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ApiKeyStatus {
    /// 活跃状态
    #[default]
    Active,
    /// 已撤销
    Revoked,
    /// 已过期
    Expired,
    /// 已禁用
    Disabled,
}

/// API Key 结构
///
/// 存储 API Key 的元数据，不包含明文密钥
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// 唯一标识符
    pub id: String,

    /// 可见前缀（如 "sk_live_"）
    pub prefix: String,

    /// Key 的哈希值（SHA-256）
    pub key_hash: String,

    /// Key 的前几个字符（用于显示，如 "sk_live_abc..."）
    pub key_hint: String,

    /// Key 所有者/描述
    pub owner: String,

    /// 权限范围
    pub scopes: Vec<String>,

    /// 创建时间
    pub created_at: DateTime<Utc>,

    /// 过期时间
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    /// 最后使用时间
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,

    /// 使用次数
    #[serde(default)]
    pub use_count: u64,

    /// 状态
    pub status: ApiKeyStatus,

    /// 元数据
    #[serde(default)]
    pub metadata: HashMap<String, String>,

    /// 轮换信息（如果此 Key 是由另一个 Key 轮换而来）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotated_from: Option<String>,
}

impl ApiKey {
    /// 检查 Key 是否有效（活跃且未过期）
    pub fn is_valid(&self) -> bool {
        if self.status != ApiKeyStatus::Active {
            return false;
        }

        if let Some(expires_at) = self.expires_at {
            expires_at > Utc::now()
        } else {
            true
        }
    }

    /// 检查是否已过期
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            expires_at <= Utc::now()
        } else {
            false
        }
    }

    /// 检查是否具有指定的权限范围
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }

    /// 检查是否具有所有指定的权限范围
    pub fn has_all_scopes(&self, scopes: &[&str]) -> bool {
        scopes.iter().all(|s| self.has_scope(s))
    }

    /// 检查是否具有任一指定的权限范围
    pub fn has_any_scope(&self, scopes: &[&str]) -> bool {
        scopes.iter().any(|s| self.has_scope(s))
    }

    /// 获取剩余有效时间
    pub fn remaining_lifetime(&self) -> Option<Duration> {
        self.expires_at.map(|exp| {
            let remaining = exp - Utc::now();
            if remaining.num_seconds() > 0 {
                remaining
            } else {
                Duration::zero()
            }
        })
    }

    /// 获取显示用的 Key 提示（如 "sk_live_abc...xyz"）
    pub fn display_hint(&self) -> String {
        format!(
            "{}...{}",
            &self.key_hint,
            &self.key_hint[self.key_hint.len().saturating_sub(4)..]
        )
    }

    /// 记录使用
    pub fn record_usage(&mut self) {
        self.last_used_at = Some(Utc::now());
        self.use_count += 1;
    }

    /// 撤销 Key
    pub fn revoke(&mut self) {
        self.status = ApiKeyStatus::Revoked;
    }

    /// 禁用 Key
    pub fn disable(&mut self) {
        self.status = ApiKeyStatus::Disabled;
    }

    /// 启用 Key（如果之前被禁用）
    pub fn enable(&mut self) {
        if self.status == ApiKeyStatus::Disabled {
            self.status = ApiKeyStatus::Active;
        }
    }
}

/// API Key 创建构建器
#[derive(Debug)]
pub struct ApiKeyBuilder<'a> {
    manager: &'a ApiKeyConfig,
    owner: String,
    prefix: Option<String>,
    scopes: Vec<String>,
    expires_at: Option<DateTime<Utc>>,
    metadata: HashMap<String, String>,
}

impl<'a> ApiKeyBuilder<'a> {
    /// 创建新的构建器
    fn new(manager: &'a ApiKeyConfig, owner: String) -> Self {
        Self {
            manager,
            owner,
            prefix: None,
            scopes: Vec::new(),
            expires_at: None,
            metadata: HashMap::new(),
        }
    }

    /// 设置前缀
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = Some(prefix.into());
        self
    }

    /// 添加权限范围
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    /// 设置多个权限范围
    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    /// 设置过期时间
    pub fn with_expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// 设置过期天数
    pub fn with_expires_in_days(mut self, days: u32) -> Self {
        self.expires_at = Some(Utc::now() + Duration::days(days as i64));
        self
    }

    /// 添加元数据
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// 构建 API Key
    ///
    /// 返回 (ApiKey, 明文密钥)
    /// 明文密钥仅在此时返回一次
    pub fn build(self) -> Result<(ApiKey, String)> {
        // 验证配置
        if !self.manager.allow_empty_scopes && self.scopes.is_empty() {
            return Err(Error::Validation(ValidationError::Custom(
                "At least one scope is required".to_string(),
            )));
        }

        if self.manager.require_expiration && self.expires_at.is_none() {
            return Err(Error::Validation(ValidationError::Custom(
                "Expiration time is required".to_string(),
            )));
        }

        // 检查最大过期时间
        if let (Some(max_days), Some(expires_at)) =
            (self.manager.max_expiration_days, self.expires_at)
        {
            let max_expiration = Utc::now() + Duration::days(max_days as i64);
            if expires_at > max_expiration {
                return Err(Error::Validation(ValidationError::Custom(format!(
                    "Expiration cannot exceed {} days",
                    max_days
                ))));
            }
        }

        let prefix = self
            .prefix
            .unwrap_or_else(|| self.manager.default_prefix.clone());

        // 生成随机 Key
        let _random_bytes = generate_random_bytes(self.manager.key_length)?;
        let random_part = generate_random_alphanumeric(self.manager.key_length)?;

        // 完整的明文 Key
        let plain_key = format!("{}_{}", prefix, random_part);

        // 计算哈希
        let key_hash = hash_api_key(&plain_key);

        // 生成 ID
        let id = generate_key_id()?;

        // 生成 hint（显示前8个字符）
        let key_hint = format!("{}_{}", prefix, &random_part[..8.min(random_part.len())]);

        let api_key = ApiKey {
            id,
            prefix,
            key_hash,
            key_hint,
            owner: self.owner,
            scopes: self.scopes,
            created_at: Utc::now(),
            expires_at: self.expires_at,
            last_used_at: None,
            use_count: 0,
            status: ApiKeyStatus::Active,
            metadata: self.metadata,
            rotated_from: None,
        };

        Ok((api_key, plain_key))
    }
}

/// API Key 管理器
#[derive(Debug)]
pub struct ApiKeyManager {
    /// 配置
    config: ApiKeyConfig,

    /// Key 存储（按 ID 索引）
    keys_by_id: HashMap<String, ApiKey>,

    /// Key 哈希到 ID 的映射（用于快速验证）
    hash_to_id: HashMap<String, String>,
}

impl ApiKeyManager {
    /// 创建新的管理器
    pub fn new(config: ApiKeyConfig) -> Self {
        Self {
            config,
            keys_by_id: HashMap::new(),
            hash_to_id: HashMap::new(),
        }
    }

    /// 使用默认配置创建管理器
    pub fn with_default_config() -> Self {
        Self::new(ApiKeyConfig::default())
    }

    /// 获取配置引用
    pub fn config(&self) -> &ApiKeyConfig {
        &self.config
    }

    /// 创建新的 API Key 构建器
    pub fn create_key(&self, owner: impl Into<String>) -> ApiKeyBuilder<'_> {
        ApiKeyBuilder::new(&self.config, owner.into())
    }

    /// 添加 Key 到管理器
    pub fn add_key(&mut self, key: ApiKey) {
        self.hash_to_id.insert(key.key_hash.clone(), key.id.clone());
        self.keys_by_id.insert(key.id.clone(), key);
    }

    /// 验证 API Key
    ///
    /// 如果 Key 有效，返回对应的 ApiKey 引用
    pub fn validate(&mut self, plain_key: &str) -> Option<&ApiKey> {
        let hash = hash_api_key(plain_key);

        let id = self.hash_to_id.get(&hash)?;
        let key = self.keys_by_id.get_mut(id)?;

        if !key.is_valid() {
            return None;
        }

        // 记录使用
        key.record_usage();

        Some(key)
    }

    /// 验证 API Key 并检查权限范围
    pub fn validate_with_scopes(
        &mut self,
        plain_key: &str,
        required_scopes: &[&str],
    ) -> Option<&ApiKey> {
        let key = self.validate(plain_key)?;

        if key.has_all_scopes(required_scopes) {
            Some(key)
        } else {
            None
        }
    }

    /// 根据 ID 获取 Key
    pub fn get_by_id(&self, id: &str) -> Option<&ApiKey> {
        self.keys_by_id.get(id)
    }

    /// 根据 ID 获取可变 Key 引用
    pub fn get_by_id_mut(&mut self, id: &str) -> Option<&mut ApiKey> {
        self.keys_by_id.get_mut(id)
    }

    /// 撤销 Key
    pub fn revoke(&mut self, id: &str) -> Result<()> {
        let key = self
            .keys_by_id
            .get_mut(id)
            .ok_or_else(|| Error::Storage(StorageError::NotFound(id.to_string())))?;

        key.revoke();
        Ok(())
    }

    /// 删除 Key
    pub fn delete(&mut self, id: &str) -> Result<ApiKey> {
        let key = self
            .keys_by_id
            .remove(id)
            .ok_or_else(|| Error::Storage(StorageError::NotFound(id.to_string())))?;

        self.hash_to_id.remove(&key.key_hash);
        Ok(key)
    }

    /// 轮换 Key
    ///
    /// 创建新 Key 并撤销旧 Key
    /// 返回 (新 ApiKey, 新明文密钥)
    pub fn rotate(&mut self, id: &str) -> Result<(ApiKey, String)> {
        let old_key = self
            .keys_by_id
            .get(id)
            .ok_or_else(|| Error::Storage(StorageError::NotFound(id.to_string())))?;

        if !old_key.is_valid() {
            return Err(Error::Validation(ValidationError::Custom(
                "Cannot rotate an invalid key".to_string(),
            )));
        }

        // 创建新 Key，继承旧 Key 的属性
        let mut builder = self
            .create_key(&old_key.owner)
            .with_prefix(&old_key.prefix)
            .with_scopes(old_key.scopes.clone());

        // 继承过期时间（如果有）
        if let Some(expires_at) = old_key.expires_at {
            builder = builder.with_expires_at(expires_at);
        }

        // 继承元数据
        for (k, v) in &old_key.metadata {
            builder = builder.with_metadata(k, v);
        }

        let (mut new_key, plain_key) = builder.build()?;
        new_key.rotated_from = Some(id.to_string());

        // 撤销旧 Key
        self.revoke(id)?;

        // 添加新 Key
        self.add_key(new_key.clone());

        Ok((new_key, plain_key))
    }

    /// 列出所有 Key
    pub fn list(&self) -> Vec<&ApiKey> {
        self.keys_by_id.values().collect()
    }

    /// 列出某个所有者的所有 Key
    pub fn list_by_owner(&self, owner: &str) -> Vec<&ApiKey> {
        self.keys_by_id
            .values()
            .filter(|k| k.owner == owner)
            .collect()
    }

    /// 列出所有活跃的 Key
    pub fn list_active(&self) -> Vec<&ApiKey> {
        self.keys_by_id.values().filter(|k| k.is_valid()).collect()
    }

    /// 列出即将过期的 Key（在指定天数内）
    pub fn list_expiring_soon(&self, days: i64) -> Vec<&ApiKey> {
        let threshold = Utc::now() + Duration::days(days);

        self.keys_by_id
            .values()
            .filter(|k| k.is_valid() && k.expires_at.map(|exp| exp <= threshold).unwrap_or(false))
            .collect()
    }

    /// 清理过期的 Key
    pub fn cleanup_expired(&mut self) -> Vec<ApiKey> {
        let expired_ids: Vec<String> = self
            .keys_by_id
            .values()
            .filter(|k| k.is_expired())
            .map(|k| k.id.clone())
            .collect();

        expired_ids
            .into_iter()
            .filter_map(|id| self.delete(&id).ok())
            .collect()
    }

    /// 获取统计信息
    pub fn stats(&self) -> ApiKeyStats {
        let total = self.keys_by_id.len();
        let active = self.keys_by_id.values().filter(|k| k.is_valid()).count();
        let expired = self.keys_by_id.values().filter(|k| k.is_expired()).count();
        let revoked = self
            .keys_by_id
            .values()
            .filter(|k| k.status == ApiKeyStatus::Revoked)
            .count();

        ApiKeyStats {
            total,
            active,
            expired,
            revoked,
        }
    }
}

/// API Key 统计信息
#[derive(Debug, Clone)]
pub struct ApiKeyStats {
    /// 总数
    pub total: usize,
    /// 活跃数
    pub active: usize,
    /// 已过期数
    pub expired: usize,
    /// 已撤销数
    pub revoked: usize,
}

/// API Key 存储 trait
///
/// 实现此 trait 以提供持久化存储
#[async_trait]
pub trait ApiKeyStore: Send + Sync {
    /// 保存 Key
    async fn save(&mut self, key: &ApiKey) -> Result<()>;

    /// 根据 ID 加载 Key
    async fn load(&self, id: &str) -> Result<Option<ApiKey>>;

    /// 根据哈希加载 Key
    async fn load_by_hash(&self, hash: &str) -> Result<Option<ApiKey>>;

    /// 删除 Key
    async fn delete(&mut self, id: &str) -> Result<()>;

    /// 列出所有 Key
    async fn list(&self) -> Result<Vec<ApiKey>>;

    /// 根据所有者列出 Key
    async fn list_by_owner(&self, owner: &str) -> Result<Vec<ApiKey>>;
}

/// 内存存储实现
#[derive(Debug, Default)]
pub struct InMemoryApiKeyStore {
    keys: HashMap<String, ApiKey>,
    hash_index: HashMap<String, String>,
}

impl InMemoryApiKeyStore {
    /// 创建新的内存存储
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ApiKeyStore for InMemoryApiKeyStore {
    async fn save(&mut self, key: &ApiKey) -> Result<()> {
        self.hash_index.insert(key.key_hash.clone(), key.id.clone());
        self.keys.insert(key.id.clone(), key.clone());
        Ok(())
    }

    async fn load(&self, id: &str) -> Result<Option<ApiKey>> {
        Ok(self.keys.get(id).cloned())
    }

    async fn load_by_hash(&self, hash: &str) -> Result<Option<ApiKey>> {
        let id = match self.hash_index.get(hash) {
            Some(id) => id,
            None => return Ok(None),
        };
        self.load(id).await
    }

    async fn delete(&mut self, id: &str) -> Result<()> {
        if let Some(key) = self.keys.remove(id) {
            self.hash_index.remove(&key.key_hash);
        }
        Ok(())
    }

    async fn list(&self) -> Result<Vec<ApiKey>> {
        Ok(self.keys.values().cloned().collect())
    }

    async fn list_by_owner(&self, owner: &str) -> Result<Vec<ApiKey>> {
        Ok(self
            .keys
            .values()
            .filter(|k| k.owner == owner)
            .cloned()
            .collect())
    }
}

// ============================================================================
// 辅助函数
// ============================================================================

/// 计算 API Key 的哈希值
fn hash_api_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    let result = hasher.finalize();
    result.iter().map(|b| format!("{:02x}", b)).collect()
}

/// 生成 Key ID
fn generate_key_id() -> Result<String> {
    let random = generate_random_alphanumeric(16)?;
    Ok(format!("key_{}", random))
}

/// 验证 API Key 格式
pub fn validate_api_key_format(key: &str) -> bool {
    // 检查是否包含前缀和随机部分
    // 格式: prefix_random 或 prefix_env_random (如 sk_test_xxx)
    let parts: Vec<&str> = key.rsplitn(2, '_').collect();
    if parts.len() < 2 {
        return false;
    }

    // 随机部分是最后一个下划线之后的内容
    let random_part = parts.first().unwrap_or(&"");
    random_part.len() >= 16 && random_part.chars().all(|c| c.is_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_api_key() {
        let mut manager = ApiKeyManager::with_default_config();

        let (key, plain_key) = manager
            .create_key("test-service")
            .with_prefix("sk_test")
            .with_scope("read")
            .with_scope("write")
            .build()
            .unwrap();

        assert!(plain_key.starts_with("sk_test_"));
        assert!(key.is_valid());
        assert!(key.has_scope("read"));
        assert!(key.has_scope("write"));
        assert!(!key.has_scope("admin"));

        manager.add_key(key);

        // 验证 Key
        let validated = manager.validate(&plain_key);
        assert!(validated.is_some());
    }

    #[test]
    fn test_key_expiration() {
        let manager = ApiKeyManager::with_default_config();

        let (mut key, _) = manager
            .create_key("test")
            .with_expires_in_days(0) // 立即过期
            .build()
            .unwrap();

        // 手动设置为过去的时间
        key.expires_at = Some(Utc::now() - Duration::hours(1));

        assert!(key.is_expired());
        assert!(!key.is_valid());
    }

    #[test]
    fn test_key_revocation() {
        let mut manager = ApiKeyManager::with_default_config();

        let (key, plain_key) = manager.create_key("test").build().unwrap();

        let id = key.id.clone();
        manager.add_key(key);

        // 验证有效
        assert!(manager.validate(&plain_key).is_some());

        // 撤销
        manager.revoke(&id).unwrap();

        // 验证无效
        assert!(manager.validate(&plain_key).is_none());
    }

    #[test]
    fn test_key_rotation() {
        let mut manager = ApiKeyManager::with_default_config();

        let (key, old_plain_key) = manager
            .create_key("test")
            .with_scope("read")
            .build()
            .unwrap();

        let old_id = key.id.clone();
        manager.add_key(key);

        // 轮换
        let (new_key, new_plain_key) = manager.rotate(&old_id).unwrap();

        assert_ne!(old_plain_key, new_plain_key);
        assert!(new_key.has_scope("read"));
        assert_eq!(new_key.rotated_from, Some(old_id.clone()));

        // 旧 Key 无效
        assert!(manager.validate(&old_plain_key).is_none());

        // 新 Key 有效
        assert!(manager.validate(&new_plain_key).is_some());
    }

    #[test]
    fn test_scope_validation() {
        let mut manager = ApiKeyManager::with_default_config();

        let (key, plain_key) = manager
            .create_key("test")
            .with_scope("read")
            .with_scope("write")
            .build()
            .unwrap();

        manager.add_key(key);

        // 有效范围
        assert!(
            manager
                .validate_with_scopes(&plain_key, &["read"])
                .is_some()
        );
        assert!(
            manager
                .validate_with_scopes(&plain_key, &["read", "write"])
                .is_some()
        );

        // 无效范围
        assert!(
            manager
                .validate_with_scopes(&plain_key, &["admin"])
                .is_none()
        );
        assert!(
            manager
                .validate_with_scopes(&plain_key, &["read", "admin"])
                .is_none()
        );
    }

    #[test]
    fn test_production_config() {
        let config = ApiKeyConfig::production();
        let manager = ApiKeyManager::new(config);

        // 生产配置要求过期时间和权限范围
        let result = manager.create_key("test").build();
        assert!(result.is_err());

        // 提供必要参数
        let result = manager
            .create_key("test")
            .with_scope("read")
            .with_expires_in_days(30)
            .build();
        assert!(result.is_ok());
    }

    #[test]
    fn test_usage_tracking() {
        let mut manager = ApiKeyManager::with_default_config();

        let (key, plain_key) = manager.create_key("test").build().unwrap();
        let id = key.id.clone();
        manager.add_key(key);

        // 多次验证
        manager.validate(&plain_key);
        manager.validate(&plain_key);
        manager.validate(&plain_key);

        let key = manager.get_by_id(&id).unwrap();
        assert_eq!(key.use_count, 3);
        assert!(key.last_used_at.is_some());
    }

    #[test]
    fn test_list_expiring_soon() {
        let mut manager = ApiKeyManager::with_default_config();

        // 即将过期的 Key
        let (key1, _) = manager
            .create_key("test1")
            .with_expires_in_days(5)
            .build()
            .unwrap();
        manager.add_key(key1);

        // 远期过期的 Key
        let (key2, _) = manager
            .create_key("test2")
            .with_expires_in_days(60)
            .build()
            .unwrap();
        manager.add_key(key2);

        let expiring = manager.list_expiring_soon(7);
        assert_eq!(expiring.len(), 1);
    }

    #[test]
    fn test_stats() {
        let mut manager = ApiKeyManager::with_default_config();

        // 活跃 Key
        let (key1, _) = manager.create_key("test1").build().unwrap();
        manager.add_key(key1);

        // 撤销的 Key
        let (key2, _) = manager.create_key("test2").build().unwrap();
        let id = key2.id.clone();
        manager.add_key(key2);
        manager.revoke(&id).unwrap();

        let stats = manager.stats();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.active, 1);
        assert_eq!(stats.revoked, 1);
    }

    #[tokio::test]
    async fn test_in_memory_store() {
        let mut store = InMemoryApiKeyStore::new();

        let manager = ApiKeyManager::with_default_config();
        let (key, _) = manager.create_key("test").build().unwrap();
        let id = key.id.clone();
        let hash = key.key_hash.clone();

        store.save(&key).await.unwrap();

        assert!(store.load(&id).await.unwrap().is_some());
        assert!(store.load_by_hash(&hash).await.unwrap().is_some());

        let list = store.list().await.unwrap();
        assert_eq!(list.len(), 1);

        store.delete(&id).await.unwrap();
        assert!(store.load(&id).await.unwrap().is_none());
    }

    #[test]
    fn test_validate_api_key_format() {
        assert!(validate_api_key_format("sk_test_abcdefghijklmnop"));
        assert!(validate_api_key_format("sk_live_1234567890abcdef"));
        assert!(!validate_api_key_format("invalid"));
        assert!(!validate_api_key_format("sk_short"));
    }

    #[test]
    fn test_key_metadata() {
        let manager = ApiKeyManager::with_default_config();

        let (key, _) = manager
            .create_key("test")
            .with_metadata("env", "production")
            .with_metadata("team", "backend")
            .build()
            .unwrap();

        assert_eq!(key.metadata.get("env"), Some(&"production".to_string()));
        assert_eq!(key.metadata.get("team"), Some(&"backend".to_string()));
    }
}
