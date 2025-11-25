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
//! - 灵活的元数据存储
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
//!
//! ## 自定义存储后端
//!
//! 实现 `RefreshTokenStore` trait 可以使用自定义的存储后端：
//!
//! ```rust,ignore
//! use authrs::token::refresh::{RefreshToken, RefreshTokenStore, RefreshTokenManager, RefreshConfig};
//! use authrs::error::Result;
//! use std::sync::Arc;
//!
//! struct RedisRefreshTokenStore {
//!     // Redis 连接
//! }
//!
//! impl RefreshTokenStore for RedisRefreshTokenStore {
//!     fn save(&self, token: &RefreshToken) -> Result<()> {
//!         // 保存到 Redis
//!         todo!()
//!     }
//!     // ... 实现其他方法
//! }
//!
//! // 使用自定义存储
//! let store = Arc::new(RedisRefreshTokenStore { /* ... */ });
//! let manager = RefreshTokenManager::with_store(RefreshConfig::default(), store);
//! ```

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::error::{Error, Result, StorageError, TokenError};
use crate::random::{generate_random_base64_url, generate_random_hex};

// ============================================================================
// Refresh Token 数据结构
// ============================================================================

/// Refresh Token 数据结构
///
/// 包含 Token 的核心字段和可扩展的元数据。
///
/// ## Token 家族
///
/// `family_id` 用于追踪 Token 的血缘关系。当 Token 轮换时，新旧 Token 共享同一个 family_id。
/// 如果检测到一个已使用的 Token 被再次使用（重用攻击），可以通过 family_id 撤销整个家族的所有 Token。
///
/// ## 元数据
///
/// `metadata` 字段允许存储任意可序列化的数据：
///
/// ```rust
/// use authrs::token::refresh::{RefreshTokenManager, RefreshConfig};
/// use serde::{Serialize, Deserialize};
///
/// let manager = RefreshTokenManager::new(RefreshConfig::default());
/// let mut token = manager.generate("user123").unwrap();
///
/// // 存储设备信息
/// token.set_metadata("device_type", "mobile");
/// token.set_metadata("app_version", "1.0.0");
///
/// // 类型安全地读取
/// let device: Option<String> = token.get_metadata("device_type");
/// ```
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

    /// 创建时间（Unix 时间戳，秒）
    pub created_at: i64,

    /// 过期时间（Unix 时间戳，秒）
    pub expires_at: i64,

    /// 是否已被使用（用于检测重用）
    pub used: bool,

    /// 使用时间（Unix 时间戳，秒）
    pub used_at: Option<i64>,

    /// 替代此 Token 的新 Token ID
    pub replaced_by: Option<String>,

    /// 设备信息（可选）
    pub device_info: Option<String>,

    /// IP 地址（可选）
    pub ip_address: Option<String>,

    /// 用户自定义元数据
    pub metadata: serde_json::Value,
}

impl RefreshToken {
    /// 创建新的 Refresh Token
    fn new(user_id: impl Into<String>, family_id: String, expires_in: Duration) -> Result<Self> {
        let now = Utc::now().timestamp();
        let token = generate_random_base64_url(48)?;
        let token_id = generate_random_hex(16)?;

        Ok(Self {
            token,
            token_id,
            user_id: user_id.into(),
            family_id,
            created_at: now,
            expires_at: now + expires_in.num_seconds(),
            used: false,
            used_at: None,
            replaced_by: None,
            device_info: None,
            ip_address: None,
            metadata: serde_json::Value::Object(serde_json::Map::new()),
        })
    }

    /// 检查 Token 是否已过期
    #[inline]
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() > self.expires_at
    }

    /// 检查 Token 是否有效（未过期且未被使用）
    #[inline]
    pub fn is_valid(&self) -> bool {
        !self.is_expired() && !self.used
    }

    /// 获取剩余有效时间（秒）
    ///
    /// 如果已过期，返回 0
    pub fn time_to_live(&self) -> i64 {
        (self.expires_at - Utc::now().timestamp()).max(0)
    }

    /// 标记 Token 为已使用
    fn mark_as_used(&mut self, replaced_by: Option<String>) {
        self.used = true;
        self.used_at = Some(Utc::now().timestamp());
        self.replaced_by = replaced_by;
    }

    // ========================================================================
    // 元数据访问方法
    // ========================================================================

    /// 设置元数据
    ///
    /// 可以存储任意可序列化的值。如果序列化失败，操作将被忽略。
    ///
    /// # 示例
    ///
    /// ```rust
    /// use authrs::token::refresh::{RefreshTokenManager, RefreshConfig};
    ///
    /// let manager = RefreshTokenManager::new(RefreshConfig::default());
    /// let mut token = manager.generate("user123").unwrap();
    ///
    /// token.set_metadata("device", "iPhone");
    /// token.set_metadata("login_count", 5);
    /// ```
    pub fn set_metadata<T: Serialize>(&mut self, key: impl Into<String>, value: T) {
        if let Ok(json_value) = serde_json::to_value(value) {
            if let Some(obj) = self.metadata.as_object_mut() {
                obj.insert(key.into(), json_value);
            }
        }
    }

    /// 获取元数据
    ///
    /// 类型安全地获取指定键的值。如果键不存在或类型不匹配，返回 `None`。
    ///
    /// # 示例
    ///
    /// ```rust
    /// use authrs::token::refresh::{RefreshTokenManager, RefreshConfig};
    ///
    /// let manager = RefreshTokenManager::new(RefreshConfig::default());
    /// let mut token = manager.generate("user123").unwrap();
    ///
    /// token.set_metadata("device", "iPhone");
    /// let device: Option<String> = token.get_metadata("device");
    /// assert_eq!(device, Some("iPhone".to_string()));
    /// ```
    pub fn get_metadata<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.metadata
            .get(key)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// 获取元数据的原始 JSON 值
    pub fn get_metadata_raw(&self, key: &str) -> Option<&serde_json::Value> {
        self.metadata.get(key)
    }

    /// 检查是否存在指定的元数据键
    pub fn has_metadata(&self, key: &str) -> bool {
        self.metadata.get(key).is_some()
    }

    /// 删除元数据
    ///
    /// 返回被删除的值（如果存在）
    pub fn remove_metadata(&mut self, key: &str) -> Option<serde_json::Value> {
        self.metadata
            .as_object_mut()
            .and_then(|obj| obj.remove(key))
    }

    /// 清空所有元数据
    pub fn clear_metadata(&mut self) {
        self.metadata = serde_json::Value::Object(serde_json::Map::new());
    }

    /// 获取所有元数据键
    pub fn metadata_keys(&self) -> Vec<&str> {
        self.metadata
            .as_object()
            .map(|obj| obj.keys().map(|k| k.as_str()).collect())
            .unwrap_or_default()
    }
}

// ============================================================================
// Refresh Token 配置
// ============================================================================

/// Refresh Token 配置
#[derive(Debug, Clone)]
pub struct RefreshConfig {
    /// Token 有效期
    pub expiration: Duration,

    /// 是否启用 Token 轮换
    pub rotation_enabled: bool,

    /// 是否启用重用检测
    pub reuse_detection: bool,

    /// 每个家族最大 Token 数
    pub max_tokens_per_family: usize,

    /// 每个用户最大 Token 家族数
    pub max_families_per_user: usize,

    /// 宽限期（Token 被使用后仍可在宽限期内使用）
    pub grace_period: Duration,
}

impl Default for RefreshConfig {
    fn default() -> Self {
        Self {
            expiration: Duration::days(30),
            rotation_enabled: true,
            reuse_detection: true,
            max_tokens_per_family: 5,
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

    /// 设置每个用户最大 Token 家族数
    pub fn with_max_families_per_user(mut self, max: usize) -> Self {
        self.max_families_per_user = max;
        self
    }

    /// 设置宽限期
    pub fn with_grace_period(mut self, duration: Duration) -> Self {
        self.grace_period = duration;
        self
    }

    /// 创建高安全配置
    ///
    /// - 7 天有效期
    /// - 启用 Token 轮换
    /// - 启用重用检测
    /// - 无宽限期
    pub fn high_security() -> Self {
        Self {
            expiration: Duration::days(7),
            rotation_enabled: true,
            reuse_detection: true,
            max_tokens_per_family: 3,
            max_families_per_user: 3,
            grace_period: Duration::seconds(0),
        }
    }

    /// 创建宽松配置
    ///
    /// - 90 天有效期
    /// - 禁用 Token 轮换
    /// - 禁用重用检测
    pub fn relaxed() -> Self {
        Self {
            expiration: Duration::days(90),
            rotation_enabled: false,
            reuse_detection: false,
            max_tokens_per_family: 10,
            max_families_per_user: 10,
            grace_period: Duration::seconds(60),
        }
    }
}

// ============================================================================
// Refresh Token 存储 Trait
// ============================================================================

/// Refresh Token 存储 trait
///
/// 实现此 trait 可以自定义 Token 的存储后端。
///
/// ## 内置实现
///
/// - `InMemoryRefreshTokenStore`: 内存存储，适用于开发和测试
///
/// ## 自定义实现示例
///
/// ```rust,ignore
/// use authrs::token::refresh::{RefreshToken, RefreshTokenStore};
/// use authrs::error::Result;
///
/// struct PostgresRefreshTokenStore {
///     pool: sqlx::PgPool,
/// }
///
/// impl RefreshTokenStore for PostgresRefreshTokenStore {
///     fn save(&self, token: &RefreshToken) -> Result<()> {
///         // INSERT INTO refresh_tokens ...
///         todo!()
///     }
///
///     fn get_by_token(&self, token: &str) -> Result<Option<RefreshToken>> {
///         // SELECT * FROM refresh_tokens WHERE token = ?
///         todo!()
///     }
///
///     // ... 实现其他方法
/// }
/// ```
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
    ///
    /// 返回删除的 Token 数量
    fn delete_family(&self, family_id: &str) -> Result<usize>;

    /// 删除用户的所有 Token
    ///
    /// 返回删除的 Token 数量
    fn delete_by_user(&self, user_id: &str) -> Result<usize>;

    /// 清理过期的 Token
    ///
    /// 返回清理的 Token 数量
    fn cleanup_expired(&self) -> Result<usize>;

    /// 获取 Token 总数
    fn count(&self) -> Result<usize>;
}

// ============================================================================
// 内存存储实现
// ============================================================================

/// 内存 Refresh Token 存储
///
/// 用于开发和测试，生产环境建议使用 Redis 等持久化存储。
///
/// ## 特点
///
/// - 线程安全（使用 `RwLock`）
/// - 维护 Token 值到 Token ID 的索引以加速查找
/// - 无持久化，重启后数据丢失
#[derive(Debug, Default)]
pub struct InMemoryRefreshTokenStore {
    tokens: RwLock<HashMap<String, RefreshToken>>,
    token_index: RwLock<HashMap<String, String>>, // token -> token_id
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

        index.insert(token.token.clone(), token.token_id.clone());
        tokens.insert(token.token_id.clone(), token.clone());
        Ok(())
    }

    fn get_by_token(&self, token: &str) -> Result<Option<RefreshToken>> {
        let index = self
            .token_index
            .read()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;
        let tokens = self
            .tokens
            .read()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;

        if let Some(token_id) = index.get(token) {
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
            Err(Error::Storage(StorageError::NotFound(
                "token not found".into(),
            )))
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

        let to_delete: Vec<_> = tokens
            .iter()
            .filter(|(_, t)| t.family_id == family_id)
            .map(|(id, t)| (id.clone(), t.token.clone()))
            .collect();

        let count = to_delete.len();
        for (token_id, token) in to_delete {
            tokens.remove(&token_id);
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

        let to_delete: Vec<_> = tokens
            .iter()
            .filter(|(_, t)| t.user_id == user_id)
            .map(|(id, t)| (id.clone(), t.token.clone()))
            .collect();

        let count = to_delete.len();
        for (token_id, token) in to_delete {
            tokens.remove(&token_id);
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

        let now = Utc::now().timestamp();
        let to_delete: Vec<_> = tokens
            .iter()
            .filter(|(_, t)| t.expires_at < now)
            .map(|(id, t)| (id.clone(), t.token.clone()))
            .collect();

        let count = to_delete.len();
        for (token_id, token) in to_delete {
            tokens.remove(&token_id);
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

// ============================================================================
// Token 使用结果
// ============================================================================

/// Token 使用结果
#[derive(Debug, Clone)]
pub struct TokenUseResult {
    /// 新生成的 Token（如果启用了轮换）
    pub new_token: Option<RefreshToken>,

    /// 用户 ID
    pub user_id: String,

    /// Token 家族 ID
    pub family_id: String,

    /// 是否在宽限期内使用
    pub was_in_grace_period: bool,
}

// ============================================================================
// Refresh Token 管理器
// ============================================================================

/// Refresh Token 管理器
///
/// 提供 Refresh Token 的完整生命周期管理，包括生成、验证、轮换和撤销。
///
/// ## 示例
///
/// ```rust
/// use authrs::token::refresh::{RefreshTokenManager, RefreshConfig, GenerateOptions};
///
/// let manager = RefreshTokenManager::new(RefreshConfig::default());
///
/// // 生成 Token
/// let token = manager.generate("user123").unwrap();
///
/// // 带元数据生成 Token
/// let options = GenerateOptions::new()
///     .with_device_info("iPhone 15")
///     .with_ip_address("192.168.1.1");
/// let token = manager.generate_with_options("user123", options).unwrap();
///
/// // 使用 Token（会自动轮换）
/// let result = manager.use_token(&token.token).unwrap();
/// if let Some(new_token) = result.new_token {
///     println!("使用新 Token: {}", new_token.token);
/// }
///
/// // 撤销用户的所有 Token
/// manager.revoke_all_for_user("user123").unwrap();
/// ```
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
    /// # 参数
    ///
    /// * `user_id` - 用户 ID
    ///
    /// # 返回
    ///
    /// 返回生成的 Token
    pub fn generate(&self, user_id: impl Into<String>) -> Result<RefreshToken> {
        let user_id = user_id.into();
        self.enforce_max_families(&user_id)?;

        let family_id = generate_random_hex(16)?;
        let token = RefreshToken::new(&user_id, family_id, self.config.expiration)?;
        self.store.save(&token)?;

        Ok(token)
    }

    /// 使用选项生成 Refresh Token
    ///
    /// 允许设置设备信息、IP 地址和初始元数据。
    pub fn generate_with_options(
        &self,
        user_id: impl Into<String>,
        options: GenerateOptions,
    ) -> Result<RefreshToken> {
        let user_id = user_id.into();
        self.enforce_max_families(&user_id)?;

        let family_id = options
            .family_id
            .unwrap_or_else(|| generate_random_hex(16).unwrap_or_default());
        let mut token = RefreshToken::new(&user_id, family_id, self.config.expiration)?;

        token.device_info = options.device_info;
        token.ip_address = options.ip_address;

        if let Some(metadata) = options.metadata {
            token.metadata = metadata;
        }

        self.store.save(&token)?;
        Ok(token)
    }

    /// 使用 Refresh Token
    ///
    /// 如果启用了 Token 轮换，会生成新的 Token 并使旧 Token 失效。
    /// 如果检测到重用攻击（已使用的 Token 被再次使用），会撤销整个 Token 家族。
    ///
    /// # 参数
    ///
    /// * `token` - Token 值
    ///
    /// # 返回
    ///
    /// 返回使用结果，包含新 Token（如果启用轮换）
    pub fn use_token(&self, token: &str) -> Result<TokenUseResult> {
        let mut stored_token = self
            .store
            .get_by_token(token)?
            .ok_or_else(|| Error::Token(TokenError::InvalidFormat("token not found".into())))?;

        // 检查是否过期
        if stored_token.is_expired() {
            self.store.delete(&stored_token.token_id)?;
            return Err(Error::Token(TokenError::Expired));
        }

        // 检查重用攻击
        if stored_token.used {
            if self.config.reuse_detection {
                // 检查是否在宽限期内
                let grace_period_secs = self.config.grace_period.num_seconds();
                let used_at = stored_token.used_at.unwrap_or(0);
                let now = Utc::now().timestamp();

                // 如果宽限期为 0，或者已超过宽限期，则触发重用检测
                if grace_period_secs == 0 || now > used_at + grace_period_secs {
                    // 撤销整个家族
                    self.store.delete_family(&stored_token.family_id)?;
                    return Err(Error::Token(TokenError::InvalidFormat(
                        "token reuse detected, family revoked".into(),
                    )));
                }

                // 在宽限期内，允许使用
                return Ok(TokenUseResult {
                    new_token: None,
                    user_id: stored_token.user_id.clone(),
                    family_id: stored_token.family_id.clone(),
                    was_in_grace_period: true,
                });
            } else {
                return Err(Error::Token(TokenError::InvalidFormat(
                    "token already used".into(),
                )));
            }
        }

        // Token 轮换
        let new_token = if self.config.rotation_enabled {
            // 创建新 Token
            let mut new = RefreshToken::new(
                &stored_token.user_id,
                stored_token.family_id.clone(),
                self.config.expiration,
            )?;

            // 继承设备信息
            new.device_info = stored_token.device_info.clone();
            new.ip_address = stored_token.ip_address.clone();
            new.metadata = stored_token.metadata.clone();

            // 标记旧 Token 为已使用
            stored_token.mark_as_used(Some(new.token_id.clone()));
            self.store.update(&stored_token)?;

            // 保存新 Token
            self.store.save(&new)?;

            // 清理家族中的旧 Token
            self.enforce_max_tokens_per_family(&stored_token.family_id)?;

            Some(new)
        } else {
            // 不轮换，只标记为已使用
            stored_token.mark_as_used(None);
            self.store.update(&stored_token)?;
            None
        };

        Ok(TokenUseResult {
            new_token,
            user_id: stored_token.user_id,
            family_id: stored_token.family_id,
            was_in_grace_period: false,
        })
    }

    /// 验证 Token
    ///
    /// 只检查 Token 是否有效，不会使用或轮换 Token。
    pub fn validate(&self, token: &str) -> Result<RefreshToken> {
        let stored_token = self
            .store
            .get_by_token(token)?
            .ok_or_else(|| Error::Token(TokenError::InvalidFormat("token not found".into())))?;

        if stored_token.is_expired() {
            return Err(Error::Token(TokenError::Expired));
        }

        if stored_token.used && self.config.reuse_detection {
            return Err(Error::Token(TokenError::InvalidFormat(
                "token already used".into(),
            )));
        }

        Ok(stored_token)
    }

    /// 撤销 Token
    pub fn revoke(&self, token: &str) -> Result<()> {
        if let Some(stored) = self.store.get_by_token(token)? {
            self.store.delete(&stored.token_id)?;
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

    /// 获取用户的所有 Token
    pub fn get_user_tokens(&self, user_id: &str) -> Result<Vec<RefreshToken>> {
        self.store.get_by_user(user_id)
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

    /// 获取配置
    pub fn config(&self) -> &RefreshConfig {
        &self.config
    }

    // ========================================================================
    // 内部方法
    // ========================================================================

    /// 强制执行单用户最大 Token 家族数限制
    fn enforce_max_families(&self, user_id: &str) -> Result<()> {
        if self.config.max_families_per_user == 0 {
            return Ok(());
        }

        let tokens = self.store.get_by_user(user_id)?;

        // 收集所有家族 ID
        let mut families: HashMap<String, i64> = HashMap::new();
        for token in tokens {
            families
                .entry(token.family_id.clone())
                .or_insert(token.created_at);
        }

        // 如果超出限制，删除最旧的家族
        if families.len() >= self.config.max_families_per_user {
            if let Some((oldest_family, _)) = families.iter().min_by_key(|(_, created)| *created) {
                self.store.delete_family(oldest_family)?;
            }
        }

        Ok(())
    }

    /// 强制执行单家族最大 Token 数限制
    fn enforce_max_tokens_per_family(&self, family_id: &str) -> Result<()> {
        if self.config.max_tokens_per_family == 0 {
            return Ok(());
        }

        let mut tokens = self.store.get_by_family(family_id)?;

        // 按创建时间排序
        tokens.sort_by_key(|t| t.created_at);

        // 删除超出限制的旧 Token
        while tokens.len() > self.config.max_tokens_per_family {
            if let Some(oldest) = tokens.first() {
                self.store.delete(&oldest.token_id)?;
                tokens.remove(0);
            }
        }

        Ok(())
    }
}

// ============================================================================
// 生成选项
// ============================================================================

/// 生成 Refresh Token 的选项
#[derive(Debug, Clone, Default)]
pub struct GenerateOptions {
    /// 设备信息
    pub device_info: Option<String>,

    /// IP 地址
    pub ip_address: Option<String>,

    /// 初始元数据
    pub metadata: Option<serde_json::Value>,

    /// 指定家族 ID（用于在已有家族中生成新 Token）
    pub family_id: Option<String>,
}

impl GenerateOptions {
    /// 创建新的选项
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置设备信息
    pub fn with_device_info(mut self, info: impl Into<String>) -> Self {
        self.device_info = Some(info.into());
        self
    }

    /// 设置 IP 地址
    pub fn with_ip_address(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// 设置初始元数据
    pub fn with_metadata(mut self, metadata: serde_json::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// 设置初始元数据（从可序列化类型）
    pub fn with_metadata_from<T: Serialize>(mut self, data: T) -> Self {
        self.metadata = serde_json::to_value(data).ok();
        self
    }

    /// 设置家族 ID
    pub fn with_family_id(mut self, family_id: impl Into<String>) -> Self {
        self.family_id = Some(family_id.into());
        self
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_refresh_token_creation() {
        let token =
            RefreshToken::new("user123", "family1".to_string(), Duration::hours(1)).unwrap();

        assert!(!token.token.is_empty());
        assert!(!token.token_id.is_empty());
        assert_eq!(token.user_id, "user123");
        assert_eq!(token.family_id, "family1");
        assert!(!token.used);
        assert!(!token.is_expired());
        assert!(token.is_valid());
    }

    #[test]
    fn test_refresh_token_expiration() {
        let mut token =
            RefreshToken::new("user123", "family1".to_string(), Duration::hours(1)).unwrap();
        assert!(!token.is_expired());

        // 手动设置过期
        token.expires_at = Utc::now().timestamp() - 1;
        assert!(token.is_expired());
        assert!(!token.is_valid());
    }

    #[test]
    fn test_refresh_token_mark_as_used() {
        let mut token =
            RefreshToken::new("user123", "family1".to_string(), Duration::hours(1)).unwrap();
        assert!(token.is_valid());

        token.mark_as_used(Some("new_token_id".to_string()));

        assert!(token.used);
        assert!(token.used_at.is_some());
        assert_eq!(token.replaced_by, Some("new_token_id".to_string()));
        assert!(!token.is_valid());
    }

    #[test]
    fn test_refresh_token_metadata() {
        let mut token =
            RefreshToken::new("user123", "family1".to_string(), Duration::hours(1)).unwrap();

        // 设置元数据
        token.set_metadata("device", "iPhone");
        token.set_metadata("count", 42);
        token.set_metadata("tags", vec!["a", "b"]);

        // 获取元数据
        let device: Option<String> = token.get_metadata("device");
        assert_eq!(device, Some("iPhone".to_string()));

        let count: Option<i32> = token.get_metadata("count");
        assert_eq!(count, Some(42));

        // 检查存在性
        assert!(token.has_metadata("device"));
        assert!(!token.has_metadata("nonexistent"));

        // 删除元数据
        token.remove_metadata("device");
        assert!(!token.has_metadata("device"));
    }

    #[test]
    fn test_manager_generate() {
        let manager = RefreshTokenManager::new(RefreshConfig::default());
        let token = manager.generate("user123").unwrap();

        assert_eq!(token.user_id, "user123");
        assert!(!token.token.is_empty());
    }

    #[test]
    fn test_manager_use_token_with_rotation() {
        let config = RefreshConfig::default().with_rotation(true);
        let manager = RefreshTokenManager::new(config);

        let token = manager.generate("user123").unwrap();
        let result = manager.use_token(&token.token).unwrap();

        assert!(result.new_token.is_some());
        assert_eq!(result.user_id, "user123");

        // 原 token 应该失效
        assert!(manager.validate(&token.token).is_err());
    }

    #[test]
    fn test_manager_use_token_without_rotation() {
        let config = RefreshConfig::default().with_rotation(false);
        let manager = RefreshTokenManager::new(config);

        let token = manager.generate("user123").unwrap();
        let result = manager.use_token(&token.token).unwrap();

        assert!(result.new_token.is_none());
    }

    #[test]
    fn test_manager_reuse_detection() {
        let config = RefreshConfig::default()
            .with_rotation(true)
            .with_reuse_detection(true)
            .with_grace_period(Duration::seconds(0));
        let manager = RefreshTokenManager::new(config);

        let token = manager.generate("user123").unwrap();
        let token_str = token.token.clone();
        let family_id = token.family_id.clone();

        // 第一次使用
        let result = manager.use_token(&token_str).unwrap();
        assert!(result.new_token.is_some());
        let new_token = result.new_token.unwrap();

        // 尝试重用旧 token（应该触发重用检测）
        let reuse_result = manager.use_token(&token_str);
        assert!(reuse_result.is_err());

        // 整个家族应该被撤销
        assert!(manager.validate(&new_token.token).is_err());
        assert_eq!(manager.get_family_tokens(&family_id).unwrap().len(), 0);
    }

    #[test]
    fn test_manager_revoke() {
        let manager = RefreshTokenManager::new(RefreshConfig::default());
        let token = manager.generate("user123").unwrap();

        manager.revoke(&token.token).unwrap();
        assert!(manager.validate(&token.token).is_err());
    }

    #[test]
    fn test_manager_revoke_all_for_user() {
        let config = RefreshConfig::default().with_max_families_per_user(0);
        let manager = RefreshTokenManager::new(config);

        manager.generate("user123").unwrap();
        manager.generate("user123").unwrap();
        manager.generate("user456").unwrap();

        let count = manager.revoke_all_for_user("user123").unwrap();
        assert_eq!(count, 2);

        assert_eq!(manager.get_user_tokens("user123").unwrap().len(), 0);
        assert_eq!(manager.get_user_tokens("user456").unwrap().len(), 1);
    }

    #[test]
    fn test_manager_max_families() {
        let config = RefreshConfig::default().with_max_families_per_user(2);
        let manager = RefreshTokenManager::new(config);

        let t1 = manager.generate("user123").unwrap();
        let _t2 = manager.generate("user123").unwrap();
        let _t3 = manager.generate("user123").unwrap();

        // 最早的 token 应该被删除
        assert!(manager.validate(&t1.token).is_err());

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
        let manager = RefreshTokenManager::new(RefreshConfig::default());

        // 创建一个已过期的 token
        let mut token =
            RefreshToken::new("user123", "family1".to_string(), Duration::hours(1)).unwrap();
        token.expires_at = Utc::now().timestamp() - 100;
        manager.store.save(&token).unwrap();

        // 创建一个有效的 token
        manager.generate("user456").unwrap();

        let cleaned = manager.cleanup().unwrap();
        assert_eq!(cleaned, 1);
        assert_eq!(manager.count().unwrap(), 1);
    }

    #[test]
    fn test_config_presets() {
        let high_security = RefreshConfig::high_security();
        assert!(high_security.rotation_enabled);
        assert!(high_security.reuse_detection);
        assert_eq!(high_security.expiration.num_days(), 7);

        let relaxed = RefreshConfig::relaxed();
        assert!(!relaxed.rotation_enabled);
        assert!(!relaxed.reuse_detection);
    }

    #[test]
    fn test_generate_with_options() {
        let manager = RefreshTokenManager::new(RefreshConfig::default());

        let options = GenerateOptions::new()
            .with_device_info("iPhone 15")
            .with_ip_address("192.168.1.1");

        let token = manager.generate_with_options("user123", options).unwrap();

        assert_eq!(token.device_info, Some("iPhone 15".to_string()));
        assert_eq!(token.ip_address, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_token_time_to_live() {
        let token =
            RefreshToken::new("user123", "family1".to_string(), Duration::hours(1)).unwrap();
        let ttl = token.time_to_live();
        assert!(ttl > 3500 && ttl <= 3600);
    }

    #[test]
    fn test_in_memory_store() {
        let store = InMemoryRefreshTokenStore::new();

        let token =
            RefreshToken::new("user123", "family1".to_string(), Duration::hours(1)).unwrap();
        store.save(&token).unwrap();

        let retrieved = store.get_by_token(&token.token).unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, "user123");

        let by_id = store.get_by_id(&token.token_id).unwrap();
        assert!(by_id.is_some());

        store.delete(&token.token_id).unwrap();
        assert!(store.get_by_token(&token.token).unwrap().is_none());
    }

    #[test]
    fn test_token_rotation_inherits_metadata() {
        let manager = RefreshTokenManager::new(RefreshConfig::default().with_rotation(true));

        let mut token = manager.generate("user123").unwrap();
        token.set_metadata("custom_key", "custom_value");
        token.device_info = Some("TestDevice".to_string());
        manager.store.update(&token).unwrap();

        let result = manager.use_token(&token.token).unwrap();
        let new_token = result.new_token.unwrap();

        // 新 token 应该继承元数据和设备信息
        assert_eq!(new_token.device_info, Some("TestDevice".to_string()));
        let value: Option<String> = new_token.get_metadata("custom_key");
        assert_eq!(value, Some("custom_value".to_string()));
    }
}
