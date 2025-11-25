//! Session Token 实现模块
//!
//! 提供 Session 的创建、验证、存储和管理功能。
//!
//! ## 特性
//!
//! - 安全的 Session ID 生成
//! - 可插拔的存储后端（内存、Redis、数据库等）
//! - Session 过期管理
//! - 并发 Session 控制
//! - 灵活的元数据存储
//!
//! ## 示例
//!
//! ```rust
//! use authrs::token::session::{SessionManager, SessionConfig};
//! use std::time::Duration;
//!
//! // 使用默认配置创建 Session 管理器
//! let manager = SessionManager::new(SessionConfig::default());
//!
//! // 创建 Session
//! let session = manager.create("user123").unwrap();
//! println!("Session ID: {}", session.id);
//!
//! // 验证 Session
//! if let Some(session) = manager.get(&session.id) {
//!     println!("User: {}", session.user_id);
//! }
//!
//! // 销毁 Session
//! manager.destroy(&session.id);
//! ```
//!
//! ## 自定义存储后端
//!
//! 实现 `SessionStore` trait 可以使用自定义的存储后端：
//!
//! ```rust,ignore
//! use authrs::token::session::{Session, SessionStore, SessionManager, SessionConfig};
//! use authrs::error::Result;
//! use std::sync::Arc;
//!
//! struct RedisSessionStore {
//!     // Redis 连接
//! }
//!
//! impl SessionStore for RedisSessionStore {
//!     fn save(&self, session: &Session) -> Result<()> {
//!         // 保存到 Redis
//!         todo!()
//!     }
//!     // ... 实现其他方法
//! }
//!
//! // 使用自定义存储
//! let store = Arc::new(RedisSessionStore { /* ... */ });
//! let manager = SessionManager::with_store(SessionConfig::default(), store);
//! ```

use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::error::{Error, Result, StorageError};
use crate::random::generate_random_base64_url;

// ============================================================================
// Session 数据结构
// ============================================================================

/// Session 数据结构
///
/// 包含 Session 的核心字段和可扩展的元数据。
///
/// ## 核心字段
///
/// - `id`: Session 唯一标识符
/// - `user_id`: 关联的用户 ID
/// - `created_at`: 创建时间戳
/// - `expires_at`: 过期时间戳
///
/// ## 元数据
///
/// `metadata` 字段允许存储任意可序列化的数据：
///
/// ```rust
/// use authrs::token::session::{SessionManager, SessionConfig};
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct UserProfile {
///     name: String,
///     role: String,
/// }
///
/// let manager = SessionManager::new(SessionConfig::default());
/// let mut session = manager.create("user123").unwrap();
///
/// // 存储简单值
/// session.set_metadata("theme", "dark");
/// session.set_metadata("language", "zh-CN");
///
/// // 存储复杂结构
/// session.set_metadata("profile", UserProfile {
///     name: "张三".to_string(),
///     role: "admin".to_string(),
/// });
///
/// // 类型安全地读取
/// let theme: Option<String> = session.get_metadata("theme");
/// let profile: Option<UserProfile> = session.get_metadata("profile");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Session ID（唯一标识符）
    pub id: String,

    /// 关联的用户 ID
    pub user_id: String,

    /// 创建时间（Unix 时间戳，秒）
    pub created_at: i64,

    /// 最后访问时间（Unix 时间戳，秒）
    pub last_accessed_at: i64,

    /// 过期时间（Unix 时间戳，秒）
    pub expires_at: i64,

    /// 用户代理信息（可选）
    pub user_agent: Option<String>,

    /// IP 地址（可选）
    pub ip_address: Option<String>,

    /// 用户自定义元数据
    ///
    /// 可以存储任意可序列化的数据，使用 `set_metadata` 和 `get_metadata` 方法访问
    pub metadata: serde_json::Value,
}

impl Session {
    /// 创建新的 Session
    fn new(user_id: impl Into<String>, expires_in: Duration) -> Result<Self> {
        let now = Utc::now().timestamp();
        let session_id = generate_random_base64_url(32)?;

        Ok(Self {
            id: session_id,
            user_id: user_id.into(),
            created_at: now,
            last_accessed_at: now,
            expires_at: now + expires_in.num_seconds(),
            user_agent: None,
            ip_address: None,
            metadata: serde_json::Value::Object(serde_json::Map::new()),
        })
    }

    /// 检查 Session 是否已过期
    #[inline]
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() > self.expires_at
    }

    /// 检查 Session 是否有效（未过期）
    #[inline]
    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }

    /// 获取剩余有效时间（秒）
    ///
    /// 如果已过期，返回 0
    pub fn time_to_live(&self) -> i64 {
        (self.expires_at - Utc::now().timestamp()).max(0)
    }

    /// 更新最后访问时间为当前时间
    pub fn touch(&mut self) {
        self.last_accessed_at = Utc::now().timestamp();
    }

    /// 延长过期时间
    ///
    /// 将过期时间设置为当前时间 + 指定的持续时间
    pub fn extend(&mut self, duration: Duration) {
        self.expires_at = Utc::now().timestamp() + duration.num_seconds();
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
    /// use authrs::token::session::{SessionManager, SessionConfig};
    ///
    /// let manager = SessionManager::new(SessionConfig::default());
    /// let mut session = manager.create("user123").unwrap();
    ///
    /// // 存储字符串
    /// session.set_metadata("role", "admin");
    ///
    /// // 存储数字
    /// session.set_metadata("login_count", 42);
    ///
    /// // 存储数组
    /// session.set_metadata("permissions", vec!["read", "write"]);
    /// ```
    pub fn set_metadata<T: Serialize>(&mut self, key: impl Into<String>, value: T) {
        if let Ok(json_value) = serde_json::to_value(value)
            && let Some(obj) = self.metadata.as_object_mut()
        {
            obj.insert(key.into(), json_value);
        }
    }

    /// 获取元数据
    ///
    /// 类型安全地获取指定键的值。如果键不存在或类型不匹配，返回 `None`。
    ///
    /// # 示例
    ///
    /// ```rust
    /// use authrs::token::session::{SessionManager, SessionConfig};
    ///
    /// let manager = SessionManager::new(SessionConfig::default());
    /// let mut session = manager.create("user123").unwrap();
    ///
    /// session.set_metadata("role", "admin");
    /// session.set_metadata("login_count", 42);
    ///
    /// // 类型安全地获取
    /// let role: Option<String> = session.get_metadata("role");
    /// let count: Option<i32> = session.get_metadata("login_count");
    ///
    /// assert_eq!(role, Some("admin".to_string()));
    /// assert_eq!(count, Some(42));
    /// ```
    pub fn get_metadata<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.metadata
            .get(key)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// 获取元数据的原始 JSON 值
    ///
    /// 返回指定键的原始 `serde_json::Value`，不进行类型转换
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

    /// 合并元数据
    ///
    /// 将另一个 JSON 对象的所有键值对合并到当前元数据中。
    /// 如果键已存在，将被覆盖。
    pub fn merge_metadata(&mut self, other: serde_json::Value) {
        if let (Some(current), Some(other_obj)) = (self.metadata.as_object_mut(), other.as_object())
        {
            for (key, value) in other_obj {
                current.insert(key.clone(), value.clone());
            }
        }
    }
}

// ============================================================================
// Session 配置
// ============================================================================

/// Session 配置
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Session 有效期
    pub expiration: Duration,

    /// 是否在每次访问时刷新过期时间（滑动过期）
    pub sliding_expiration: bool,

    /// 单用户最大并发 Session 数（0 表示不限制）
    pub max_sessions_per_user: usize,

    /// Session ID 长度（字节数）
    pub id_length: usize,

    /// 是否验证 IP 地址
    pub validate_ip: bool,

    /// 是否验证 User-Agent
    pub validate_user_agent: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            expiration: Duration::hours(24),
            sliding_expiration: true,
            max_sessions_per_user: 5,
            id_length: 32,
            validate_ip: false,
            validate_user_agent: false,
        }
    }
}

impl SessionConfig {
    /// 创建新的配置
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置有效期
    pub fn with_expiration(mut self, duration: Duration) -> Self {
        self.expiration = duration;
        self
    }

    /// 设置是否启用滑动过期
    pub fn with_sliding_expiration(mut self, enabled: bool) -> Self {
        self.sliding_expiration = enabled;
        self
    }

    /// 设置单用户最大 Session 数
    pub fn with_max_sessions_per_user(mut self, max: usize) -> Self {
        self.max_sessions_per_user = max;
        self
    }

    /// 设置是否验证 IP 地址
    pub fn with_ip_validation(mut self, enabled: bool) -> Self {
        self.validate_ip = enabled;
        self
    }

    /// 设置是否验证 User-Agent
    pub fn with_user_agent_validation(mut self, enabled: bool) -> Self {
        self.validate_user_agent = enabled;
        self
    }

    /// 创建短期 Session 配置（1 小时）
    pub fn short_lived() -> Self {
        Self {
            expiration: Duration::hours(1),
            sliding_expiration: false,
            max_sessions_per_user: 10,
            ..Default::default()
        }
    }

    /// 创建长期 Session 配置（30 天）
    pub fn long_lived() -> Self {
        Self {
            expiration: Duration::days(30),
            sliding_expiration: true,
            max_sessions_per_user: 3,
            ..Default::default()
        }
    }
}

// ============================================================================
// Session 存储 Trait
// ============================================================================

/// Session 存储 trait
///
/// 实现此 trait 可以自定义 Session 的存储后端。
///
/// ## 内置实现
///
/// - `InMemorySessionStore`: 内存存储，适用于开发和测试
///
/// ## 自定义实现示例
///
/// ```rust,ignore
/// use authrs::token::session::{Session, SessionStore};
/// use authrs::error::Result;
///
/// struct PostgresSessionStore {
///     pool: sqlx::PgPool,
/// }
///
/// impl SessionStore for PostgresSessionStore {
///     fn save(&self, session: &Session) -> Result<()> {
///         // INSERT INTO sessions ...
///         todo!()
///     }
///
///     fn get(&self, session_id: &str) -> Result<Option<Session>> {
///         // SELECT * FROM sessions WHERE id = ?
///         todo!()
///     }
///
///     // ... 实现其他方法
/// }
/// ```
pub trait SessionStore: Send + Sync {
    /// 保存 Session
    fn save(&self, session: &Session) -> Result<()>;

    /// 获取 Session
    fn get(&self, session_id: &str) -> Result<Option<Session>>;

    /// 更新 Session
    fn update(&self, session: &Session) -> Result<()>;

    /// 删除 Session
    fn delete(&self, session_id: &str) -> Result<()>;

    /// 获取用户的所有 Session
    fn get_by_user(&self, user_id: &str) -> Result<Vec<Session>>;

    /// 删除用户的所有 Session
    ///
    /// 返回删除的 Session 数量
    fn delete_by_user(&self, user_id: &str) -> Result<usize>;

    /// 清理过期的 Session
    ///
    /// 返回清理的 Session 数量
    fn cleanup_expired(&self) -> Result<usize>;

    /// 获取 Session 总数
    fn count(&self) -> Result<usize>;
}

// ============================================================================
// 内存存储实现
// ============================================================================

/// 内存 Session 存储
///
/// 用于开发和测试，生产环境建议使用 Redis 等持久化存储。
///
/// ## 特点
///
/// - 线程安全（使用 `RwLock`）
/// - 无持久化，重启后数据丢失
/// - 适合单实例部署的开发环境
///
/// ## 示例
///
/// ```rust
/// use authrs::token::session::{InMemorySessionStore, SessionStore, Session};
/// use std::sync::Arc;
///
/// let store = InMemorySessionStore::new();
/// // 使用 store...
/// ```
#[derive(Debug, Default)]
pub struct InMemorySessionStore {
    sessions: RwLock<HashMap<String, Session>>,
}

impl InMemorySessionStore {
    /// 创建新的内存存储
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionStore for InMemorySessionStore {
    fn save(&self, session: &Session) -> Result<()> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;
        sessions.insert(session.id.clone(), session.clone());
        Ok(())
    }

    fn get(&self, session_id: &str) -> Result<Option<Session>> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;
        Ok(sessions.get(session_id).cloned())
    }

    fn update(&self, session: &Session) -> Result<()> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;

        if sessions.contains_key(&session.id) {
            sessions.insert(session.id.clone(), session.clone());
            Ok(())
        } else {
            Err(Error::Storage(StorageError::NotFound(format!(
                "session {}",
                session.id
            ))))
        }
    }

    fn delete(&self, session_id: &str) -> Result<()> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;
        sessions.remove(session_id);
        Ok(())
    }

    fn get_by_user(&self, user_id: &str) -> Result<Vec<Session>> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;

        Ok(sessions
            .values()
            .filter(|s| s.user_id == user_id)
            .cloned()
            .collect())
    }

    fn delete_by_user(&self, user_id: &str) -> Result<usize> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;

        let to_delete: Vec<String> = sessions
            .iter()
            .filter(|(_, s)| s.user_id == user_id)
            .map(|(id, _)| id.clone())
            .collect();

        let count = to_delete.len();
        for id in to_delete {
            sessions.remove(&id);
        }

        Ok(count)
    }

    fn cleanup_expired(&self) -> Result<usize> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;

        let now = Utc::now().timestamp();
        let to_delete: Vec<String> = sessions
            .iter()
            .filter(|(_, s)| s.expires_at < now)
            .map(|(id, _)| id.clone())
            .collect();

        let count = to_delete.len();
        for id in to_delete {
            sessions.remove(&id);
        }

        Ok(count)
    }

    fn count(&self) -> Result<usize> {
        let sessions = self
            .sessions
            .read()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;
        Ok(sessions.len())
    }
}

// ============================================================================
// Session 管理器
// ============================================================================

/// Session 管理器
///
/// 提供 Session 的完整生命周期管理，包括创建、验证、刷新和销毁。
///
/// ## 示例
///
/// ```rust
/// use authrs::token::session::{SessionManager, SessionConfig, CreateSessionOptions};
///
/// let manager = SessionManager::new(SessionConfig::default());
///
/// // 创建 Session
/// let session = manager.create("user123").unwrap();
///
/// // 带元数据创建 Session
/// let options = CreateSessionOptions::new()
///     .with_user_agent("Mozilla/5.0 ...")
///     .with_ip_address("192.168.1.1");
/// let session = manager.create_with_options("user123", options).unwrap();
///
/// // 验证 Session
/// if manager.validate(&session.id, None, None).is_ok() {
///     println!("Session 有效");
/// }
///
/// // 销毁 Session
/// manager.destroy(&session.id);
/// ```
pub struct SessionManager {
    store: Arc<dyn SessionStore>,
    config: SessionConfig,
}

impl SessionManager {
    /// 使用默认内存存储创建 Session 管理器
    pub fn new(config: SessionConfig) -> Self {
        Self {
            store: Arc::new(InMemorySessionStore::new()),
            config,
        }
    }

    /// 使用自定义存储创建 Session 管理器
    pub fn with_store(config: SessionConfig, store: Arc<dyn SessionStore>) -> Self {
        Self { store, config }
    }

    /// 创建新的 Session
    ///
    /// # 参数
    ///
    /// * `user_id` - 用户 ID
    ///
    /// # 返回
    ///
    /// 返回创建的 Session
    pub fn create(&self, user_id: impl Into<String>) -> Result<Session> {
        let user_id = user_id.into();
        self.enforce_max_sessions(&user_id)?;

        let session = Session::new(&user_id, self.config.expiration)?;
        self.store.save(&session)?;

        Ok(session)
    }

    /// 使用选项创建 Session
    ///
    /// 允许设置 User-Agent、IP 地址和初始元数据。
    pub fn create_with_options(
        &self,
        user_id: impl Into<String>,
        options: CreateSessionOptions,
    ) -> Result<Session> {
        let user_id = user_id.into();
        self.enforce_max_sessions(&user_id)?;

        let expiration = options.custom_expiration.unwrap_or(self.config.expiration);

        let mut session = Session::new(&user_id, expiration)?;
        session.user_agent = options.user_agent;
        session.ip_address = options.ip_address;

        if let Some(metadata) = options.metadata {
            session.metadata = metadata;
        }

        self.store.save(&session)?;

        Ok(session)
    }

    /// 获取 Session
    ///
    /// 如果启用了滑动过期，会自动更新最后访问时间和过期时间。
    pub fn get(&self, session_id: &str) -> Option<Session> {
        let session = self.store.get(session_id).ok()??;

        if session.is_expired() {
            let _ = self.store.delete(session_id);
            return None;
        }

        // 如果启用滑动过期，更新访问时间
        if self.config.sliding_expiration {
            let mut updated = session.clone();
            updated.touch();
            updated.extend(self.config.expiration);
            let _ = self.store.update(&updated);
            return Some(updated);
        }

        Some(session)
    }

    /// 验证 Session
    ///
    /// # 参数
    ///
    /// * `session_id` - Session ID
    /// * `ip_address` - 可选的 IP 地址（用于验证）
    /// * `user_agent` - 可选的 User-Agent（用于验证）
    ///
    /// # 返回
    ///
    /// 如果验证成功返回 Session，否则返回错误
    pub fn validate(
        &self,
        session_id: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Session> {
        let session = self
            .store
            .get(session_id)?
            .ok_or_else(|| Error::Storage(StorageError::NotFound("session".into())))?;

        // 检查过期
        if session.is_expired() {
            self.store.delete(session_id)?;
            return Err(Error::validation("session expired"));
        }

        // 验证 IP 地址
        if self.config.validate_ip
            && let (Some(stored_ip), Some(request_ip)) = (&session.ip_address, ip_address)
            && stored_ip != request_ip
        {
            return Err(Error::validation("IP address mismatch"));
        }

        // 验证 User-Agent
        if self.config.validate_user_agent
            && let (Some(stored_ua), Some(request_ua)) = (&session.user_agent, user_agent)
            && stored_ua != request_ua
        {
            return Err(Error::validation("User-Agent mismatch"));
        }

        Ok(session)
    }

    /// 更新 Session
    pub fn update(&self, session: &Session) -> Result<()> {
        self.store.update(session)
    }

    /// 销毁 Session
    pub fn destroy(&self, session_id: &str) -> Result<()> {
        self.store.delete(session_id)
    }

    /// 销毁用户的所有 Session
    ///
    /// 返回销毁的 Session 数量
    pub fn destroy_all_for_user(&self, user_id: &str) -> Result<usize> {
        self.store.delete_by_user(user_id)
    }

    /// 获取用户的所有 Session
    pub fn get_user_sessions(&self, user_id: &str) -> Result<Vec<Session>> {
        self.store.get_by_user(user_id)
    }

    /// 清理过期的 Session
    pub fn cleanup(&self) -> Result<usize> {
        self.store.cleanup_expired()
    }

    /// 获取 Session 总数
    pub fn count(&self) -> Result<usize> {
        self.store.count()
    }

    /// 刷新 Session
    ///
    /// 更新最后访问时间并延长过期时间
    pub fn refresh(&self, session_id: &str) -> Result<Session> {
        let mut session = self
            .store
            .get(session_id)?
            .ok_or_else(|| Error::Storage(StorageError::NotFound("session".into())))?;

        if session.is_expired() {
            self.store.delete(session_id)?;
            return Err(Error::validation("session expired"));
        }

        session.touch();
        session.extend(self.config.expiration);
        self.store.update(&session)?;

        Ok(session)
    }

    /// 获取配置
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    // ========================================================================
    // 内部方法
    // ========================================================================

    /// 强制执行单用户最大 Session 数限制
    fn enforce_max_sessions(&self, user_id: &str) -> Result<()> {
        if self.config.max_sessions_per_user == 0 {
            return Ok(());
        }

        let sessions = self.store.get_by_user(user_id)?;
        if sessions.len() >= self.config.max_sessions_per_user {
            // 删除最早创建的 Session
            if let Some(oldest) = sessions.iter().min_by_key(|s| s.created_at) {
                self.store.delete(&oldest.id)?;
            }
        }

        Ok(())
    }
}

// ============================================================================
// 创建 Session 选项
// ============================================================================

/// 创建 Session 的选项
#[derive(Debug, Clone, Default)]
pub struct CreateSessionOptions {
    /// User-Agent
    pub user_agent: Option<String>,

    /// IP 地址
    pub ip_address: Option<String>,

    /// 初始元数据
    pub metadata: Option<serde_json::Value>,

    /// 自定义过期时间
    pub custom_expiration: Option<Duration>,
}

impl CreateSessionOptions {
    /// 创建新的选项
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置 User-Agent
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
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

    /// 设置自定义过期时间
    pub fn with_expiration(mut self, duration: Duration) -> Self {
        self.custom_expiration = Some(duration);
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
    fn test_session_creation() {
        let session = Session::new("user123", Duration::hours(1)).unwrap();
        assert_eq!(session.user_id, "user123");
        assert!(!session.is_expired());
        assert!(session.is_valid());
    }

    #[test]
    fn test_session_expiration() {
        let mut session = Session::new("user123", Duration::seconds(-1)).unwrap();
        session.expires_at = Utc::now().timestamp() - 1;
        assert!(session.is_expired());
        assert!(!session.is_valid());
    }

    #[test]
    fn test_session_metadata() {
        let mut session = Session::new("user123", Duration::hours(1)).unwrap();

        // 设置字符串
        session.set_metadata("role", "admin");
        let role: Option<String> = session.get_metadata("role");
        assert_eq!(role, Some("admin".to_string()));

        // 设置数字
        session.set_metadata("count", 42);
        let count: Option<i32> = session.get_metadata("count");
        assert_eq!(count, Some(42));

        // 设置数组
        session.set_metadata("tags", vec!["a", "b", "c"]);
        let tags: Option<Vec<String>> = session.get_metadata("tags");
        assert_eq!(
            tags,
            Some(vec!["a".to_string(), "b".to_string(), "c".to_string()])
        );

        // 检查键存在
        assert!(session.has_metadata("role"));
        assert!(!session.has_metadata("nonexistent"));

        // 删除元数据
        session.remove_metadata("role");
        assert!(!session.has_metadata("role"));

        // 获取所有键
        let keys = session.metadata_keys();
        assert!(keys.contains(&"count"));
        assert!(keys.contains(&"tags"));
    }

    #[test]
    fn test_session_metadata_complex_types() {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        struct UserProfile {
            name: String,
            age: u32,
        }

        let mut session = Session::new("user123", Duration::hours(1)).unwrap();

        let profile = UserProfile {
            name: "张三".to_string(),
            age: 30,
        };
        session.set_metadata("profile", profile.clone());

        let retrieved: Option<UserProfile> = session.get_metadata("profile");
        assert_eq!(retrieved, Some(profile));
    }

    #[test]
    fn test_session_manager_create() {
        let manager = SessionManager::new(SessionConfig::default());
        let session = manager.create("user123").unwrap();
        assert_eq!(session.user_id, "user123");
    }

    #[test]
    fn test_session_manager_get() {
        let manager = SessionManager::new(SessionConfig::default());
        let session = manager.create("user123").unwrap();

        let retrieved = manager.get(&session.id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, "user123");
    }

    #[test]
    fn test_session_manager_destroy() {
        let manager = SessionManager::new(SessionConfig::default());
        let session = manager.create("user123").unwrap();

        manager.destroy(&session.id).unwrap();
        assert!(manager.get(&session.id).is_none());
    }

    #[test]
    fn test_session_manager_destroy_all_for_user() {
        let config = SessionConfig::default().with_max_sessions_per_user(0);
        let manager = SessionManager::new(config);

        manager.create("user123").unwrap();
        manager.create("user123").unwrap();
        manager.create("user456").unwrap();

        let count = manager.destroy_all_for_user("user123").unwrap();
        assert_eq!(count, 2);

        let remaining = manager.get_user_sessions("user123").unwrap();
        assert!(remaining.is_empty());
    }

    #[test]
    fn test_session_manager_max_sessions() {
        let config = SessionConfig::default().with_max_sessions_per_user(2);
        let manager = SessionManager::new(config);

        let s1 = manager.create("user123").unwrap();
        let s2 = manager.create("user123").unwrap();
        let s3 = manager.create("user123").unwrap();

        // 应该只有 2 个 session
        let sessions = manager.get_user_sessions("user123").unwrap();
        assert_eq!(sessions.len(), 2);

        // 最早的 session 应该被删除（s1）
        // 注意：由于时间戳可能相同，我们只验证数量正确
        let session_ids: Vec<_> = sessions.iter().map(|s| s.id.clone()).collect();
        // 至少 s3 应该存在（最新创建的）
        assert!(session_ids.contains(&s3.id));
        // s2 或 s1 中应该有一个被删除
        let deleted_count = [&s1.id, &s2.id]
            .iter()
            .filter(|id| !session_ids.contains(*id))
            .count();
        assert_eq!(deleted_count, 1);
    }

    #[test]
    fn test_session_manager_sliding_expiration() {
        let config = SessionConfig::default()
            .with_expiration(Duration::hours(1))
            .with_sliding_expiration(true);
        let manager = SessionManager::new(config);

        let session = manager.create("user123").unwrap();
        let original_expires = session.expires_at;

        // 等待一小段时间后获取 session
        std::thread::sleep(std::time::Duration::from_millis(10));

        let retrieved = manager.get(&session.id).unwrap();
        // 过期时间应该被更新
        assert!(retrieved.expires_at >= original_expires);
    }

    #[test]
    fn test_session_manager_validate() {
        let config = SessionConfig::default()
            .with_ip_validation(true)
            .with_user_agent_validation(true);
        let manager = SessionManager::new(config);

        let options = CreateSessionOptions::new()
            .with_ip_address("192.168.1.1")
            .with_user_agent("TestBrowser");
        let session = manager.create_with_options("user123", options).unwrap();

        // 正确的 IP 和 UA 应该通过验证
        assert!(
            manager
                .validate(&session.id, Some("192.168.1.1"), Some("TestBrowser"))
                .is_ok()
        );

        // 错误的 IP 应该失败
        assert!(
            manager
                .validate(&session.id, Some("10.0.0.1"), Some("TestBrowser"))
                .is_err()
        );
    }

    #[test]
    fn test_session_cleanup() {
        let manager = SessionManager::new(SessionConfig::default());

        // 创建一个已过期的 session
        let mut session = Session::new("user123", Duration::hours(1)).unwrap();
        session.expires_at = Utc::now().timestamp() - 100;
        manager.store.save(&session).unwrap();

        // 创建一个有效的 session
        manager.create("user456").unwrap();

        let cleaned = manager.cleanup().unwrap();
        assert_eq!(cleaned, 1);
        assert_eq!(manager.count().unwrap(), 1);
    }

    #[test]
    fn test_in_memory_store() {
        let store = InMemorySessionStore::new();

        let session = Session::new("user123", Duration::hours(1)).unwrap();
        store.save(&session).unwrap();

        let retrieved = store.get(&session.id).unwrap();
        assert!(retrieved.is_some());

        store.delete(&session.id).unwrap();
        let retrieved = store.get(&session.id).unwrap();
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_session_time_to_live() {
        let session = Session::new("user123", Duration::hours(1)).unwrap();
        let ttl = session.time_to_live();
        assert!(ttl > 3500 && ttl <= 3600);
    }

    #[test]
    fn test_session_touch() {
        let mut session = Session::new("user123", Duration::hours(1)).unwrap();
        let original_accessed = session.last_accessed_at;

        std::thread::sleep(std::time::Duration::from_millis(10));
        session.touch();

        assert!(session.last_accessed_at >= original_accessed);
    }

    #[test]
    fn test_create_session_options() {
        let options = CreateSessionOptions::new()
            .with_user_agent("Mozilla/5.0")
            .with_ip_address("192.168.1.1")
            .with_expiration(Duration::hours(2));

        assert_eq!(options.user_agent, Some("Mozilla/5.0".to_string()));
        assert_eq!(options.ip_address, Some("192.168.1.1".to_string()));
        assert!(options.custom_expiration.is_some());
    }

    #[test]
    fn test_session_config_presets() {
        let short = SessionConfig::short_lived();
        assert_eq!(short.expiration, Duration::hours(1));
        assert!(!short.sliding_expiration);

        let long = SessionConfig::long_lived();
        assert_eq!(long.expiration, Duration::days(30));
        assert!(long.sliding_expiration);
    }

    #[test]
    fn test_refresh_session() {
        let manager = SessionManager::new(SessionConfig::default());
        let session = manager.create("user123").unwrap();

        std::thread::sleep(std::time::Duration::from_millis(10));

        let refreshed = manager.refresh(&session.id).unwrap();
        assert!(refreshed.last_accessed_at >= session.last_accessed_at);
    }

    #[test]
    fn test_session_clear_metadata() {
        let mut session = Session::new("user123", Duration::hours(1)).unwrap();
        session.set_metadata("key1", "value1");
        session.set_metadata("key2", "value2");

        assert!(session.has_metadata("key1"));
        session.clear_metadata();
        assert!(!session.has_metadata("key1"));
        assert!(session.metadata_keys().is_empty());
    }

    #[test]
    fn test_session_merge_metadata() {
        let mut session = Session::new("user123", Duration::hours(1)).unwrap();
        session.set_metadata("existing", "value");

        let additional = serde_json::json!({
            "new_key": "new_value",
            "another": 123
        });
        session.merge_metadata(additional);

        assert_eq!(
            session.get_metadata::<String>("existing"),
            Some("value".to_string())
        );
        assert_eq!(
            session.get_metadata::<String>("new_key"),
            Some("new_value".to_string())
        );
        assert_eq!(session.get_metadata::<i32>("another"), Some(123));
    }
}
