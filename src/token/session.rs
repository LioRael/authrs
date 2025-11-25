//! Session Token 实现模块
//!
//! 提供 Session 的创建、验证、存储和管理功能。
//!
//! ## 特性
//!
//! - 安全的 Session ID 生成
//! - 可插拔的存储后端（内存、自定义实现）
//! - Session 过期管理
//! - 并发 Session 控制
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

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::error::{Error, Result, StorageError};
use crate::random::generate_random_base64_url;

/// Session 数据结构
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Session ID（唯一标识符）
    pub id: String,

    /// 关联的用户 ID
    pub user_id: String,

    /// 创建时间
    pub created_at: DateTime<Utc>,

    /// 最后访问时间
    pub last_accessed_at: DateTime<Utc>,

    /// 过期时间
    pub expires_at: DateTime<Utc>,

    /// 用户代理信息
    pub user_agent: Option<String>,

    /// IP 地址
    pub ip_address: Option<String>,

    /// 自定义数据
    pub data: HashMap<String, serde_json::Value>,
}

impl Session {
    /// 创建新的 Session
    fn new(user_id: impl Into<String>, expires_in: Duration) -> Result<Self> {
        let now = Utc::now();
        let session_id = generate_random_base64_url(32)?;

        Ok(Self {
            id: session_id,
            user_id: user_id.into(),
            created_at: now,
            last_accessed_at: now,
            expires_at: now + expires_in,
            user_agent: None,
            ip_address: None,
            data: HashMap::new(),
        })
    }

    /// 检查 Session 是否已过期
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// 检查 Session 是否有效
    pub fn is_valid(&self) -> bool {
        !self.is_expired()
    }

    /// 获取剩余有效时间（秒）
    pub fn time_to_live(&self) -> i64 {
        let remaining = self.expires_at - Utc::now();
        remaining.num_seconds().max(0)
    }

    /// 更新最后访问时间
    pub fn touch(&mut self) {
        self.last_accessed_at = Utc::now();
    }

    /// 延长过期时间
    pub fn extend(&mut self, duration: Duration) {
        self.expires_at = Utc::now() + duration;
    }

    /// 设置自定义数据
    pub fn set_data<V: Serialize>(&mut self, key: impl Into<String>, value: V) {
        if let Ok(json_value) = serde_json::to_value(value) {
            self.data.insert(key.into(), json_value);
        }
    }

    /// 获取自定义数据
    pub fn get_data<V: serde::de::DeserializeOwned>(&self, key: &str) -> Option<V> {
        self.data
            .get(key)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// 删除自定义数据
    pub fn remove_data(&mut self, key: &str) -> Option<serde_json::Value> {
        self.data.remove(key)
    }
}

/// Session 配置
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Session 有效期
    pub expiration: Duration,

    /// 是否在每次访问时刷新过期时间
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

/// Session 存储 trait
///
/// 实现此 trait 可以自定义 Session 的存储后端
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
    fn delete_by_user(&self, user_id: &str) -> Result<usize>;

    /// 清理过期的 Session
    fn cleanup_expired(&self) -> Result<usize>;

    /// 获取 Session 总数
    fn count(&self) -> Result<usize>;
}

/// 内存 Session 存储
///
/// 用于开发和测试，生产环境建议使用 Redis 等持久化存储
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

        let to_remove: Vec<String> = sessions
            .iter()
            .filter(|(_, s)| s.user_id == user_id)
            .map(|(id, _)| id.clone())
            .collect();

        let count = to_remove.len();
        for id in to_remove {
            sessions.remove(&id);
        }

        Ok(count)
    }

    fn cleanup_expired(&self) -> Result<usize> {
        let mut sessions = self
            .sessions
            .write()
            .map_err(|_| Error::Storage(StorageError::OperationFailed("lock poisoned".into())))?;

        let to_remove: Vec<String> = sessions
            .iter()
            .filter(|(_, s)| s.is_expired())
            .map(|(id, _)| id.clone())
            .collect();

        let count = to_remove.len();
        for id in to_remove {
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

/// Session 管理器
///
/// 提供 Session 的完整生命周期管理
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
    /// * `user_id` - 关联的用户 ID
    ///
    /// # 返回
    ///
    /// 返回新创建的 Session
    pub fn create(&self, user_id: impl Into<String>) -> Result<Session> {
        let user_id = user_id.into();

        // 检查并清理超出限制的 Session
        if self.config.max_sessions_per_user > 0 {
            self.enforce_max_sessions(&user_id)?;
        }

        let session = Session::new(&user_id, self.config.expiration)?;
        self.store.save(&session)?;

        Ok(session)
    }

    /// 创建带有元信息的 Session
    ///
    /// # 参数
    ///
    /// * `user_id` - 关联的用户 ID
    /// * `user_agent` - 用户代理字符串
    /// * `ip_address` - IP 地址
    pub fn create_with_metadata(
        &self,
        user_id: impl Into<String>,
        user_agent: Option<String>,
        ip_address: Option<String>,
    ) -> Result<Session> {
        let user_id = user_id.into();

        // 检查并清理超出限制的 Session
        if self.config.max_sessions_per_user > 0 {
            self.enforce_max_sessions(&user_id)?;
        }

        let mut session = Session::new(&user_id, self.config.expiration)?;
        session.user_agent = user_agent;
        session.ip_address = ip_address;

        self.store.save(&session)?;

        Ok(session)
    }

    /// 获取 Session
    ///
    /// 如果启用了滑动过期，会自动刷新过期时间
    pub fn get(&self, session_id: &str) -> Option<Session> {
        match self.store.get(session_id) {
            Ok(Some(mut session)) => {
                if session.is_expired() {
                    let _ = self.store.delete(session_id);
                    return None;
                }

                if self.config.sliding_expiration {
                    session.touch();
                    session.extend(self.config.expiration);
                    let _ = self.store.update(&session);
                }

                Some(session)
            }
            _ => None,
        }
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
    /// 如果验证成功，返回 Session
    pub fn validate(
        &self,
        session_id: &str,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<Session> {
        let session = self
            .get(session_id)
            .ok_or_else(|| Error::Storage(StorageError::NotFound("session not found".into())))?;

        // 验证 IP 地址
        if self.config.validate_ip {
            if let (Some(stored_ip), Some(request_ip)) = (&session.ip_address, ip_address) {
                if stored_ip != request_ip {
                    return Err(Error::Storage(StorageError::OperationFailed(
                        "IP address mismatch".into(),
                    )));
                }
            }
        }

        // 验证 User-Agent
        if self.config.validate_user_agent {
            if let (Some(stored_ua), Some(request_ua)) = (&session.user_agent, user_agent) {
                if stored_ua != request_ua {
                    return Err(Error::Storage(StorageError::OperationFailed(
                        "User-Agent mismatch".into(),
                    )));
                }
            }
        }

        Ok(session)
    }

    /// 更新 Session 数据
    pub fn update(&self, session: &Session) -> Result<()> {
        self.store.update(session)
    }

    /// 销毁 Session
    pub fn destroy(&self, session_id: &str) -> Result<()> {
        self.store.delete(session_id)
    }

    /// 销毁用户的所有 Session
    ///
    /// 常用于密码修改、登出所有设备等场景
    pub fn destroy_all_for_user(&self, user_id: &str) -> Result<usize> {
        self.store.delete_by_user(user_id)
    }

    /// 获取用户的所有活跃 Session
    pub fn get_user_sessions(&self, user_id: &str) -> Result<Vec<Session>> {
        let sessions = self.store.get_by_user(user_id)?;
        Ok(sessions.into_iter().filter(|s| !s.is_expired()).collect())
    }

    /// 清理过期的 Session
    pub fn cleanup(&self) -> Result<usize> {
        self.store.cleanup_expired()
    }

    /// 获取 Session 总数
    pub fn count(&self) -> Result<usize> {
        self.store.count()
    }

    /// 刷新 Session 过期时间
    pub fn refresh(&self, session_id: &str) -> Result<Session> {
        let mut session = self
            .store
            .get(session_id)?
            .ok_or_else(|| Error::Storage(StorageError::NotFound("session not found".into())))?;

        if session.is_expired() {
            self.store.delete(session_id)?;
            return Err(Error::Storage(StorageError::NotFound(
                "session expired".into(),
            )));
        }

        session.touch();
        session.extend(self.config.expiration);
        self.store.update(&session)?;

        Ok(session)
    }

    /// 强制执行最大 Session 数限制
    fn enforce_max_sessions(&self, user_id: &str) -> Result<()> {
        let sessions = self.store.get_by_user(user_id)?;
        let active_sessions: Vec<_> = sessions.into_iter().filter(|s| !s.is_expired()).collect();

        if active_sessions.len() >= self.config.max_sessions_per_user {
            // 删除最旧的 Session
            if let Some(oldest) = active_sessions.iter().min_by_key(|s| s.created_at) {
                self.store.delete(&oldest.id)?;
            }
        }

        Ok(())
    }
}

/// Session 创建选项
#[derive(Debug, Clone, Default)]
pub struct CreateSessionOptions {
    /// 用户代理
    pub user_agent: Option<String>,
    /// IP 地址
    pub ip_address: Option<String>,
    /// 初始数据
    pub data: HashMap<String, serde_json::Value>,
    /// 自定义过期时间
    pub custom_expiration: Option<Duration>,
}

impl CreateSessionOptions {
    /// 创建新的选项
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置用户代理
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// 设置 IP 地址
    pub fn with_ip_address(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// 设置初始数据
    pub fn with_data<V: Serialize>(mut self, key: impl Into<String>, value: V) -> Self {
        if let Ok(json_value) = serde_json::to_value(value) {
            self.data.insert(key.into(), json_value);
        }
        self
    }

    /// 设置自定义过期时间
    pub fn with_expiration(mut self, duration: Duration) -> Self {
        self.custom_expiration = Some(duration);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_creation() {
        let session = Session::new("user123", Duration::hours(1)).unwrap();

        assert!(!session.id.is_empty());
        assert_eq!(session.user_id, "user123");
        assert!(!session.is_expired());
    }

    #[test]
    fn test_session_expiration() {
        let mut session = Session::new("user123", Duration::seconds(-10)).unwrap();
        assert!(session.is_expired());

        session.extend(Duration::hours(1));
        assert!(!session.is_expired());
    }

    #[test]
    fn test_session_data() {
        let mut session = Session::new("user123", Duration::hours(1)).unwrap();

        session.set_data("role", "admin");
        session.set_data("permissions", vec!["read", "write"]);

        let role: Option<String> = session.get_data("role");
        assert_eq!(role, Some("admin".to_string()));

        let permissions: Option<Vec<String>> = session.get_data("permissions");
        assert_eq!(
            permissions,
            Some(vec!["read".to_string(), "write".to_string()])
        );
    }

    #[test]
    fn test_session_manager_create() {
        let manager = SessionManager::new(SessionConfig::default());
        let session = manager.create("user123").unwrap();

        assert_eq!(session.user_id, "user123");
        assert!(!session.is_expired());
    }

    #[test]
    fn test_session_manager_get() {
        let manager = SessionManager::new(SessionConfig::default());
        let session = manager.create("user123").unwrap();
        let session_id = session.id.clone();

        let retrieved = manager.get(&session_id);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().user_id, "user123");
    }

    #[test]
    fn test_session_manager_destroy() {
        let manager = SessionManager::new(SessionConfig::default());
        let session = manager.create("user123").unwrap();
        let session_id = session.id.clone();

        manager.destroy(&session_id).unwrap();
        assert!(manager.get(&session_id).is_none());
    }

    #[test]
    fn test_session_manager_destroy_all_for_user() {
        let manager = SessionManager::new(
            SessionConfig::default().with_max_sessions_per_user(10), // 增加限制以便测试
        );

        // 创建多个 Session
        manager.create("user123").unwrap();
        manager.create("user123").unwrap();
        manager.create("user456").unwrap();

        // 销毁 user123 的所有 Session
        let deleted = manager.destroy_all_for_user("user123").unwrap();
        assert_eq!(deleted, 2);

        // user456 的 Session 应该还在
        let user456_sessions = manager.get_user_sessions("user456").unwrap();
        assert_eq!(user456_sessions.len(), 1);
    }

    #[test]
    fn test_session_manager_max_sessions() {
        let config = SessionConfig::default().with_max_sessions_per_user(2);
        let manager = SessionManager::new(config);

        let session1 = manager.create("user123").unwrap();
        let _session2 = manager.create("user123").unwrap();
        let _session3 = manager.create("user123").unwrap();

        // session1 应该被清理了
        assert!(manager.get(&session1.id).is_none());

        // 用户应该只有 2 个 Session
        let sessions = manager.get_user_sessions("user123").unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn test_session_manager_sliding_expiration() {
        let config = SessionConfig::default()
            .with_expiration(Duration::hours(1))
            .with_sliding_expiration(true);

        let manager = SessionManager::new(config);
        let session = manager.create("user123").unwrap();
        let original_expires = session.expires_at;

        // 等待一小段时间
        std::thread::sleep(std::time::Duration::from_millis(10));

        // 获取 Session 应该刷新过期时间
        let retrieved = manager.get(&session.id).unwrap();
        assert!(retrieved.expires_at >= original_expires);
    }

    #[test]
    fn test_session_manager_validate() {
        let config = SessionConfig::default()
            .with_ip_validation(true)
            .with_user_agent_validation(true);

        let manager = SessionManager::new(config);
        let session = manager
            .create_with_metadata(
                "user123",
                Some("Mozilla/5.0".to_string()),
                Some("192.168.1.1".to_string()),
            )
            .unwrap();

        // 正确的验证
        let result = manager.validate(&session.id, Some("192.168.1.1"), Some("Mozilla/5.0"));
        assert!(result.is_ok());

        // 错误的 IP
        let result = manager.validate(&session.id, Some("192.168.1.2"), Some("Mozilla/5.0"));
        assert!(result.is_err());
    }

    #[test]
    fn test_session_cleanup() {
        let config = SessionConfig::default().with_expiration(Duration::seconds(-1));
        let manager = SessionManager::new(config);

        // 创建已过期的 Session
        manager.create("user123").unwrap();
        manager.create("user456").unwrap();

        // 清理过期 Session
        let cleaned = manager.cleanup().unwrap();
        assert_eq!(cleaned, 2);

        assert_eq!(manager.count().unwrap(), 0);
    }

    #[test]
    fn test_in_memory_store() {
        let store = InMemorySessionStore::new();
        let session = Session::new("user123", Duration::hours(1)).unwrap();

        // 保存
        store.save(&session).unwrap();

        // 获取
        let retrieved = store.get(&session.id).unwrap();
        assert!(retrieved.is_some());

        // 计数
        assert_eq!(store.count().unwrap(), 1);

        // 删除
        store.delete(&session.id).unwrap();
        assert!(store.get(&session.id).unwrap().is_none());
    }

    #[test]
    fn test_session_time_to_live() {
        let session = Session::new("user123", Duration::hours(1)).unwrap();
        let ttl = session.time_to_live();

        assert!(ttl > 3500); // 应该接近 3600 秒
        assert!(ttl <= 3600);
    }

    #[test]
    fn test_session_touch() {
        let mut session = Session::new("user123", Duration::hours(1)).unwrap();
        let original_accessed = session.last_accessed_at;

        std::thread::sleep(std::time::Duration::from_millis(10));
        session.touch();

        assert!(session.last_accessed_at > original_accessed);
    }

    #[test]
    fn test_create_session_options() {
        let options = CreateSessionOptions::new()
            .with_user_agent("Mozilla/5.0")
            .with_ip_address("192.168.1.1")
            .with_data("role", "admin")
            .with_expiration(Duration::hours(2));

        assert_eq!(options.user_agent, Some("Mozilla/5.0".to_string()));
        assert_eq!(options.ip_address, Some("192.168.1.1".to_string()));
        assert!(options.data.contains_key("role"));
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
        let original_expires = session.expires_at;

        std::thread::sleep(std::time::Duration::from_millis(10));

        let refreshed = manager.refresh(&session.id).unwrap();
        assert!(refreshed.expires_at >= original_expires);
    }
}
