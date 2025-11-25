//! WebAuthn 凭证管理模块
//!
//! 提供凭证存储、查询和管理的功能。

use std::collections::HashMap;
use std::sync::RwLock;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

// ============================================================================
// 凭证存储结构
// ============================================================================

/// 存储的 WebAuthn 凭证
///
/// 包含 Passkey 凭证及其元数据信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    /// 凭证 ID（Base64 URL 安全编码）
    pub credential_id: String,

    /// 关联的用户 ID
    pub user_id: String,

    /// 底层 Passkey 凭证
    pub passkey: Passkey,

    /// 凭证名称（用户自定义，如 "我的 YubiKey"）
    pub name: String,

    /// 创建时间
    pub created_at: DateTime<Utc>,

    /// 最后使用时间
    pub last_used_at: Option<DateTime<Utc>>,

    /// 使用次数
    pub use_count: u64,

    /// 是否已撤销
    pub revoked: bool,

    /// 设备类型提示（如 "platform", "cross-platform"）
    pub authenticator_type: Option<String>,

    /// 额外元数据
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl StoredCredential {
    /// 创建新的存储凭证
    pub fn new(user_id: impl Into<String>, passkey: Passkey, name: impl Into<String>) -> Self {
        let cred_id = passkey.cred_id();
        let credential_id = base64_url_encode(cred_id.as_ref());

        Self {
            credential_id,
            user_id: user_id.into(),
            passkey,
            name: name.into(),
            created_at: Utc::now(),
            last_used_at: None,
            use_count: 0,
            revoked: false,
            authenticator_type: None,
            metadata: HashMap::new(),
        }
    }

    /// 设置认证器类型
    pub fn with_authenticator_type(mut self, auth_type: impl Into<String>) -> Self {
        self.authenticator_type = Some(auth_type.into());
        self
    }

    /// 添加元数据
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// 记录一次使用
    pub fn record_use(&mut self) {
        self.last_used_at = Some(Utc::now());
        self.use_count += 1;
    }

    /// 撤销凭证
    pub fn revoke(&mut self) {
        self.revoked = true;
    }

    /// 检查凭证是否有效（未撤销）
    pub fn is_valid(&self) -> bool {
        !self.revoked
    }

    /// 更新底层 Passkey（认证后更新计数器等）
    pub fn update_passkey(&mut self, passkey: Passkey) {
        self.passkey = passkey;
    }
}

// ============================================================================
// 凭证存储 Trait
// ============================================================================

/// 凭证存储 Trait
///
/// 实现此 trait 以提供自定义的凭证存储后端（如数据库）
#[async_trait]
pub trait CredentialStore: Send + Sync {
    /// 保存凭证
    async fn save(&self, credential: StoredCredential) -> Result<(), CredentialStoreError>;

    /// 根据凭证 ID 查找凭证
    async fn find_by_id(&self, credential_id: &str) -> Option<StoredCredential>;

    /// 根据用户 ID 查找所有凭证
    async fn find_by_user(&self, user_id: &str) -> Vec<StoredCredential>;

    /// 根据用户 ID 获取所有 Passkey（用于认证）
    async fn get_passkeys_for_user(&self, user_id: &str) -> Vec<Passkey> {
        self.find_by_user(user_id)
            .await
            .into_iter()
            .filter(|c| c.is_valid())
            .map(|c| c.passkey)
            .collect()
    }

    /// 更新凭证
    async fn update(&self, credential: StoredCredential) -> Result<(), CredentialStoreError>;

    /// 删除凭证
    async fn delete(&self, credential_id: &str) -> Result<bool, CredentialStoreError>;

    /// 根据用户 ID 删除所有凭证
    async fn delete_by_user(&self, user_id: &str) -> Result<usize, CredentialStoreError>;

    /// 列出所有凭证
    async fn list(&self) -> Vec<StoredCredential>;

    /// 统计用户凭证数量
    async fn count_by_user(&self, user_id: &str) -> usize {
        self.find_by_user(user_id).await.len()
    }
}

/// 凭证存储错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialStoreError {
    /// 凭证已存在
    AlreadyExists,
    /// 凭证未找到
    NotFound,
    /// 存储操作失败
    StorageError(String),
}

impl std::fmt::Display for CredentialStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyExists => write!(f, "凭证已存在"),
            Self::NotFound => write!(f, "凭证未找到"),
            Self::StorageError(msg) => write!(f, "存储错误: {}", msg),
        }
    }
}

impl std::error::Error for CredentialStoreError {}

// ============================================================================
// 内存存储实现
// ============================================================================

/// 内存凭证存储
///
/// 适用于测试和开发环境
#[derive(Debug, Default)]
pub struct InMemoryCredentialStore {
    credentials: RwLock<HashMap<String, StoredCredential>>,
}

impl InMemoryCredentialStore {
    /// 创建新的内存存储
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl CredentialStore for InMemoryCredentialStore {
    async fn save(&self, credential: StoredCredential) -> Result<(), CredentialStoreError> {
        let mut credentials = self
            .credentials
            .write()
            .map_err(|e| CredentialStoreError::StorageError(e.to_string()))?;

        if credentials.contains_key(&credential.credential_id) {
            return Err(CredentialStoreError::AlreadyExists);
        }

        credentials.insert(credential.credential_id.clone(), credential);
        Ok(())
    }

    async fn find_by_id(&self, credential_id: &str) -> Option<StoredCredential> {
        self.credentials
            .read()
            .ok()
            .and_then(|creds| creds.get(credential_id).cloned())
    }

    async fn find_by_user(&self, user_id: &str) -> Vec<StoredCredential> {
        self.credentials
            .read()
            .map(|creds| {
                creds
                    .values()
                    .filter(|c| c.user_id == user_id)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn update(&self, credential: StoredCredential) -> Result<(), CredentialStoreError> {
        let mut credentials = self
            .credentials
            .write()
            .map_err(|e| CredentialStoreError::StorageError(e.to_string()))?;

        if !credentials.contains_key(&credential.credential_id) {
            return Err(CredentialStoreError::NotFound);
        }

        credentials.insert(credential.credential_id.clone(), credential);
        Ok(())
    }

    async fn delete(&self, credential_id: &str) -> Result<bool, CredentialStoreError> {
        let mut credentials = self
            .credentials
            .write()
            .map_err(|e| CredentialStoreError::StorageError(e.to_string()))?;
        Ok(credentials.remove(credential_id).is_some())
    }

    async fn delete_by_user(&self, user_id: &str) -> Result<usize, CredentialStoreError> {
        let mut credentials = self
            .credentials
            .write()
            .map_err(|e| CredentialStoreError::StorageError(e.to_string()))?;

        let to_remove: Vec<_> = credentials
            .iter()
            .filter(|(_, c)| c.user_id == user_id)
            .map(|(k, _)| k.clone())
            .collect();

        let count = to_remove.len();
        for key in to_remove {
            credentials.remove(&key);
        }

        Ok(count)
    }

    async fn list(&self) -> Vec<StoredCredential> {
        self.credentials
            .read()
            .map(|creds| creds.values().cloned().collect())
            .unwrap_or_default()
    }
}

// ============================================================================
// 辅助函数
// ============================================================================

/// Base64 URL 安全编码（无填充）
fn base64_url_encode(data: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(data)
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // 注意：由于 Passkey 需要真实的 WebAuthn 注册流程创建，
    // 这里的测试主要验证存储逻辑

    #[test]
    fn test_credential_store_error_display() {
        assert_eq!(
            CredentialStoreError::AlreadyExists.to_string(),
            "凭证已存在"
        );
        assert_eq!(CredentialStoreError::NotFound.to_string(), "凭证未找到");
        assert_eq!(
            CredentialStoreError::StorageError("test".to_string()).to_string(),
            "存储错误: test"
        );
    }

    #[test]
    fn test_base64_url_encode() {
        let data = b"hello world";
        let encoded = base64_url_encode(data);
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
    }

    #[tokio::test]
    async fn test_in_memory_store_basic() {
        let store = InMemoryCredentialStore::new();
        assert!(store.list().await.is_empty());
    }
}
