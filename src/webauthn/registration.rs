//! WebAuthn 注册流程模块
//!
//! 提供 Passkey 凭证注册的完整流程支持。

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

use super::credential::{CredentialStore, StoredCredential};

/// 从 Passkey 列表提取 CredentialID 列表
fn extract_credential_ids(passkeys: &[Passkey]) -> Vec<CredentialID> {
    passkeys.iter().map(|p| p.cred_id().clone()).collect()
}

// ============================================================================
// 注册配置
// ============================================================================

/// 用户验证策略
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UserVerification {
    /// 首选进行用户验证，但不强制
    #[default]
    Preferred,
    /// 强制要求用户验证
    Required,
    /// 不鼓励用户验证（仅用于特殊场景）
    Discouraged,
}

/// 注册配置
#[derive(Debug, Clone)]
pub struct RegistrationConfig {
    /// 用户验证要求
    pub user_verification: UserVerification,

    /// 认证器附件要求（None 表示不限制）
    pub authenticator_attachment: Option<AuthenticatorAttachment>,

    /// 是否要求常驻密钥（Resident Key / Discoverable Credential）
    pub require_resident_key: bool,

    /// 排除已注册的凭证（防止重复注册）
    pub exclude_credentials: bool,

    /// 注册超时时间（毫秒）
    pub timeout_ms: u32,

    /// 最大允许注册的凭证数量（每用户）
    pub max_credentials_per_user: Option<usize>,
}

impl Default for RegistrationConfig {
    fn default() -> Self {
        Self {
            user_verification: UserVerification::Preferred,
            authenticator_attachment: None,
            require_resident_key: false,
            exclude_credentials: true,
            timeout_ms: 60000, // 60 秒
            max_credentials_per_user: Some(10),
        }
    }
}

impl RegistrationConfig {
    /// 创建仅允许平台认证器的配置（如 Touch ID、Windows Hello）
    pub fn platform_only() -> Self {
        Self {
            authenticator_attachment: Some(AuthenticatorAttachment::Platform),
            require_resident_key: true,
            ..Default::default()
        }
    }

    /// 创建仅允许跨平台认证器的配置（如安全密钥）
    pub fn cross_platform_only() -> Self {
        Self {
            authenticator_attachment: Some(AuthenticatorAttachment::CrossPlatform),
            ..Default::default()
        }
    }

    /// 创建高安全性配置（要求用户验证）
    pub fn high_security() -> Self {
        Self {
            user_verification: UserVerification::Required,
            require_resident_key: true,
            ..Default::default()
        }
    }
}

// ============================================================================
// 注册状态
// ============================================================================

/// 注册会话状态
///
/// 在开始注册和完成注册之间需要保存此状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationState {
    /// 用户唯一标识
    pub user_id: String,

    /// 用户名
    pub username: String,

    /// 用户显示名称
    pub display_name: String,

    /// 凭证名称（用户为此认证器起的名字）
    pub credential_name: String,

    /// 底层 Passkey 注册状态
    pub passkey_registration: PasskeyRegistration,

    /// 会话创建时间
    pub created_at: DateTime<Utc>,

    /// 会话过期时间
    pub expires_at: DateTime<Utc>,
}

impl RegistrationState {
    /// 检查会话是否已过期
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

// ============================================================================
// 注册管理器
// ============================================================================

/// WebAuthn 注册管理器
///
/// 管理 Passkey 凭证的注册流程
pub struct RegistrationManager<'a> {
    webauthn: &'a Webauthn,
    config: RegistrationConfig,
}

impl<'a> RegistrationManager<'a> {
    /// 创建新的注册管理器
    pub fn new(webauthn: &'a Webauthn) -> Self {
        Self {
            webauthn,
            config: RegistrationConfig::default(),
        }
    }

    /// 使用自定义配置创建注册管理器
    pub fn with_config(webauthn: &'a Webauthn, config: RegistrationConfig) -> Self {
        Self { webauthn, config }
    }

    /// 开始注册流程
    ///
    /// # 参数
    /// - `user_id`: 用户唯一标识
    /// - `username`: 用户名（用于显示）
    /// - `display_name`: 用户显示名称
    /// - `credential_name`: 凭证名称（用户自定义，如 "我的 YubiKey"）
    /// - `existing_credentials`: 用户已有的凭证（用于排除）
    ///
    /// # 返回
    /// - `CreationChallengeResponse`: 发送给客户端的挑战数据
    /// - `RegistrationState`: 需要保存的注册状态
    pub fn start_registration(
        &self,
        user_id: impl Into<String>,
        username: impl Into<String>,
        display_name: impl Into<String>,
        credential_name: impl Into<String>,
        existing_credentials: Option<Vec<Passkey>>,
    ) -> Result<(CreationChallengeResponse, RegistrationState), RegistrationError> {
        let user_id = user_id.into();
        let username = username.into();
        let display_name = display_name.into();
        let credential_name = credential_name.into();

        // 检查凭证数量限制
        if let Some(max) = self.config.max_credentials_per_user
            && let Some(ref creds) = existing_credentials
            && creds.len() >= max
        {
            return Err(RegistrationError::MaxCredentialsReached(max));
        }

        // 解析用户 ID 为 UUID（如果不是有效 UUID，则生成一个确定性 UUID）
        let user_uuid = parse_or_generate_uuid(&user_id);

        // 准备排除凭证列表（使用 CredentialID）
        let exclude_creds: Option<Vec<CredentialID>> = if self.config.exclude_credentials {
            existing_credentials
                .as_ref()
                .map(|c| extract_credential_ids(c))
        } else {
            None
        };

        // 开始注册流程
        let (ccr, passkey_registration) = self
            .webauthn
            .start_passkey_registration(user_uuid, &username, &display_name, exclude_creds)
            .map_err(|e| RegistrationError::WebAuthnError(e.to_string()))?;

        // 创建注册状态
        let now = Utc::now();
        let expires_at = now + chrono::Duration::milliseconds(i64::from(self.config.timeout_ms));

        let state = RegistrationState {
            user_id,
            username,
            display_name,
            credential_name,
            passkey_registration,
            created_at: now,
            expires_at,
        };

        Ok((ccr, state))
    }

    /// 完成注册流程
    ///
    /// # 参数
    /// - `state`: 之前保存的注册状态
    /// - `response`: 客户端返回的注册响应
    ///
    /// # 返回
    /// - `StoredCredential`: 可存储的凭证对象
    pub fn finish_registration(
        &self,
        state: &RegistrationState,
        response: &RegisterPublicKeyCredential,
    ) -> Result<StoredCredential, RegistrationError> {
        // 检查会话是否过期
        if state.is_expired() {
            return Err(RegistrationError::SessionExpired);
        }

        // 完成注册
        let passkey = self
            .webauthn
            .finish_passkey_registration(response, &state.passkey_registration)
            .map_err(|e| RegistrationError::WebAuthnError(e.to_string()))?;

        // 创建存储凭证
        let credential = StoredCredential::new(&state.user_id, passkey, &state.credential_name);

        Ok(credential)
    }

    /// 开始注册并自动排除已有凭证
    ///
    /// 便捷方法，自动从存储中获取用户已有凭证
    pub async fn start_registration_with_store<S: CredentialStore>(
        &self,
        user_id: impl Into<String>,
        username: impl Into<String>,
        display_name: impl Into<String>,
        credential_name: impl Into<String>,
        store: &S,
    ) -> Result<(CreationChallengeResponse, RegistrationState), RegistrationError> {
        let user_id = user_id.into();
        let existing = store.get_passkeys_for_user(&user_id).await;
        let existing = if existing.is_empty() {
            None
        } else {
            Some(existing)
        };

        self.start_registration(user_id, username, display_name, credential_name, existing)
    }

    /// 完成注册并保存凭证
    ///
    /// 便捷方法，自动保存凭证到存储
    pub async fn finish_registration_and_save<S: CredentialStore>(
        &self,
        state: &RegistrationState,
        response: &RegisterPublicKeyCredential,
        store: &S,
    ) -> Result<StoredCredential, RegistrationError> {
        let credential = self.finish_registration(state, response)?;

        store
            .save(credential.clone())
            .await
            .map_err(|e| RegistrationError::StorageError(e.to_string()))?;

        Ok(credential)
    }
}

// ============================================================================
// 注册状态存储
// ============================================================================

/// 注册状态存储 Trait
///
/// 用于在注册流程中保存临时状态
pub trait RegistrationStateStore {
    /// 保存注册状态
    fn save_state(
        &mut self,
        session_id: &str,
        state: RegistrationState,
    ) -> Result<(), RegistrationError>;

    /// 获取并移除注册状态
    fn take_state(&mut self, session_id: &str) -> Option<RegistrationState>;

    /// 清理过期状态
    fn cleanup_expired(&mut self);
}

/// 内存注册状态存储
#[derive(Debug, Default)]
pub struct InMemoryRegistrationStateStore {
    states: HashMap<String, RegistrationState>,
}

impl InMemoryRegistrationStateStore {
    /// 创建新的内存存储
    pub fn new() -> Self {
        Self::default()
    }
}

impl RegistrationStateStore for InMemoryRegistrationStateStore {
    fn save_state(
        &mut self,
        session_id: &str,
        state: RegistrationState,
    ) -> Result<(), RegistrationError> {
        self.states.insert(session_id.to_string(), state);
        Ok(())
    }

    fn take_state(&mut self, session_id: &str) -> Option<RegistrationState> {
        self.states.remove(session_id)
    }

    fn cleanup_expired(&mut self) {
        self.states.retain(|_, state| !state.is_expired());
    }
}

// ============================================================================
// 错误类型
// ============================================================================

/// 注册错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationError {
    /// WebAuthn 操作错误
    WebAuthnError(String),

    /// 会话已过期
    SessionExpired,

    /// 达到最大凭证数量
    MaxCredentialsReached(usize),

    /// 存储错误
    StorageError(String),

    /// 无效的用户 ID
    InvalidUserId(String),

    /// 凭证已存在
    CredentialExists,
}

impl std::fmt::Display for RegistrationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WebAuthnError(e) => write!(f, "WebAuthn 错误: {}", e),
            Self::SessionExpired => write!(f, "注册会话已过期"),
            Self::MaxCredentialsReached(max) => {
                write!(f, "已达到最大凭证数量限制 ({})", max)
            }
            Self::StorageError(e) => write!(f, "存储错误: {}", e),
            Self::InvalidUserId(id) => write!(f, "无效的用户 ID: {}", id),
            Self::CredentialExists => write!(f, "凭证已存在"),
        }
    }
}

impl std::error::Error for RegistrationError {}

// ============================================================================
// 辅助函数
// ============================================================================

/// 解析或生成 UUID
///
/// 如果输入是有效的 UUID 字符串则解析，否则基于输入生成确定性 UUID
fn parse_or_generate_uuid(input: &str) -> Uuid {
    // 尝试直接解析
    if let Ok(uuid) = Uuid::parse_str(input) {
        return uuid;
    }

    // 使用基于输入的确定性 UUID 生成
    // 计算输入的 SHA256 哈希，取前 16 字节构造 UUID
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash = hasher.finalize();

    // 从哈希的前 16 字节构造 UUID（版本 4 格式）
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);

    // 设置版本位（版本 4）和变体位
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // 版本 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // 变体 1

    Uuid::from_bytes(bytes)
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration_config_default() {
        let config = RegistrationConfig::default();
        assert_eq!(config.timeout_ms, 60000);
        assert_eq!(config.max_credentials_per_user, Some(10));
        assert!(config.exclude_credentials);
    }

    #[test]
    fn test_registration_config_platform_only() {
        let config = RegistrationConfig::platform_only();
        assert_eq!(
            config.authenticator_attachment,
            Some(AuthenticatorAttachment::Platform)
        );
        assert!(config.require_resident_key);
    }

    #[test]
    fn test_registration_config_high_security() {
        let config = RegistrationConfig::high_security();
        assert_eq!(config.user_verification, UserVerification::Required);
    }

    #[test]
    fn test_parse_or_generate_uuid() {
        // 有效 UUID 应直接解析
        let valid_uuid = "550e8400-e29b-41d4-a716-446655440000";
        let parsed = parse_or_generate_uuid(valid_uuid);
        assert_eq!(parsed.to_string(), valid_uuid);

        // 非 UUID 字符串应生成确定性 UUID
        let user_id = "user@example.com";
        let generated1 = parse_or_generate_uuid(user_id);
        let generated2 = parse_or_generate_uuid(user_id);
        assert_eq!(generated1, generated2);

        // 不同输入应生成不同 UUID
        let other_id = "other@example.com";
        let other_uuid = parse_or_generate_uuid(other_id);
        assert_ne!(generated1, other_uuid);
    }

    #[test]
    fn test_registration_error_display() {
        assert_eq!(
            RegistrationError::SessionExpired.to_string(),
            "注册会话已过期"
        );
        assert_eq!(
            RegistrationError::MaxCredentialsReached(5).to_string(),
            "已达到最大凭证数量限制 (5)"
        );
    }

    #[test]
    fn test_in_memory_registration_state_store() {
        let mut store = InMemoryRegistrationStateStore::new();

        // 由于我们无法轻松创建 PasskeyRegistration，
        // 这里只测试基本的存储操作
        assert!(store.take_state("nonexistent").is_none());
    }

    #[test]
    fn test_user_verification_default() {
        let uv = UserVerification::default();
        assert_eq!(uv, UserVerification::Preferred);
    }
}
