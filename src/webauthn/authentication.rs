//! WebAuthn 认证流程模块
//!
//! 提供 Passkey 凭证认证的完整流程支持。

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

use super::credential::CredentialStore;
use super::registration::UserVerification;

// ============================================================================
// 认证配置
// ============================================================================

/// 认证配置
#[derive(Debug, Clone)]
pub struct AuthenticationConfig {
    /// 用户验证要求
    pub user_verification: UserVerification,

    /// 认证超时时间（毫秒）
    pub timeout_ms: u32,

    /// 是否允许空凭证列表（用于可发现凭证 / Discoverable Credentials）
    pub allow_empty_credentials: bool,
}

impl Default for AuthenticationConfig {
    fn default() -> Self {
        Self {
            user_verification: UserVerification::Preferred,
            timeout_ms: 60000, // 60 秒
            allow_empty_credentials: false,
        }
    }
}

impl AuthenticationConfig {
    /// 创建高安全性配置（要求用户验证）
    pub fn high_security() -> Self {
        Self {
            user_verification: UserVerification::Required,
            ..Default::default()
        }
    }

    /// 创建可发现凭证配置（无需提供用户名）
    pub fn discoverable() -> Self {
        Self {
            allow_empty_credentials: true,
            ..Default::default()
        }
    }
}

// ============================================================================
// 认证状态
// ============================================================================

/// 认证会话状态
///
/// 在开始认证和完成认证之间需要保存此状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationState {
    /// 用户唯一标识（可能为空，用于可发现凭证场景）
    pub user_id: Option<String>,

    /// 底层 Passkey 认证状态
    pub passkey_authentication: PasskeyAuthentication,

    /// 会话创建时间
    pub created_at: DateTime<Utc>,

    /// 会话过期时间
    pub expires_at: DateTime<Utc>,
}

impl AuthenticationState {
    /// 检查会话是否已过期
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

// ============================================================================
// 认证结果
// ============================================================================

/// 认证结果
#[derive(Debug, Clone)]
pub struct WebAuthnAuthenticationResult {
    /// 认证成功的凭证 ID
    pub credential_id: String,

    /// 用户 ID
    pub user_id: String,

    /// 用户是否进行了验证（如指纹、PIN）
    pub user_verified: bool,

    /// 认证计数器（用于检测克隆攻击）
    pub counter: u32,

    /// 认证时间
    pub authenticated_at: DateTime<Utc>,
}

// ============================================================================
// 认证管理器
// ============================================================================

/// WebAuthn 认证管理器
///
/// 管理 Passkey 凭证的认证流程
pub struct AuthenticationManager<'a> {
    webauthn: &'a Webauthn,
    config: AuthenticationConfig,
}

impl<'a> AuthenticationManager<'a> {
    /// 创建新的认证管理器
    pub fn new(webauthn: &'a Webauthn) -> Self {
        Self {
            webauthn,
            config: AuthenticationConfig::default(),
        }
    }

    /// 使用自定义配置创建认证管理器
    pub fn with_config(webauthn: &'a Webauthn, config: AuthenticationConfig) -> Self {
        Self { webauthn, config }
    }

    /// 开始认证流程
    ///
    /// # 参数
    /// - `user_id`: 用户唯一标识
    /// - `credentials`: 用户已注册的凭证列表
    ///
    /// # 返回
    /// - `RequestChallengeResponse`: 发送给客户端的挑战数据
    /// - `AuthenticationState`: 需要保存的认证状态
    pub fn start_authentication(
        &self,
        user_id: Option<String>,
        credentials: Vec<Passkey>,
    ) -> Result<(RequestChallengeResponse, AuthenticationState), AuthenticationError> {
        // 检查凭证列表
        if credentials.is_empty() && !self.config.allow_empty_credentials {
            return Err(AuthenticationError::NoCredentials);
        }

        // 开始认证流程
        let (rcr, passkey_authentication) = self
            .webauthn
            .start_passkey_authentication(&credentials)
            .map_err(|e| AuthenticationError::WebAuthnError(e.to_string()))?;

        // 创建认证状态
        let now = Utc::now();
        let expires_at = now + chrono::Duration::milliseconds(i64::from(self.config.timeout_ms));

        let state = AuthenticationState {
            user_id,
            passkey_authentication,
            created_at: now,
            expires_at,
        };

        Ok((rcr, state))
    }

    /// 完成认证流程
    ///
    /// # 参数
    /// - `state`: 之前保存的认证状态
    /// - `response`: 客户端返回的认证响应
    /// - `credentials`: 用户已注册的凭证列表（用于验证和更新）
    ///
    /// # 返回
    /// - `WebAuthnAuthenticationResult`: 认证结果
    /// - `Option<Passkey>`: 更新后的 Passkey（如果计数器有变化）
    pub fn finish_authentication(
        &self,
        state: &AuthenticationState,
        response: &PublicKeyCredential,
        credentials: &[Passkey],
    ) -> Result<(WebAuthnAuthenticationResult, Option<Passkey>), AuthenticationError> {
        // 检查会话是否过期
        if state.is_expired() {
            return Err(AuthenticationError::SessionExpired);
        }

        // 完成认证
        let auth_result = self
            .webauthn
            .finish_passkey_authentication(response, &state.passkey_authentication)
            .map_err(|e| AuthenticationError::WebAuthnError(e.to_string()))?;

        // 查找匹配的凭证
        let cred_id_bytes = auth_result.cred_id();
        let credential_id = base64_url_encode(cred_id_bytes.as_ref());

        // 查找并更新凭证
        let updated_passkey = credentials
            .iter()
            .find(|c| c.cred_id() == cred_id_bytes)
            .cloned()
            .map(|mut pk| {
                pk.update_credential(&auth_result);
                pk
            });

        let user_id = state
            .user_id
            .clone()
            .unwrap_or_else(|| credential_id.clone());

        let result = WebAuthnAuthenticationResult {
            credential_id,
            user_id,
            user_verified: auth_result.user_verified(),
            counter: auth_result.counter(),
            authenticated_at: Utc::now(),
        };

        Ok((result, updated_passkey))
    }

    /// 使用存储开始认证
    ///
    /// 便捷方法，自动从存储中获取用户凭证
    pub fn start_authentication_with_store<S: CredentialStore>(
        &self,
        user_id: impl Into<String>,
        store: &S,
    ) -> Result<(RequestChallengeResponse, AuthenticationState), AuthenticationError> {
        let user_id = user_id.into();
        let credentials = store.get_passkeys_for_user(&user_id);

        if credentials.is_empty() {
            return Err(AuthenticationError::NoCredentials);
        }

        self.start_authentication(Some(user_id), credentials)
    }

    /// 完成认证并更新凭证
    ///
    /// 便捷方法，自动更新存储中的凭证
    pub fn finish_authentication_and_update<S: CredentialStore>(
        &self,
        state: &AuthenticationState,
        response: &PublicKeyCredential,
        store: &mut S,
    ) -> Result<WebAuthnAuthenticationResult, AuthenticationError> {
        // 获取用户凭证
        let user_id = state
            .user_id
            .as_ref()
            .ok_or(AuthenticationError::MissingUserId)?;

        let credentials = store.get_passkeys_for_user(user_id);

        // 完成认证
        let (result, updated_passkey) =
            self.finish_authentication(state, response, &credentials)?;

        // 更新凭证（如果有变化）
        if let Some(passkey) = updated_passkey
            && let Some(mut stored) = store.find_by_id(&result.credential_id)
        {
            stored.update_passkey(passkey);
            stored.record_use();
            store
                .update(stored)
                .map_err(|e| AuthenticationError::StorageError(e.to_string()))?;
        }

        Ok(result)
    }
}

// ============================================================================
// 认证状态存储
// ============================================================================

/// 认证状态存储 Trait
///
/// 用于在认证流程中保存临时状态
pub trait AuthenticationStateStore {
    /// 保存认证状态
    fn save_state(
        &mut self,
        session_id: &str,
        state: AuthenticationState,
    ) -> Result<(), AuthenticationError>;

    /// 获取并移除认证状态
    fn take_state(&mut self, session_id: &str) -> Option<AuthenticationState>;

    /// 清理过期状态
    fn cleanup_expired(&mut self);
}

/// 内存认证状态存储
#[derive(Debug, Default)]
pub struct InMemoryAuthenticationStateStore {
    states: HashMap<String, AuthenticationState>,
}

impl InMemoryAuthenticationStateStore {
    /// 创建新的内存存储
    pub fn new() -> Self {
        Self::default()
    }
}

impl AuthenticationStateStore for InMemoryAuthenticationStateStore {
    fn save_state(
        &mut self,
        session_id: &str,
        state: AuthenticationState,
    ) -> Result<(), AuthenticationError> {
        self.states.insert(session_id.to_string(), state);
        Ok(())
    }

    fn take_state(&mut self, session_id: &str) -> Option<AuthenticationState> {
        self.states.remove(session_id)
    }

    fn cleanup_expired(&mut self) {
        self.states.retain(|_, state| !state.is_expired());
    }
}

// ============================================================================
// 错误类型
// ============================================================================

/// 认证错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthenticationError {
    /// WebAuthn 操作错误
    WebAuthnError(String),

    /// 会话已过期
    SessionExpired,

    /// 没有可用的凭证
    NoCredentials,

    /// 凭证未找到
    CredentialNotFound,

    /// 缺少用户 ID
    MissingUserId,

    /// 存储错误
    StorageError(String),

    /// 凭证已被撤销
    CredentialRevoked,

    /// 计数器回滚（可能的克隆攻击）
    CounterRollback {
        /// 存储的计数器值
        stored: u32,
        /// 收到的计数器值
        received: u32,
    },
}

impl std::fmt::Display for AuthenticationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WebAuthnError(e) => write!(f, "WebAuthn 错误: {}", e),
            Self::SessionExpired => write!(f, "认证会话已过期"),
            Self::NoCredentials => write!(f, "没有可用的凭证"),
            Self::CredentialNotFound => write!(f, "凭证未找到"),
            Self::MissingUserId => write!(f, "缺少用户 ID"),
            Self::StorageError(e) => write!(f, "存储错误: {}", e),
            Self::CredentialRevoked => write!(f, "凭证已被撤销"),
            Self::CounterRollback { stored, received } => {
                write!(
                    f,
                    "检测到计数器回滚（可能的克隆攻击）：存储值={}, 收到值={}",
                    stored, received
                )
            }
        }
    }
}

impl std::error::Error for AuthenticationError {}

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

    #[test]
    fn test_authentication_config_default() {
        let config = AuthenticationConfig::default();
        assert_eq!(config.timeout_ms, 60000);
        assert!(!config.allow_empty_credentials);
    }

    #[test]
    fn test_authentication_config_high_security() {
        let config = AuthenticationConfig::high_security();
        assert_eq!(config.user_verification, UserVerification::Required);
    }

    #[test]
    fn test_authentication_config_discoverable() {
        let config = AuthenticationConfig::discoverable();
        assert!(config.allow_empty_credentials);
    }

    #[test]
    fn test_authentication_error_display() {
        assert_eq!(
            AuthenticationError::SessionExpired.to_string(),
            "认证会话已过期"
        );
        assert_eq!(
            AuthenticationError::NoCredentials.to_string(),
            "没有可用的凭证"
        );
        assert_eq!(
            AuthenticationError::CounterRollback {
                stored: 10,
                received: 5
            }
            .to_string(),
            "检测到计数器回滚（可能的克隆攻击）：存储值=10, 收到值=5"
        );
    }

    #[test]
    fn test_in_memory_authentication_state_store() {
        let mut store = InMemoryAuthenticationStateStore::new();

        // 测试获取不存在的状态
        assert!(store.take_state("nonexistent").is_none());
    }

    #[test]
    fn test_base64_url_encode() {
        let data = b"hello world";
        let encoded = base64_url_encode(data);
        // URL 安全编码不应包含 +, /, =
        assert!(!encoded.contains('+'));
        assert!(!encoded.contains('/'));
        assert!(!encoded.contains('='));
    }
}
