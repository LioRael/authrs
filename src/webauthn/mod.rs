//! WebAuthn / Passkeys 模块
//!
//! 提供完整的 WebAuthn 认证支持，包括 Passkey 注册和认证流程。
//!
//! ## 功能概述
//!
//! - **凭证管理** (`credential`): 凭证存储、查询和生命周期管理
//! - **注册流程** (`registration`): Passkey 凭证注册
//! - **认证流程** (`authentication`): Passkey 凭证认证
//!
//! ## 快速开始
//!
//! ### 创建 WebAuthn 实例
//!
//! ```rust,ignore
//! use authrs::webauthn::WebAuthnService;
//!
//! // 创建 WebAuthn 服务
//! let webauthn = WebAuthnService::new(
//!     "example.com",           // Relying Party ID
//!     "https://example.com",   // Origin URL
//!     "My Application",        // 应用名称
//! ).expect("创建 WebAuthn 服务失败");
//! ```
//!
//! ### 注册流程
//!
//! ```rust,ignore
//! use authrs::webauthn::{WebAuthnService, RegistrationManager};
//!
//! // 在 async 环境中执行
//! let reg_manager = RegistrationManager::new(webauthn.webauthn());
//! let (challenge, state) = reg_manager.start_registration(
//!     "user123",               // 用户 ID
//!     "alice",                 // 用户名
//!     "Alice",                 // 显示名称
//!     "My Passkey",            // 凭证名称
//!     None,                    // 已有凭证（排除）
//! )?;
//!
//! // 2. 将 challenge 发送给客户端...
//! // 3. 客户端完成后返回 response
//!
//! // 4. 完成注册
//! let credential = reg_manager.finish_registration(&state, &response)?;
//!
//! // 5. 保存凭证到存储
//! store.save(credential).await?;
//! ```
//!
//! ### 认证流程
//!
//! ```rust,ignore
//! use authrs::webauthn::{WebAuthnService, AuthenticationManager};
//!
//! // 1. 获取用户凭证
//! let credentials = store.get_passkeys_for_user("user123").await;
//!
//! // 2. 开始认证
//! let auth_manager = AuthenticationManager::new(webauthn.webauthn());
//! let (challenge, state) = auth_manager.start_authentication(
//!     Some("user123".to_string()),
//!     credentials.clone(),
//! )?;
//!
//! // 3. 将 challenge 发送给客户端...
//! // 4. 客户端完成后返回 response
//!
//! // 5. 完成认证
//! let result = auth_manager.finish_authentication(&state, &response, &credentials)?;
//!
//! println!("认证成功！用户: {}", result.user_id);
//! ```
//!
//! ## 存储后端
//!
//! 本模块提供内存存储实现用于测试和开发。
//! 生产环境请实现 `CredentialStore` trait 对接数据库。
//!
//! ```rust,ignore
//! use async_trait::async_trait;
//! use authrs::webauthn::{CredentialStore, StoredCredential, CredentialStoreError};
//!
//! struct MyDatabaseStore { /* ... */ }
//!
//! #[async_trait]
//! impl CredentialStore for MyDatabaseStore {
//!     async fn save(&self, credential: StoredCredential) -> Result<(), CredentialStoreError> {
//!         // 保存到数据库...
//!         Ok(())
//!     }
//!     // 实现其他方法...
//! }
//! ```

pub mod authentication;
pub mod credential;
pub mod registration;

// ============================================================================
// 凭证管理导出
// ============================================================================

pub use credential::{
    CredentialStore, CredentialStoreError, InMemoryCredentialStore, StoredCredential,
};

// ============================================================================
// 注册流程导出
// ============================================================================

pub use registration::{
    InMemoryRegistrationStateStore, RegistrationConfig, RegistrationError, RegistrationManager,
    RegistrationState, RegistrationStateStore, UserVerification,
};

// ============================================================================
// 认证流程导出
// ============================================================================

pub use authentication::{
    AuthenticationConfig, AuthenticationError, AuthenticationManager, AuthenticationState,
    AuthenticationStateStore, InMemoryAuthenticationStateStore, WebAuthnAuthenticationResult,
};

// ============================================================================
// Re-export webauthn-rs 常用类型
// ============================================================================

pub use url::Url;
pub use webauthn_rs::prelude::{
    AuthenticatorAttachment, CreationChallengeResponse, Passkey, PublicKeyCredential,
    RegisterPublicKeyCredential, RequestChallengeResponse, Uuid, Webauthn, WebauthnBuilder,
};

// ============================================================================
// 便捷 WebAuthn 服务封装
// ============================================================================

/// WebAuthn 服务
///
/// 提供便捷的 WebAuthn 实例创建和管理
pub struct WebAuthnService {
    webauthn: Webauthn,
    rp_id: String,
    rp_origin: Url,
    rp_name: String,
}

impl WebAuthnService {
    /// 创建新的 WebAuthn 服务
    ///
    /// # 参数
    /// - `rp_id`: Relying Party ID，通常是你的域名（如 "example.com"）
    /// - `rp_origin`: Origin URL（如 "https://example.com"）
    /// - `rp_name`: 应用名称，显示在认证器上
    ///
    /// # 示例
    ///
    /// ```rust,ignore
    /// let service = WebAuthnService::new(
    ///     "example.com",
    ///     "https://example.com",
    ///     "My Application",
    /// )?;
    /// ```
    pub fn new(
        rp_id: impl Into<String>,
        rp_origin: impl AsRef<str>,
        rp_name: impl Into<String>,
    ) -> Result<Self, WebAuthnServiceError> {
        let rp_id = rp_id.into();
        let rp_name = rp_name.into();
        let rp_origin = Url::parse(rp_origin.as_ref())
            .map_err(|e| WebAuthnServiceError::InvalidOrigin(e.to_string()))?;

        let webauthn = WebauthnBuilder::new(&rp_id, &rp_origin)
            .map_err(|e| WebAuthnServiceError::ConfigurationError(e.to_string()))?
            .rp_name(&rp_name)
            .build()
            .map_err(|e| WebAuthnServiceError::ConfigurationError(e.to_string()))?;

        Ok(Self {
            webauthn,
            rp_id,
            rp_origin,
            rp_name,
        })
    }

    /// 获取底层 Webauthn 实例
    pub fn webauthn(&self) -> &Webauthn {
        &self.webauthn
    }

    /// 获取 Relying Party ID
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// 获取 Origin URL
    pub fn rp_origin(&self) -> &Url {
        &self.rp_origin
    }

    /// 获取应用名称
    pub fn rp_name(&self) -> &str {
        &self.rp_name
    }

    /// 创建注册管理器
    pub fn registration_manager(&self) -> RegistrationManager<'_> {
        RegistrationManager::new(&self.webauthn)
    }

    /// 使用自定义配置创建注册管理器
    pub fn registration_manager_with_config(
        &self,
        config: RegistrationConfig,
    ) -> RegistrationManager<'_> {
        RegistrationManager::with_config(&self.webauthn, config)
    }

    /// 创建认证管理器
    pub fn authentication_manager(&self) -> AuthenticationManager<'_> {
        AuthenticationManager::new(&self.webauthn)
    }

    /// 使用自定义配置创建认证管理器
    pub fn authentication_manager_with_config(
        &self,
        config: AuthenticationConfig,
    ) -> AuthenticationManager<'_> {
        AuthenticationManager::with_config(&self.webauthn, config)
    }
}

/// WebAuthn 服务错误
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebAuthnServiceError {
    /// 无效的 Origin URL
    InvalidOrigin(String),

    /// 配置错误
    ConfigurationError(String),
}

impl std::fmt::Display for WebAuthnServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOrigin(e) => write!(f, "无效的 Origin URL: {}", e),
            Self::ConfigurationError(e) => write!(f, "WebAuthn 配置错误: {}", e),
        }
    }
}

impl std::error::Error for WebAuthnServiceError {}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webauthn_service_creation() {
        let service = WebAuthnService::new("example.com", "https://example.com", "Test App");

        assert!(service.is_ok());
        let service = service.unwrap();
        assert_eq!(service.rp_id(), "example.com");
        assert_eq!(service.rp_name(), "Test App");
    }

    #[test]
    fn test_webauthn_service_invalid_origin() {
        let result = WebAuthnService::new("example.com", "not a valid url", "Test App");

        assert!(result.is_err());
        match result {
            Err(WebAuthnServiceError::InvalidOrigin(_)) => {}
            _ => panic!("应该返回 InvalidOrigin 错误"),
        }
    }

    #[test]
    fn test_webauthn_service_managers() {
        let service =
            WebAuthnService::new("example.com", "https://example.com", "Test App").unwrap();

        // 验证可以创建管理器
        let _reg_manager = service.registration_manager();
        let _auth_manager = service.authentication_manager();

        // 验证可以创建带配置的管理器
        let _reg_manager =
            service.registration_manager_with_config(RegistrationConfig::high_security());
        let _auth_manager =
            service.authentication_manager_with_config(AuthenticationConfig::high_security());
    }

    #[test]
    fn test_webauthn_service_error_display() {
        let error = WebAuthnServiceError::InvalidOrigin("test".to_string());
        assert!(error.to_string().contains("无效的 Origin URL"));

        let error = WebAuthnServiceError::ConfigurationError("test".to_string());
        assert!(error.to_string().contains("配置错误"));
    }
}
