//! 审计日志模块
//!
//! 提供安全事件的记录和审计功能，包括：
//!
//! - **安全事件枚举**: 定义各种安全相关事件
//! - **审计日志 Trait**: 定义日志记录接口
//! - **内存实现**: 用于测试和开发的简单实现
//!
//! ## 使用示例
//!
//! ### 基本用法
//!
//! ```rust
//! use authrs::audit::{AuditLogger, SecurityEvent, InMemoryAuditLogger, EventSeverity};
//!
//! // 创建内存审计日志器
//! let logger = InMemoryAuditLogger::new();
//!
//! // 记录登录成功事件
//! logger.log(SecurityEvent::login_success("user123", "192.168.1.1"));
//!
//! // 记录登录失败事件
//! logger.log(SecurityEvent::login_failed("user456", "Invalid password"));
//!
//! // 获取所有事件
//! let events = logger.get_events();
//! assert_eq!(events.len(), 2);
//! ```
//!
//! ### 自定义事件
//!
//! ```rust
//! use authrs::audit::{SecurityEvent, EventSeverity};
//!
//! // 创建自定义事件
//! let event = SecurityEvent::custom(
//!     "api_rate_limit_exceeded",
//!     EventSeverity::Warning,
//! ).with_user_id("user123")
//!  .with_ip("10.0.0.1")
//!  .with_detail("endpoint", "/api/users")
//!  .with_detail("limit", "100");
//! ```
//!
//! ### 过滤和查询
//!
//! ```rust
//! use authrs::audit::{AuditLogger, SecurityEvent, InMemoryAuditLogger, EventSeverity};
//!
//! let logger = InMemoryAuditLogger::new();
//!
//! logger.log(SecurityEvent::login_success("user1", "192.168.1.1"));
//! logger.log(SecurityEvent::login_failed("user2", "Bad password"));
//! logger.log(SecurityEvent::password_changed("user1"));
//!
//! // 按用户过滤
//! let user1_events = logger.get_events_by_user("user1");
//! assert_eq!(user1_events.len(), 2);
//!
//! // 按严重程度过滤
//! let warnings = logger.get_events_by_severity(EventSeverity::Warning);
//! ```

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// 事件严重程度
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum EventSeverity {
    /// 调试信息
    Debug,
    /// 一般信息
    #[default]
    Info,
    /// 警告
    Warning,
    /// 错误
    Error,
    /// 严重/危险
    Critical,
}

impl std::fmt::Display for EventSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventSeverity::Debug => write!(f, "DEBUG"),
            EventSeverity::Info => write!(f, "INFO"),
            EventSeverity::Warning => write!(f, "WARNING"),
            EventSeverity::Error => write!(f, "ERROR"),
            EventSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// 安全事件类型
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventType {
    /// 登录成功
    LoginSuccess,
    /// 登录失败
    LoginFailed,
    /// 登出
    Logout,
    /// 密码更改
    PasswordChanged,
    /// 密码重置请求
    PasswordResetRequested,
    /// 密码重置完成
    PasswordResetCompleted,
    /// MFA 启用
    MfaEnabled,
    /// MFA 禁用
    MfaDisabled,
    /// MFA 验证成功
    MfaVerified,
    /// MFA 验证失败
    MfaFailed,
    /// 账户锁定
    AccountLocked,
    /// 账户解锁
    AccountUnlocked,
    /// 账户创建
    AccountCreated,
    /// 账户删除
    AccountDeleted,
    /// 权限变更
    PermissionChanged,
    /// 角色变更
    RoleChanged,
    /// API Key 创建
    ApiKeyCreated,
    /// API Key 撤销
    ApiKeyRevoked,
    /// API Key 使用
    ApiKeyUsed,
    /// OAuth 客户端创建
    OauthClientCreated,
    /// OAuth 客户端删除
    OauthClientDeleted,
    /// OAuth 客户端密钥轮换
    OauthClientSecretRotated,
    /// OAuth Token 签发
    OauthTokenIssued,
    /// OAuth Token 吊销
    OauthTokenRevoked,
    /// OAuth Token 内省失败
    OauthTokenIntrospectionFailed,
    /// WebAuthn 注册成功
    WebauthnRegistration,
    /// WebAuthn 注册失败
    WebauthnRegistrationFailed,
    /// WebAuthn 断言成功
    WebauthnAssertion,
    /// WebAuthn 断言失败
    WebauthnAssertionFailed,
    /// 魔法链接创建
    MagicLinkIssued,
    /// 魔法链接使用
    MagicLinkUsed,
    /// 魔法链接过期
    MagicLinkExpired,
    /// OTP 发送
    OtpSent,
    /// OTP 验证成功
    OtpVerified,
    /// OTP 验证失败
    OtpFailed,
    /// Refresh Token 签发
    RefreshTokenIssued,
    /// Refresh Token 轮换
    RefreshTokenRotated,
    /// Refresh Token 重用检测
    RefreshTokenReuseDetected,
    /// Session 创建
    SessionCreated,
    /// Session 过期
    SessionExpired,
    /// Session 撤销
    SessionRevoked,
    /// 可疑活动
    SuspiciousActivity,
    /// 速率限制触发
    RateLimitTriggered,
    /// IP 封禁
    IpBanned,
    /// 自定义事件
    Custom(String),
}

impl std::fmt::Display for EventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventType::LoginSuccess => write!(f, "login_success"),
            EventType::LoginFailed => write!(f, "login_failed"),
            EventType::Logout => write!(f, "logout"),
            EventType::PasswordChanged => write!(f, "password_changed"),
            EventType::PasswordResetRequested => write!(f, "password_reset_requested"),
            EventType::PasswordResetCompleted => write!(f, "password_reset_completed"),
            EventType::MfaEnabled => write!(f, "mfa_enabled"),
            EventType::MfaDisabled => write!(f, "mfa_disabled"),
            EventType::MfaVerified => write!(f, "mfa_verified"),
            EventType::MfaFailed => write!(f, "mfa_failed"),
            EventType::AccountLocked => write!(f, "account_locked"),
            EventType::AccountUnlocked => write!(f, "account_unlocked"),
            EventType::AccountCreated => write!(f, "account_created"),
            EventType::AccountDeleted => write!(f, "account_deleted"),
            EventType::PermissionChanged => write!(f, "permission_changed"),
            EventType::RoleChanged => write!(f, "role_changed"),
            EventType::ApiKeyCreated => write!(f, "api_key_created"),
            EventType::ApiKeyRevoked => write!(f, "api_key_revoked"),
            EventType::ApiKeyUsed => write!(f, "api_key_used"),
            EventType::OauthClientCreated => write!(f, "oauth_client_created"),
            EventType::OauthClientDeleted => write!(f, "oauth_client_deleted"),
            EventType::OauthClientSecretRotated => write!(f, "oauth_client_secret_rotated"),
            EventType::OauthTokenIssued => write!(f, "oauth_token_issued"),
            EventType::OauthTokenRevoked => write!(f, "oauth_token_revoked"),
            EventType::OauthTokenIntrospectionFailed => {
                write!(f, "oauth_token_introspection_failed")
            }
            EventType::WebauthnRegistration => write!(f, "webauthn_registration"),
            EventType::WebauthnRegistrationFailed => {
                write!(f, "webauthn_registration_failed")
            }
            EventType::WebauthnAssertion => write!(f, "webauthn_assertion"),
            EventType::WebauthnAssertionFailed => write!(f, "webauthn_assertion_failed"),
            EventType::MagicLinkIssued => write!(f, "magic_link_issued"),
            EventType::MagicLinkUsed => write!(f, "magic_link_used"),
            EventType::MagicLinkExpired => write!(f, "magic_link_expired"),
            EventType::OtpSent => write!(f, "otp_sent"),
            EventType::OtpVerified => write!(f, "otp_verified"),
            EventType::OtpFailed => write!(f, "otp_failed"),
            EventType::RefreshTokenIssued => write!(f, "refresh_token_issued"),
            EventType::RefreshTokenRotated => write!(f, "refresh_token_rotated"),
            EventType::RefreshTokenReuseDetected => write!(f, "refresh_token_reuse_detected"),
            EventType::SessionCreated => write!(f, "session_created"),
            EventType::SessionExpired => write!(f, "session_expired"),
            EventType::SessionRevoked => write!(f, "session_revoked"),
            EventType::SuspiciousActivity => write!(f, "suspicious_activity"),
            EventType::RateLimitTriggered => write!(f, "rate_limit_triggered"),
            EventType::IpBanned => write!(f, "ip_banned"),
            EventType::Custom(name) => write!(f, "custom:{}", name),
        }
    }
}

/// 安全事件
///
/// 表示一个安全相关的事件记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// 事件 ID
    pub id: String,
    /// 事件类型
    pub event_type: EventType,
    /// 严重程度
    pub severity: EventSeverity,
    /// 用户 ID（如果适用）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// IP 地址（如果适用）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    /// 用户代理（如果适用）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// 事件消息/描述
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// 额外详情
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub details: HashMap<String, String>,
    /// 事件时间
    pub timestamp: DateTime<Utc>,
}

impl SecurityEvent {
    /// 创建新的安全事件
    pub fn new(event_type: EventType, severity: EventSeverity) -> Self {
        Self {
            id: generate_event_id(),
            event_type,
            severity,
            user_id: None,
            ip_address: None,
            user_agent: None,
            message: None,
            details: HashMap::new(),
            timestamp: Utc::now(),
        }
    }

    /// 创建自定义事件
    pub fn custom(name: impl Into<String>, severity: EventSeverity) -> Self {
        Self::new(EventType::Custom(name.into()), severity)
    }

    // ========================================================================
    // 便捷构造方法
    // ========================================================================

    /// 创建登录成功事件
    pub fn login_success(user_id: impl Into<String>, ip: impl Into<String>) -> Self {
        Self::new(EventType::LoginSuccess, EventSeverity::Info)
            .with_user_id(user_id)
            .with_ip(ip)
            .with_message("User logged in successfully")
    }

    /// 创建登录失败事件
    pub fn login_failed(user_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::new(EventType::LoginFailed, EventSeverity::Warning)
            .with_user_id(user_id)
            .with_message(reason)
    }

    /// 创建登出事件
    pub fn logout(user_id: impl Into<String>) -> Self {
        Self::new(EventType::Logout, EventSeverity::Info)
            .with_user_id(user_id)
            .with_message("User logged out")
    }

    /// 创建密码更改事件
    pub fn password_changed(user_id: impl Into<String>) -> Self {
        Self::new(EventType::PasswordChanged, EventSeverity::Info)
            .with_user_id(user_id)
            .with_message("Password changed successfully")
    }

    /// 创建密码重置请求事件
    pub fn password_reset_requested(user_id: impl Into<String>) -> Self {
        Self::new(EventType::PasswordResetRequested, EventSeverity::Info)
            .with_user_id(user_id)
            .with_message("Password reset requested")
    }

    /// 创建 MFA 启用事件
    pub fn mfa_enabled(user_id: impl Into<String>) -> Self {
        Self::new(EventType::MfaEnabled, EventSeverity::Info)
            .with_user_id(user_id)
            .with_message("MFA enabled for account")
    }

    /// 创建 MFA 禁用事件
    pub fn mfa_disabled(user_id: impl Into<String>) -> Self {
        Self::new(EventType::MfaDisabled, EventSeverity::Warning)
            .with_user_id(user_id)
            .with_message("MFA disabled for account")
    }

    /// 创建 MFA 验证失败事件
    pub fn mfa_failed(user_id: impl Into<String>) -> Self {
        Self::new(EventType::MfaFailed, EventSeverity::Warning)
            .with_user_id(user_id)
            .with_message("MFA verification failed")
    }

    /// 创建账户锁定事件
    pub fn account_locked(user_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::new(EventType::AccountLocked, EventSeverity::Warning)
            .with_user_id(user_id)
            .with_message(format!("Account locked: {}", reason.into()))
    }

    /// 创建账户解锁事件
    pub fn account_unlocked(user_id: impl Into<String>) -> Self {
        Self::new(EventType::AccountUnlocked, EventSeverity::Info)
            .with_user_id(user_id)
            .with_message("Account unlocked")
    }

    /// 创建可疑活动事件
    pub fn suspicious_activity(details: impl Into<String>) -> Self {
        Self::new(EventType::SuspiciousActivity, EventSeverity::Critical).with_message(details)
    }

    /// 创建速率限制触发事件
    pub fn rate_limit_triggered(
        identifier: impl Into<String>,
        ip: Option<impl Into<String>>,
    ) -> Self {
        let mut event = Self::new(EventType::RateLimitTriggered, EventSeverity::Warning)
            .with_detail("identifier", identifier.into());
        if let Some(ip) = ip {
            event = event.with_ip(ip);
        }
        event
    }

    /// 创建 IP 封禁事件
    pub fn ip_banned(ip: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::new(EventType::IpBanned, EventSeverity::Warning)
            .with_ip(ip)
            .with_message(reason)
    }

    /// 创建 OAuth 客户端创建事件
    pub fn oauth_client_created(client_id: impl Into<String>) -> Self {
        Self::new(EventType::OauthClientCreated, EventSeverity::Info)
            .with_detail("client_id", client_id.into())
            .with_message("OAuth client created")
    }

    /// 创建 OAuth 客户端删除事件
    pub fn oauth_client_deleted(client_id: impl Into<String>) -> Self {
        Self::new(EventType::OauthClientDeleted, EventSeverity::Warning)
            .with_detail("client_id", client_id.into())
            .with_message("OAuth client deleted")
    }

    /// 创建 OAuth 客户端密钥轮换事件
    pub fn oauth_client_secret_rotated(client_id: impl Into<String>) -> Self {
        Self::new(EventType::OauthClientSecretRotated, EventSeverity::Info)
            .with_detail("client_id", client_id.into())
            .with_message("OAuth client secret rotated")
    }

    /// 创建 OAuth Token 签发事件
    pub fn oauth_token_issued(
        client_id: impl Into<String>,
        user_id: Option<impl Into<String>>,
    ) -> Self {
        let mut event = Self::new(EventType::OauthTokenIssued, EventSeverity::Info)
            .with_detail("client_id", client_id.into())
            .with_message("OAuth token issued");
        if let Some(user_id) = user_id {
            event = event.with_user_id(user_id);
        }
        event
    }

    /// 创建 OAuth Token 吊销事件
    pub fn oauth_token_revoked(client_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::new(EventType::OauthTokenRevoked, EventSeverity::Warning)
            .with_detail("client_id", client_id.into())
            .with_message(format!("OAuth token revoked: {}", reason.into()))
    }

    /// 创建 OAuth Token 内省失败事件
    pub fn oauth_token_introspection_failed(
        client_id: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(EventType::OauthTokenIntrospectionFailed, EventSeverity::Warning)
            .with_detail("client_id", client_id.into())
            .with_message(format!("OAuth token introspection failed: {}", reason.into()))
    }

    /// 创建 WebAuthn 注册成功事件
    pub fn webauthn_registration(user_id: impl Into<String>, rp_id: impl Into<String>) -> Self {
        Self::new(EventType::WebauthnRegistration, EventSeverity::Info)
            .with_user_id(user_id)
            .with_detail("rp_id", rp_id.into())
            .with_message("WebAuthn registration successful")
    }

    /// 创建 WebAuthn 注册失败事件
    pub fn webauthn_registration_failed(
        user_id: impl Into<String>,
        rp_id: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(EventType::WebauthnRegistrationFailed, EventSeverity::Warning)
            .with_user_id(user_id)
            .with_detail("rp_id", rp_id.into())
            .with_message(format!("WebAuthn registration failed: {}", reason.into()))
    }

    /// 创建 WebAuthn 断言成功事件
    pub fn webauthn_assertion(user_id: impl Into<String>, rp_id: impl Into<String>) -> Self {
        Self::new(EventType::WebauthnAssertion, EventSeverity::Info)
            .with_user_id(user_id)
            .with_detail("rp_id", rp_id.into())
            .with_message("WebAuthn assertion successful")
    }

    /// 创建 WebAuthn 断言失败事件
    pub fn webauthn_assertion_failed(
        user_id: impl Into<String>,
        rp_id: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(EventType::WebauthnAssertionFailed, EventSeverity::Warning)
            .with_user_id(user_id)
            .with_detail("rp_id", rp_id.into())
            .with_message(format!("WebAuthn assertion failed: {}", reason.into()))
    }

    /// 创建魔法链接发放事件
    pub fn magic_link_issued(recipient: impl Into<String>) -> Self {
        Self::new(EventType::MagicLinkIssued, EventSeverity::Info)
            .with_detail("recipient", recipient.into())
            .with_message("Magic link issued")
    }

    /// 创建魔法链接使用事件
    pub fn magic_link_used(recipient: impl Into<String>) -> Self {
        Self::new(EventType::MagicLinkUsed, EventSeverity::Info)
            .with_detail("recipient", recipient.into())
            .with_message("Magic link used")
    }

    /// 创建魔法链接过期事件
    pub fn magic_link_expired(recipient: impl Into<String>) -> Self {
        Self::new(EventType::MagicLinkExpired, EventSeverity::Warning)
            .with_detail("recipient", recipient.into())
            .with_message("Magic link expired")
    }

    /// 创建 OTP 发送事件
    pub fn otp_sent(recipient: impl Into<String>) -> Self {
        Self::new(EventType::OtpSent, EventSeverity::Info)
            .with_detail("recipient", recipient.into())
            .with_message("OTP sent")
    }

    /// 创建 OTP 验证成功事件
    pub fn otp_verified(recipient: impl Into<String>) -> Self {
        Self::new(EventType::OtpVerified, EventSeverity::Info)
            .with_detail("recipient", recipient.into())
            .with_message("OTP verified")
    }

    /// 创建 OTP 验证失败事件
    pub fn otp_failed(recipient: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::new(EventType::OtpFailed, EventSeverity::Warning)
            .with_detail("recipient", recipient.into())
            .with_message(format!("OTP verification failed: {}", reason.into()))
    }

    /// 创建 Refresh Token 签发事件
    pub fn refresh_token_issued(user_id: impl Into<String>, family_id: impl Into<String>) -> Self {
        Self::new(EventType::RefreshTokenIssued, EventSeverity::Info)
            .with_user_id(user_id)
            .with_detail("family_id", family_id.into())
            .with_message("Refresh token issued")
    }

    /// 创建 Refresh Token 轮换事件
    pub fn refresh_token_rotated(
        user_id: impl Into<String>,
        family_id: impl Into<String>,
    ) -> Self {
        Self::new(EventType::RefreshTokenRotated, EventSeverity::Info)
            .with_user_id(user_id)
            .with_detail("family_id", family_id.into())
            .with_message("Refresh token rotated")
    }

    /// 创建 Refresh Token 重用检测事件
    pub fn refresh_token_reuse_detected(
        user_id: impl Into<String>,
        family_id: impl Into<String>,
    ) -> Self {
        Self::new(EventType::RefreshTokenReuseDetected, EventSeverity::Critical)
            .with_user_id(user_id)
            .with_detail("family_id", family_id.into())
            .with_message("Refresh token reuse detected")
    }

    /// 创建 API Key 创建事件
    pub fn api_key_created(user_id: impl Into<String>, key_id: impl Into<String>) -> Self {
        Self::new(EventType::ApiKeyCreated, EventSeverity::Info)
            .with_user_id(user_id)
            .with_detail("key_id", key_id.into())
            .with_message("API key created")
    }

    /// 创建 API Key 撤销事件
    pub fn api_key_revoked(user_id: impl Into<String>, key_id: impl Into<String>) -> Self {
        Self::new(EventType::ApiKeyRevoked, EventSeverity::Info)
            .with_user_id(user_id)
            .with_detail("key_id", key_id.into())
            .with_message("API key revoked")
    }

    // ========================================================================
    // Builder 方法
    // ========================================================================

    /// 设置用户 ID
    pub fn with_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// 设置 IP 地址
    pub fn with_ip(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// 设置 User Agent
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// 设置消息
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    /// 添加详情
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }

    /// 设置严重程度
    pub fn with_severity(mut self, severity: EventSeverity) -> Self {
        self.severity = severity;
        self
    }

    // ========================================================================
    // 查询方法
    // ========================================================================

    /// 获取事件类型名称
    pub fn event_name(&self) -> String {
        self.event_type.to_string()
    }

    /// 检查是否是高严重程度事件
    pub fn is_high_severity(&self) -> bool {
        matches!(
            self.severity,
            EventSeverity::Error | EventSeverity::Critical
        )
    }

    /// 检查是否是认证相关事件
    pub fn is_auth_event(&self) -> bool {
        matches!(
            self.event_type,
            EventType::LoginSuccess
                | EventType::LoginFailed
                | EventType::Logout
                | EventType::MfaVerified
                | EventType::MfaFailed
                | EventType::MagicLinkIssued
                | EventType::MagicLinkUsed
                | EventType::MagicLinkExpired
                | EventType::OtpSent
                | EventType::OtpVerified
                | EventType::OtpFailed
                | EventType::WebauthnRegistration
                | EventType::WebauthnRegistrationFailed
                | EventType::WebauthnAssertion
                | EventType::WebauthnAssertionFailed
        )
    }
}

/// 生成事件 ID
fn generate_event_id() -> String {
    use crate::random::generate_random_hex;
    format!(
        "evt_{}",
        generate_random_hex(16).unwrap_or_else(|_| "unknown".to_string())
    )
}

// ============================================================================
// AuditLogger Trait
// ============================================================================

/// 审计日志记录器 trait
///
/// 定义审计日志的记录接口
pub trait AuditLogger: Send + Sync {
    /// 记录安全事件
    fn log(&self, event: SecurityEvent);

    /// 批量记录事件
    fn log_batch(&self, events: Vec<SecurityEvent>) {
        for event in events {
            self.log(event);
        }
    }
}

// ============================================================================
// InMemoryAuditLogger
// ============================================================================

/// 内存审计日志记录器
///
/// 用于测试和开发环境，将事件存储在内存中
#[derive(Debug, Default)]
pub struct InMemoryAuditLogger {
    events: Arc<RwLock<Vec<SecurityEvent>>>,
    max_events: Option<usize>,
}

impl InMemoryAuditLogger {
    /// 创建新的内存日志记录器
    pub fn new() -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
            max_events: None,
        }
    }

    /// 创建带有最大事件数限制的日志记录器
    pub fn with_max_events(max: usize) -> Self {
        Self {
            events: Arc::new(RwLock::new(Vec::new())),
            max_events: Some(max),
        }
    }

    /// 获取所有事件
    pub fn get_events(&self) -> Vec<SecurityEvent> {
        self.events.read().unwrap().clone()
    }

    /// 获取事件数量
    pub fn event_count(&self) -> usize {
        self.events.read().unwrap().len()
    }

    /// 按用户 ID 获取事件
    pub fn get_events_by_user(&self, user_id: &str) -> Vec<SecurityEvent> {
        self.events
            .read()
            .unwrap()
            .iter()
            .filter(|e| e.user_id.as_deref() == Some(user_id))
            .cloned()
            .collect()
    }

    /// 按事件类型获取事件
    pub fn get_events_by_type(&self, event_type: &EventType) -> Vec<SecurityEvent> {
        self.events
            .read()
            .unwrap()
            .iter()
            .filter(|e| &e.event_type == event_type)
            .cloned()
            .collect()
    }

    /// 按严重程度获取事件
    pub fn get_events_by_severity(&self, severity: EventSeverity) -> Vec<SecurityEvent> {
        self.events
            .read()
            .unwrap()
            .iter()
            .filter(|e| e.severity == severity)
            .cloned()
            .collect()
    }

    /// 获取时间范围内的事件
    pub fn get_events_in_range(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Vec<SecurityEvent> {
        self.events
            .read()
            .unwrap()
            .iter()
            .filter(|e| e.timestamp >= start && e.timestamp <= end)
            .cloned()
            .collect()
    }

    /// 获取最近 N 个事件
    pub fn get_recent_events(&self, count: usize) -> Vec<SecurityEvent> {
        let events = self.events.read().unwrap();
        events.iter().rev().take(count).cloned().collect()
    }

    /// 清空所有事件
    pub fn clear(&self) {
        self.events.write().unwrap().clear();
    }

    /// 获取高严重程度事件
    pub fn get_high_severity_events(&self) -> Vec<SecurityEvent> {
        self.events
            .read()
            .unwrap()
            .iter()
            .filter(|e| e.is_high_severity())
            .cloned()
            .collect()
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> AuditStats {
        let events = self.events.read().unwrap();
        let mut stats = AuditStats {
            total_events: events.len(),
            ..Default::default()
        };

        for event in events.iter() {
            match event.severity {
                EventSeverity::Debug => stats.debug_count += 1,
                EventSeverity::Info => stats.info_count += 1,
                EventSeverity::Warning => stats.warning_count += 1,
                EventSeverity::Error => stats.error_count += 1,
                EventSeverity::Critical => stats.critical_count += 1,
            }

            *stats.events_by_type.entry(event.event_name()).or_insert(0) += 1;
        }

        stats
    }
}

impl AuditLogger for InMemoryAuditLogger {
    fn log(&self, event: SecurityEvent) {
        let mut events = self.events.write().unwrap();

        // 如果设置了最大事件数，删除最旧的事件
        if let Some(max) = self.max_events {
            while events.len() >= max {
                events.remove(0);
            }
        }

        events.push(event);
    }
}

impl Clone for InMemoryAuditLogger {
    fn clone(&self) -> Self {
        Self {
            events: Arc::clone(&self.events),
            max_events: self.max_events,
        }
    }
}

/// 审计统计信息
#[derive(Debug, Default, Clone)]
pub struct AuditStats {
    /// 总事件数
    pub total_events: usize,
    /// Debug 级别事件数
    pub debug_count: usize,
    /// Info 级别事件数
    pub info_count: usize,
    /// Warning 级别事件数
    pub warning_count: usize,
    /// Error 级别事件数
    pub error_count: usize,
    /// Critical 级别事件数
    pub critical_count: usize,
    /// 按类型统计
    pub events_by_type: HashMap<String, usize>,
}

// ============================================================================
// NoOpAuditLogger
// ============================================================================

/// 空操作日志记录器
///
/// 不执行任何操作，用于禁用审计日志
#[derive(Debug, Default, Clone, Copy)]
pub struct NoOpAuditLogger;

impl NoOpAuditLogger {
    /// 创建新的空操作日志记录器
    pub fn new() -> Self {
        Self
    }
}

impl AuditLogger for NoOpAuditLogger {
    fn log(&self, _event: SecurityEvent) {
        // 不执行任何操作
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_event_creation() {
        let event = SecurityEvent::login_success("user123", "192.168.1.1");

        assert_eq!(event.event_type, EventType::LoginSuccess);
        assert_eq!(event.severity, EventSeverity::Info);
        assert_eq!(event.user_id, Some("user123".to_string()));
        assert_eq!(event.ip_address, Some("192.168.1.1".to_string()));
        assert!(event.id.starts_with("evt_"));
    }

    #[test]
    fn test_security_event_builder() {
        let event = SecurityEvent::custom("custom_event", EventSeverity::Warning)
            .with_user_id("user456")
            .with_ip("10.0.0.1")
            .with_user_agent("Mozilla/5.0")
            .with_detail("key1", "value1")
            .with_detail("key2", "value2");

        assert_eq!(event.user_id, Some("user456".to_string()));
        assert_eq!(event.ip_address, Some("10.0.0.1".to_string()));
        assert_eq!(event.user_agent, Some("Mozilla/5.0".to_string()));
        assert_eq!(event.details.get("key1"), Some(&"value1".to_string()));
        assert_eq!(event.details.get("key2"), Some(&"value2".to_string()));
    }

    #[test]
    fn test_in_memory_logger() {
        let logger = InMemoryAuditLogger::new();

        logger.log(SecurityEvent::login_success("user1", "192.168.1.1"));
        logger.log(SecurityEvent::login_failed("user2", "Bad password"));
        logger.log(SecurityEvent::password_changed("user1"));

        assert_eq!(logger.event_count(), 3);

        let events = logger.get_events();
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn test_filter_by_user() {
        let logger = InMemoryAuditLogger::new();

        logger.log(SecurityEvent::login_success("user1", "192.168.1.1"));
        logger.log(SecurityEvent::login_failed("user2", "Bad password"));
        logger.log(SecurityEvent::password_changed("user1"));

        let user1_events = logger.get_events_by_user("user1");
        assert_eq!(user1_events.len(), 2);

        let user2_events = logger.get_events_by_user("user2");
        assert_eq!(user2_events.len(), 1);
    }

    #[test]
    fn test_filter_by_type() {
        let logger = InMemoryAuditLogger::new();

        logger.log(SecurityEvent::login_success("user1", "192.168.1.1"));
        logger.log(SecurityEvent::login_failed("user2", "Bad password"));
        logger.log(SecurityEvent::login_success("user3", "10.0.0.1"));

        let login_success = logger.get_events_by_type(&EventType::LoginSuccess);
        assert_eq!(login_success.len(), 2);

        let login_failed = logger.get_events_by_type(&EventType::LoginFailed);
        assert_eq!(login_failed.len(), 1);
    }

    #[test]
    fn test_filter_by_severity() {
        let logger = InMemoryAuditLogger::new();

        logger.log(SecurityEvent::login_success("user1", "192.168.1.1"));
        logger.log(SecurityEvent::login_failed("user2", "Bad password"));
        logger.log(SecurityEvent::suspicious_activity("Unusual login pattern"));

        let info_events = logger.get_events_by_severity(EventSeverity::Info);
        assert_eq!(info_events.len(), 1);

        let warning_events = logger.get_events_by_severity(EventSeverity::Warning);
        assert_eq!(warning_events.len(), 1);

        let critical_events = logger.get_events_by_severity(EventSeverity::Critical);
        assert_eq!(critical_events.len(), 1);
    }

    #[test]
    fn test_max_events_limit() {
        let logger = InMemoryAuditLogger::with_max_events(3);

        logger.log(SecurityEvent::login_success("user1", "1.1.1.1"));
        logger.log(SecurityEvent::login_success("user2", "2.2.2.2"));
        logger.log(SecurityEvent::login_success("user3", "3.3.3.3"));
        logger.log(SecurityEvent::login_success("user4", "4.4.4.4"));

        assert_eq!(logger.event_count(), 3);

        // 最旧的事件（user1）应该被删除
        let events = logger.get_events();
        assert!(
            events
                .iter()
                .all(|e| e.user_id != Some("user1".to_string()))
        );
    }

    #[test]
    fn test_clear_events() {
        let logger = InMemoryAuditLogger::new();

        logger.log(SecurityEvent::login_success("user1", "192.168.1.1"));
        logger.log(SecurityEvent::login_success("user2", "192.168.1.2"));

        assert_eq!(logger.event_count(), 2);

        logger.clear();
        assert_eq!(logger.event_count(), 0);
    }

    #[test]
    fn test_get_stats() {
        let logger = InMemoryAuditLogger::new();

        logger.log(SecurityEvent::login_success("user1", "192.168.1.1"));
        logger.log(SecurityEvent::login_failed("user2", "Bad password"));
        logger.log(SecurityEvent::suspicious_activity("Test"));

        let stats = logger.get_stats();

        assert_eq!(stats.total_events, 3);
        assert_eq!(stats.info_count, 1);
        assert_eq!(stats.warning_count, 1);
        assert_eq!(stats.critical_count, 1);
    }

    #[test]
    fn test_is_high_severity() {
        let info_event = SecurityEvent::login_success("user1", "192.168.1.1");
        let critical_event = SecurityEvent::suspicious_activity("Test");

        assert!(!info_event.is_high_severity());
        assert!(critical_event.is_high_severity());
    }

    #[test]
    fn test_is_auth_event() {
        let login = SecurityEvent::login_success("user1", "192.168.1.1");
        let password_change = SecurityEvent::password_changed("user1");

        assert!(login.is_auth_event());
        assert!(!password_change.is_auth_event());
    }

    #[test]
    fn test_event_serialization() {
        let event =
            SecurityEvent::login_success("user123", "192.168.1.1").with_detail("browser", "Chrome");

        let json = serde_json::to_string(&event).unwrap();
        let deserialized: SecurityEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.user_id, event.user_id);
        assert_eq!(deserialized.ip_address, event.ip_address);
        assert_eq!(
            deserialized.details.get("browser"),
            Some(&"Chrome".to_string())
        );
    }

    #[test]
    fn test_noop_logger() {
        let logger = NoOpAuditLogger::new();

        // 这不应该做任何事情，只是确保不会 panic
        logger.log(SecurityEvent::login_success("user1", "192.168.1.1"));
    }

    #[test]
    fn test_batch_logging() {
        let logger = InMemoryAuditLogger::new();

        let events = vec![
            SecurityEvent::login_success("user1", "1.1.1.1"),
            SecurityEvent::login_success("user2", "2.2.2.2"),
            SecurityEvent::login_success("user3", "3.3.3.3"),
        ];

        logger.log_batch(events);

        assert_eq!(logger.event_count(), 3);
    }

    #[test]
    fn test_clone_logger_shares_state() {
        let logger1 = InMemoryAuditLogger::new();
        let logger2 = logger1.clone();

        logger1.log(SecurityEvent::login_success("user1", "192.168.1.1"));

        // 两个 logger 应该共享状态
        assert_eq!(logger2.event_count(), 1);
    }

    #[test]
    fn test_refresh_token_reuse_detected_event() {
        let event =
            SecurityEvent::refresh_token_reuse_detected("user1", "fam123");

        assert_eq!(event.event_type, EventType::RefreshTokenReuseDetected);
        assert_eq!(event.severity, EventSeverity::Critical);
        assert_eq!(event.user_id.as_deref(), Some("user1"));
        assert_eq!(event.details.get("family_id"), Some(&"fam123".to_string()));
    }

    #[test]
    fn test_oauth_token_issued_event() {
        let event = SecurityEvent::oauth_token_issued("client-1", Some("user-9"));

        assert_eq!(event.event_type, EventType::OauthTokenIssued);
        assert_eq!(event.severity, EventSeverity::Info);
        assert_eq!(event.user_id.as_deref(), Some("user-9"));
        assert_eq!(event.details.get("client_id"), Some(&"client-1".to_string()));
    }
}
