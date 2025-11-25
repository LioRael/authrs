//! OTP (One-Time Password) 实现
//!
//! 提供基于一次性验证码的无密码认证功能，适用于邮件和短信验证。
//!
//! ## 与 MFA TOTP 的区别
//!
//! - **MFA TOTP**: 基于时间的算法，用户使用 Authenticator App 生成
//! - **本模块 OTP**: 服务端生成随机码，通过邮件/短信发送给用户
//!
//! ## 工作流程
//!
//! 1. 用户请求验证（输入邮箱或手机号）
//! 2. 系统生成随机数字验证码
//! 3. 应用层将验证码通过邮件/短信发送给用户
//! 4. 用户输入收到的验证码
//! 5. 系统验证码是否正确且未过期
//! 6. 验证成功后，验证码失效
//!
//! ## 示例
//!
//! ```rust
//! use authrs::passwordless::{OtpManager, OtpConfig, OtpPurpose};
//!
//! // 创建管理器
//! let manager = OtpManager::new(OtpConfig::default());
//!
//! // 生成 OTP
//! let otp_data = manager.generate("user@example.com", OtpPurpose::Login).unwrap();
//! println!("验证码: {}", otp_data.code);  // 例如: "847291"
//!
//! // 应用层发送验证码（邮件/短信）
//! // send_email(user_email, otp_data.code);
//!
//! // 验证用户输入的验证码
//! match manager.verify("user@example.com", &otp_data.code, OtpPurpose::Login) {
//!     Ok(()) => println!("验证成功"),
//!     Err(e) => println!("验证失败: {}", e),
//! }
//! ```
//!
//! ## 自定义配置
//!
//! ```rust
//! use authrs::passwordless::OtpConfig;
//! use std::time::Duration;
//!
//! let config = OtpConfig::default()
//!     .with_code_length(6)              // 6 位数字
//!     .with_ttl(Duration::from_secs(300))   // 5 分钟过期
//!     .with_max_attempts(3);            // 最多尝试 3 次
//! ```

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::error::{Error, Result};
use crate::random::{constant_time_compare_str, generate_random_in_range};

// ============================================================================
// OTP 用途
// ============================================================================

/// OTP 用途
///
/// 不同用途的 OTP 是相互独立的，防止混用。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OtpPurpose {
    /// 登录验证
    Login,
    /// 注册验证
    Registration,
    /// 密码重置
    PasswordReset,
    /// 邮箱验证
    EmailVerification,
    /// 手机号验证
    PhoneVerification,
    /// 交易确认
    TransactionConfirmation,
    /// 双因素认证
    TwoFactor,
    /// 自定义用途
    Custom(u8),
}

impl std::fmt::Display for OtpPurpose {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OtpPurpose::Login => write!(f, "login"),
            OtpPurpose::Registration => write!(f, "registration"),
            OtpPurpose::PasswordReset => write!(f, "password_reset"),
            OtpPurpose::EmailVerification => write!(f, "email_verification"),
            OtpPurpose::PhoneVerification => write!(f, "phone_verification"),
            OtpPurpose::TransactionConfirmation => write!(f, "transaction_confirmation"),
            OtpPurpose::TwoFactor => write!(f, "two_factor"),
            OtpPurpose::Custom(id) => write!(f, "custom_{}", id),
        }
    }
}

// ============================================================================
// 配置
// ============================================================================

/// OTP 配置
#[derive(Debug, Clone)]
pub struct OtpConfig {
    /// 验证码长度（数字位数）
    pub code_length: usize,

    /// 验证码有效期
    pub ttl: std::time::Duration,

    /// 最大尝试次数（超过后需要重新生成）
    pub max_attempts: u32,

    /// 验证成功后是否自动删除
    pub consume_on_verify: bool,

    /// 是否允许同一用户同一用途同时存在多个 OTP
    pub allow_multiple: bool,

    /// 生成新 OTP 的最小间隔（防止滥用）
    pub min_interval: Option<std::time::Duration>,
}

impl Default for OtpConfig {
    fn default() -> Self {
        Self {
            code_length: 6,
            ttl: std::time::Duration::from_secs(5 * 60), // 5 分钟
            max_attempts: 3,
            consume_on_verify: true,
            allow_multiple: false,
            min_interval: Some(std::time::Duration::from_secs(60)), // 1 分钟
        }
    }
}

impl OtpConfig {
    /// 创建新配置
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置验证码长度
    pub fn with_code_length(mut self, length: usize) -> Self {
        assert!(
            (4..=10).contains(&length),
            "code length must be between 4 and 10"
        );
        self.code_length = length;
        self
    }

    /// 设置有效期
    pub fn with_ttl(mut self, ttl: std::time::Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// 设置最大尝试次数
    pub fn with_max_attempts(mut self, max: u32) -> Self {
        self.max_attempts = max;
        self
    }

    /// 设置是否在验证后消费 OTP
    pub fn with_consume_on_verify(mut self, consume: bool) -> Self {
        self.consume_on_verify = consume;
        self
    }

    /// 设置是否允许同时多个 OTP
    pub fn with_allow_multiple(mut self, allow: bool) -> Self {
        self.allow_multiple = allow;
        self
    }

    /// 设置最小生成间隔
    pub fn with_min_interval(mut self, interval: Option<std::time::Duration>) -> Self {
        self.min_interval = interval;
        self
    }

    /// 高安全性配置
    ///
    /// - 8 位验证码
    /// - 3 分钟过期
    /// - 最多 3 次尝试
    /// - 2 分钟生成间隔
    pub fn high_security() -> Self {
        Self {
            code_length: 8,
            ttl: std::time::Duration::from_secs(3 * 60),
            max_attempts: 3,
            consume_on_verify: true,
            allow_multiple: false,
            min_interval: Some(std::time::Duration::from_secs(120)),
        }
    }

    /// 宽松配置（适用于开发/测试）
    ///
    /// - 4 位验证码
    /// - 30 分钟过期
    /// - 10 次尝试
    /// - 无生成间隔限制
    pub fn relaxed() -> Self {
        Self {
            code_length: 4,
            ttl: std::time::Duration::from_secs(30 * 60),
            max_attempts: 10,
            consume_on_verify: true,
            allow_multiple: true,
            min_interval: None,
        }
    }
}

// ============================================================================
// 数据结构
// ============================================================================

/// OTP 数据
#[derive(Debug, Clone)]
pub struct OtpData {
    /// 生成的验证码
    pub code: String,

    /// 关联的用户标识
    pub identifier: String,

    /// OTP 用途
    pub purpose: OtpPurpose,

    /// 创建时间
    pub created_at: DateTime<Utc>,

    /// 过期时间
    pub expires_at: DateTime<Utc>,

    /// 剩余尝试次数
    pub remaining_attempts: u32,
}

impl OtpData {
    /// 检查是否已过期
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// 获取剩余有效时间（秒）
    pub fn remaining_seconds(&self) -> i64 {
        let remaining = self.expires_at - Utc::now();
        remaining.num_seconds().max(0)
    }
}

/// 内部存储的 OTP 记录
#[derive(Debug, Clone)]
pub struct StoredOtp {
    /// 验证码（存储用于比较）
    pub code: String,

    /// 过期时间
    pub expires_at: DateTime<Utc>,

    /// 创建时间
    pub created_at: DateTime<Utc>,

    /// 剩余尝试次数
    pub remaining_attempts: u32,
}

/// OTP 存储键
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct OtpKey {
    identifier: String,
    purpose: OtpPurpose,
}

// ============================================================================
// 存储接口
// ============================================================================

/// OTP 存储接口
///
/// 实现此 trait 以提供自定义的存储后端（如 Redis、数据库等）
pub trait OtpStore: Send + Sync {
    /// 保存 OTP
    fn save(
        &self,
        identifier: &str,
        purpose: OtpPurpose,
        code: &str,
        expires_at: DateTime<Utc>,
        max_attempts: u32,
    ) -> Result<()>;

    /// 获取 OTP
    fn get(&self, identifier: &str, purpose: OtpPurpose) -> Result<Option<StoredOtp>>;

    /// 更新剩余尝试次数
    fn decrement_attempts(&self, identifier: &str, purpose: OtpPurpose) -> Result<()>;

    /// 删除 OTP
    fn delete(&self, identifier: &str, purpose: OtpPurpose) -> Result<()>;

    /// 获取最后一次生成时间
    fn get_last_generated(
        &self,
        identifier: &str,
        purpose: OtpPurpose,
    ) -> Result<Option<DateTime<Utc>>>;

    /// 清理过期的 OTP
    fn cleanup_expired(&self) -> Result<usize>;
}

// ============================================================================
// 内存存储实现
// ============================================================================

/// 内存存储实现
///
/// 适用于单实例部署或测试环境。
/// 生产环境建议使用 Redis 等分布式存储。
#[derive(Debug, Clone, Default)]
pub struct InMemoryOtpStore {
    /// (identifier, purpose) -> 记录
    records: Arc<RwLock<HashMap<OtpKey, StoredOtp>>>,
}

impl InMemoryOtpStore {
    /// 创建新的内存存储
    pub fn new() -> Self {
        Self::default()
    }

    /// 获取当前存储的 OTP 数量
    pub fn len(&self) -> usize {
        self.records.read().unwrap().len()
    }

    /// 检查存储是否为空
    pub fn is_empty(&self) -> bool {
        self.records.read().unwrap().is_empty()
    }
}

impl OtpStore for InMemoryOtpStore {
    fn save(
        &self,
        identifier: &str,
        purpose: OtpPurpose,
        code: &str,
        expires_at: DateTime<Utc>,
        max_attempts: u32,
    ) -> Result<()> {
        let mut records = self.records.write().unwrap();
        let key = OtpKey {
            identifier: identifier.to_string(),
            purpose,
        };
        records.insert(
            key,
            StoredOtp {
                code: code.to_string(),
                expires_at,
                created_at: Utc::now(),
                remaining_attempts: max_attempts,
            },
        );
        Ok(())
    }

    fn get(&self, identifier: &str, purpose: OtpPurpose) -> Result<Option<StoredOtp>> {
        let records = self.records.read().unwrap();
        let key = OtpKey {
            identifier: identifier.to_string(),
            purpose,
        };
        Ok(records.get(&key).cloned())
    }

    fn decrement_attempts(&self, identifier: &str, purpose: OtpPurpose) -> Result<()> {
        let mut records = self.records.write().unwrap();
        let key = OtpKey {
            identifier: identifier.to_string(),
            purpose,
        };
        if let Some(record) = records.get_mut(&key) {
            record.remaining_attempts = record.remaining_attempts.saturating_sub(1);
        }
        Ok(())
    }

    fn delete(&self, identifier: &str, purpose: OtpPurpose) -> Result<()> {
        let mut records = self.records.write().unwrap();
        let key = OtpKey {
            identifier: identifier.to_string(),
            purpose,
        };
        records.remove(&key);
        Ok(())
    }

    fn get_last_generated(
        &self,
        identifier: &str,
        purpose: OtpPurpose,
    ) -> Result<Option<DateTime<Utc>>> {
        let records = self.records.read().unwrap();
        let key = OtpKey {
            identifier: identifier.to_string(),
            purpose,
        };
        Ok(records.get(&key).map(|r| r.created_at))
    }

    fn cleanup_expired(&self) -> Result<usize> {
        let mut records = self.records.write().unwrap();
        let now = Utc::now();
        let before = records.len();
        records.retain(|_, record| record.expires_at > now);
        Ok(before - records.len())
    }
}

// ============================================================================
// OTP 管理器
// ============================================================================

/// OTP 管理器
///
/// 负责生成和验证一次性密码。
///
/// ## 示例
///
/// ```rust
/// use authrs::passwordless::{OtpManager, OtpConfig, OtpPurpose};
///
/// let manager = OtpManager::new(OtpConfig::default());
///
/// // 生成 OTP
/// let otp = manager.generate("user@example.com", OtpPurpose::Login).unwrap();
/// println!("验证码: {}", otp.code);
///
/// // 验证 OTP
/// manager.verify("user@example.com", &otp.code, OtpPurpose::Login).unwrap();
/// ```
pub struct OtpManager<S: OtpStore = InMemoryOtpStore> {
    store: S,
    config: OtpConfig,
}

impl OtpManager<InMemoryOtpStore> {
    /// 使用默认内存存储创建管理器
    pub fn new(config: OtpConfig) -> Self {
        Self {
            store: InMemoryOtpStore::new(),
            config,
        }
    }

    /// 使用默认配置创建管理器
    pub fn with_default_config() -> Self {
        Self::new(OtpConfig::default())
    }
}

impl<S: OtpStore> OtpManager<S> {
    /// 使用自定义存储创建管理器
    pub fn with_store(store: S, config: OtpConfig) -> Self {
        Self { store, config }
    }

    /// 生成随机验证码
    fn generate_code(&self) -> String {
        let min = 10u64.pow((self.config.code_length - 1) as u32);
        let max = 10u64.pow(self.config.code_length as u32);
        let code = generate_random_in_range(min, max);
        format!("{:0>width$}", code, width = self.config.code_length)
    }

    /// 生成 OTP
    ///
    /// # Arguments
    ///
    /// * `identifier` - 用户标识（邮箱或手机号）
    /// * `purpose` - OTP 用途
    ///
    /// # Returns
    ///
    /// 返回包含验证码和元数据的 `OtpData`
    ///
    /// # Errors
    ///
    /// - 如果设置了最小间隔且距上次生成时间不足
    ///
    /// # Example
    ///
    /// ```rust
    /// use authrs::passwordless::{OtpManager, OtpConfig, OtpPurpose};
    ///
    /// let manager = OtpManager::new(OtpConfig::default());
    /// let otp = manager.generate("user@example.com", OtpPurpose::Login).unwrap();
    ///
    /// // 发送验证码给用户
    /// println!("请输入验证码: {}", otp.code);
    /// ```
    pub fn generate(&self, identifier: impl Into<String>, purpose: OtpPurpose) -> Result<OtpData> {
        let identifier = identifier.into();

        // 检查最小间隔
        if let Some(min_interval) = self.config.min_interval
            && let Some(last_generated) = self.store.get_last_generated(&identifier, purpose)?
        {
            let elapsed = Utc::now() - last_generated;
            let min_seconds = min_interval.as_secs() as i64;
            if elapsed.num_seconds() < min_seconds {
                let wait_seconds = min_seconds - elapsed.num_seconds();
                return Err(Error::validation(format!(
                    "please wait {} seconds before requesting a new code",
                    wait_seconds
                )));
            }
        }

        // 如果不允许多个，先删除现有的
        if !self.config.allow_multiple {
            self.store.delete(&identifier, purpose)?;
        }

        // 生成验证码
        let code = self.generate_code();

        // 计算过期时间
        let created_at = Utc::now();
        let expires_at = created_at + Duration::seconds(self.config.ttl.as_secs() as i64);

        // 保存
        self.store.save(
            &identifier,
            purpose,
            &code,
            expires_at,
            self.config.max_attempts,
        )?;

        Ok(OtpData {
            code,
            identifier,
            purpose,
            created_at,
            expires_at,
            remaining_attempts: self.config.max_attempts,
        })
    }

    /// 验证 OTP
    ///
    /// 使用常量时间比较防止时序攻击。
    ///
    /// # Arguments
    ///
    /// * `identifier` - 用户标识
    /// * `code` - 用户输入的验证码
    /// * `purpose` - OTP 用途
    ///
    /// # Returns
    ///
    /// 验证成功返回 `Ok(())`，失败返回错误
    ///
    /// # Errors
    ///
    /// - OTP 不存在
    /// - OTP 已过期
    /// - 验证码错误
    /// - 超过最大尝试次数
    ///
    /// # Example
    ///
    /// ```rust
    /// use authrs::passwordless::{OtpManager, OtpConfig, OtpPurpose};
    ///
    /// let manager = OtpManager::new(OtpConfig::default());
    /// let otp = manager.generate("user@example.com", OtpPurpose::Login).unwrap();
    ///
    /// // 验证正确的验证码
    /// assert!(manager.verify("user@example.com", &otp.code, OtpPurpose::Login).is_ok());
    ///
    /// // 验证码已被消费，再次验证会失败
    /// assert!(manager.verify("user@example.com", &otp.code, OtpPurpose::Login).is_err());
    /// ```
    pub fn verify(&self, identifier: &str, code: &str, purpose: OtpPurpose) -> Result<()> {
        // 获取存储的 OTP
        let stored = self
            .store
            .get(identifier, purpose)?
            .ok_or_else(|| Error::validation("no OTP found for this identifier and purpose"))?;

        // 检查是否过期
        if Utc::now() > stored.expires_at {
            self.store.delete(identifier, purpose)?;
            return Err(Error::validation("OTP has expired"));
        }

        // 检查剩余尝试次数
        if stored.remaining_attempts == 0 {
            self.store.delete(identifier, purpose)?;
            return Err(Error::validation("maximum attempts exceeded"));
        }

        // 使用常量时间比较验证码
        if !constant_time_compare_str(code, &stored.code) {
            // 减少尝试次数
            self.store.decrement_attempts(identifier, purpose)?;

            let remaining = stored.remaining_attempts.saturating_sub(1);
            if remaining == 0 {
                self.store.delete(identifier, purpose)?;
                return Err(Error::validation("invalid OTP, maximum attempts exceeded"));
            }

            return Err(Error::validation(format!(
                "invalid OTP, {} attempts remaining",
                remaining
            )));
        }

        // 验证成功，根据配置决定是否删除
        if self.config.consume_on_verify {
            self.store.delete(identifier, purpose)?;
        }

        Ok(())
    }

    /// 检查是否可以生成新的 OTP
    ///
    /// 检查是否超过了最小生成间隔。
    pub fn can_generate(&self, identifier: &str, purpose: OtpPurpose) -> Result<bool> {
        if let Some(min_interval) = self.config.min_interval
            && let Some(last_generated) = self.store.get_last_generated(identifier, purpose)?
        {
            let elapsed = Utc::now() - last_generated;
            let min_seconds = min_interval.as_secs() as i64;
            return Ok(elapsed.num_seconds() >= min_seconds);
        }
        Ok(true)
    }

    /// 获取距离可以重新生成的剩余秒数
    pub fn seconds_until_can_generate(&self, identifier: &str, purpose: OtpPurpose) -> Result<i64> {
        if let Some(min_interval) = self.config.min_interval
            && let Some(last_generated) = self.store.get_last_generated(identifier, purpose)?
        {
            let elapsed = Utc::now() - last_generated;
            let min_seconds = min_interval.as_secs() as i64;
            let remaining = min_seconds - elapsed.num_seconds();
            return Ok(remaining.max(0));
        }
        Ok(0)
    }

    /// 撤销 OTP
    pub fn revoke(&self, identifier: &str, purpose: OtpPurpose) -> Result<()> {
        self.store.delete(identifier, purpose)
    }

    /// 清理过期的 OTP
    pub fn cleanup(&self) -> Result<usize> {
        self.store.cleanup_expired()
    }

    /// 获取配置
    pub fn config(&self) -> &OtpConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::Duration as StdDuration;

    #[test]
    fn test_generate_and_verify() {
        let manager = OtpManager::new(OtpConfig::default().with_min_interval(None));

        let otp = manager
            .generate("user@example.com", OtpPurpose::Login)
            .unwrap();
        assert_eq!(otp.code.len(), 6);
        assert_eq!(otp.identifier, "user@example.com");
        assert_eq!(otp.purpose, OtpPurpose::Login);
        assert!(!otp.is_expired());

        // 验证成功
        assert!(
            manager
                .verify("user@example.com", &otp.code, OtpPurpose::Login)
                .is_ok()
        );
    }

    #[test]
    fn test_otp_consumed_after_verify() {
        let manager = OtpManager::new(OtpConfig::default().with_min_interval(None));

        let otp = manager
            .generate("user@example.com", OtpPurpose::Login)
            .unwrap();

        // 第一次验证成功
        assert!(
            manager
                .verify("user@example.com", &otp.code, OtpPurpose::Login)
                .is_ok()
        );

        // 第二次验证失败
        assert!(
            manager
                .verify("user@example.com", &otp.code, OtpPurpose::Login)
                .is_err()
        );
    }

    #[test]
    fn test_otp_not_consumed_when_disabled() {
        let config = OtpConfig::default()
            .with_consume_on_verify(false)
            .with_min_interval(None);
        let manager = OtpManager::new(config);

        let otp = manager
            .generate("user@example.com", OtpPurpose::Login)
            .unwrap();

        // 多次验证都成功
        assert!(
            manager
                .verify("user@example.com", &otp.code, OtpPurpose::Login)
                .is_ok()
        );
        assert!(
            manager
                .verify("user@example.com", &otp.code, OtpPurpose::Login)
                .is_ok()
        );
    }

    #[test]
    fn test_wrong_code() {
        let manager = OtpManager::new(OtpConfig::default().with_min_interval(None));

        let otp = manager
            .generate("user@example.com", OtpPurpose::Login)
            .unwrap();

        // 错误的验证码
        assert!(
            manager
                .verify("user@example.com", "000000", OtpPurpose::Login)
                .is_err()
        );

        // 正确的验证码仍然有效（还有尝试次数）
        assert!(
            manager
                .verify("user@example.com", &otp.code, OtpPurpose::Login)
                .is_ok()
        );
    }

    #[test]
    fn test_max_attempts() {
        let config = OtpConfig::default()
            .with_max_attempts(2)
            .with_min_interval(None);
        let manager = OtpManager::new(config);

        let otp = manager
            .generate("user@example.com", OtpPurpose::Login)
            .unwrap();

        // 错误尝试 1
        assert!(
            manager
                .verify("user@example.com", "000000", OtpPurpose::Login)
                .is_err()
        );

        // 错误尝试 2 - 超过最大次数
        assert!(
            manager
                .verify("user@example.com", "000000", OtpPurpose::Login)
                .is_err()
        );

        // 正确的验证码也无效了
        assert!(
            manager
                .verify("user@example.com", &otp.code, OtpPurpose::Login)
                .is_err()
        );
    }

    #[test]
    fn test_otp_expiration() {
        let config = OtpConfig::default()
            .with_ttl(StdDuration::from_millis(100))
            .with_min_interval(None);
        let manager = OtpManager::new(config);

        let otp = manager
            .generate("user@example.com", OtpPurpose::Login)
            .unwrap();

        // 等待过期
        sleep(StdDuration::from_millis(150));

        // 验证失败
        assert!(
            manager
                .verify("user@example.com", &otp.code, OtpPurpose::Login)
                .is_err()
        );
    }

    #[test]
    fn test_different_purposes_independent() {
        let manager = OtpManager::new(OtpConfig::default().with_min_interval(None));

        let login_otp = manager
            .generate("user@example.com", OtpPurpose::Login)
            .unwrap();
        let reset_otp = manager
            .generate("user@example.com", OtpPurpose::PasswordReset)
            .unwrap();

        // 不同用途的验证码不能混用
        assert!(
            manager
                .verify(
                    "user@example.com",
                    &login_otp.code,
                    OtpPurpose::PasswordReset
                )
                .is_err()
        );
        assert!(
            manager
                .verify("user@example.com", &reset_otp.code, OtpPurpose::Login)
                .is_err()
        );

        // 正确的用途可以验证
        assert!(
            manager
                .verify("user@example.com", &login_otp.code, OtpPurpose::Login)
                .is_ok()
        );
        assert!(
            manager
                .verify(
                    "user@example.com",
                    &reset_otp.code,
                    OtpPurpose::PasswordReset
                )
                .is_ok()
        );
    }

    #[test]
    fn test_min_interval() {
        let config = OtpConfig::default().with_min_interval(Some(StdDuration::from_secs(1)));
        let manager = OtpManager::new(config);

        // 第一次生成成功
        manager
            .generate("user@example.com", OtpPurpose::Login)
            .unwrap();

        // 立即再次生成失败
        assert!(
            manager
                .generate("user@example.com", OtpPurpose::Login)
                .is_err()
        );

        // 等待间隔后成功
        sleep(StdDuration::from_millis(1100));
        assert!(
            manager
                .generate("user@example.com", OtpPurpose::Login)
                .is_ok()
        );
    }

    #[test]
    fn test_code_length() {
        let config = OtpConfig::default()
            .with_code_length(8)
            .with_min_interval(None);
        let manager = OtpManager::new(config);

        let otp = manager
            .generate("user@example.com", OtpPurpose::Login)
            .unwrap();
        assert_eq!(otp.code.len(), 8);
    }

    #[test]
    fn test_revoke() {
        let manager = OtpManager::new(OtpConfig::default().with_min_interval(None));

        let otp = manager
            .generate("user@example.com", OtpPurpose::Login)
            .unwrap();

        // 撤销
        manager
            .revoke("user@example.com", OtpPurpose::Login)
            .unwrap();

        // 验证失败
        assert!(
            manager
                .verify("user@example.com", &otp.code, OtpPurpose::Login)
                .is_err()
        );
    }

    #[test]
    fn test_cleanup_expired() {
        let config = OtpConfig::default()
            .with_ttl(StdDuration::from_millis(100))
            .with_min_interval(None);
        let manager = OtpManager::new(config);

        manager
            .generate("user1@example.com", OtpPurpose::Login)
            .unwrap();
        manager
            .generate("user2@example.com", OtpPurpose::Login)
            .unwrap();

        // 等待过期
        sleep(StdDuration::from_millis(150));

        // 清理
        let cleaned = manager.cleanup().unwrap();
        assert_eq!(cleaned, 2);
    }

    #[test]
    fn test_can_generate() {
        let config = OtpConfig::default().with_min_interval(Some(StdDuration::from_secs(1)));
        let manager = OtpManager::new(config);

        // 初始可以生成
        assert!(
            manager
                .can_generate("user@example.com", OtpPurpose::Login)
                .unwrap()
        );

        manager
            .generate("user@example.com", OtpPurpose::Login)
            .unwrap();

        // 生成后不能立即再生成
        assert!(
            !manager
                .can_generate("user@example.com", OtpPurpose::Login)
                .unwrap()
        );

        // 等待后可以
        sleep(StdDuration::from_millis(1100));
        assert!(
            manager
                .can_generate("user@example.com", OtpPurpose::Login)
                .unwrap()
        );
    }

    #[test]
    fn test_seconds_until_can_generate() {
        let config = OtpConfig::default().with_min_interval(Some(StdDuration::from_secs(60)));
        let manager = OtpManager::new(config);

        // 初始为 0
        assert_eq!(
            manager
                .seconds_until_can_generate("user@example.com", OtpPurpose::Login)
                .unwrap(),
            0
        );

        manager
            .generate("user@example.com", OtpPurpose::Login)
            .unwrap();

        // 生成后接近 60 秒
        let seconds = manager
            .seconds_until_can_generate("user@example.com", OtpPurpose::Login)
            .unwrap();
        assert!(seconds > 55 && seconds <= 60);
    }

    #[test]
    fn test_high_security_config() {
        let config = OtpConfig::high_security();
        assert_eq!(config.code_length, 8);
        assert_eq!(config.ttl, StdDuration::from_secs(3 * 60));
        assert_eq!(config.max_attempts, 3);
    }

    #[test]
    fn test_relaxed_config() {
        let config = OtpConfig::relaxed();
        assert_eq!(config.code_length, 4);
        assert_eq!(config.ttl, StdDuration::from_secs(30 * 60));
        assert_eq!(config.max_attempts, 10);
    }

    #[test]
    fn test_otp_purpose_display() {
        assert_eq!(OtpPurpose::Login.to_string(), "login");
        assert_eq!(OtpPurpose::PasswordReset.to_string(), "password_reset");
        assert_eq!(OtpPurpose::Custom(42).to_string(), "custom_42");
    }

    #[test]
    fn test_remaining_seconds() {
        let config = OtpConfig::default()
            .with_ttl(StdDuration::from_secs(300))
            .with_min_interval(None);
        let manager = OtpManager::new(config);

        let otp = manager
            .generate("user@example.com", OtpPurpose::Login)
            .unwrap();

        let remaining = otp.remaining_seconds();
        assert!(remaining > 295 && remaining <= 300);
    }

    #[test]
    fn test_store_len_and_is_empty() {
        let store = InMemoryOtpStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);

        store
            .save(
                "user@example.com",
                OtpPurpose::Login,
                "123456",
                Utc::now() + Duration::hours(1),
                3,
            )
            .unwrap();
        assert!(!store.is_empty());
        assert_eq!(store.len(), 1);
    }
}
