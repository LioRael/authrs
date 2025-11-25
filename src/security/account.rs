//! 账户安全模块
//!
//! 提供账户级别的安全防护功能，包括：
//! - 账户锁定机制
//! - 登录尝试追踪
//! - 递增延迟策略
//! - 与速率限制模块集成

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

use crate::error::{Error, Result, StorageError};

/// 账户锁定配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountLockoutConfig {
    /// 触发锁定前允许的最大失败尝试次数
    pub max_failed_attempts: u32,

    /// 锁定持续时间
    pub lockout_duration: Duration,

    /// 是否启用递增延迟
    pub progressive_delay: bool,

    /// 基础延迟时间（用于递增延迟）
    pub base_delay: Duration,

    /// 最大延迟时间（递增延迟的上限）
    pub max_delay: Duration,

    /// 失败尝试记录的有效期（超过此时间后重置计数）
    pub attempt_window: Duration,

    /// 是否追踪 IP 地址
    pub track_ip: bool,

    /// 同一 IP 的最大失败尝试次数（0 表示不限制）
    pub max_ip_attempts: u32,
}

impl Default for AccountLockoutConfig {
    fn default() -> Self {
        Self {
            max_failed_attempts: 5,
            lockout_duration: Duration::minutes(15),
            progressive_delay: true,
            base_delay: Duration::seconds(1),
            max_delay: Duration::minutes(5),
            attempt_window: Duration::hours(1),
            track_ip: true,
            max_ip_attempts: 10,
        }
    }
}

impl AccountLockoutConfig {
    /// 创建严格的安全配置
    pub fn strict() -> Self {
        Self {
            max_failed_attempts: 3,
            lockout_duration: Duration::minutes(30),
            progressive_delay: true,
            base_delay: Duration::seconds(2),
            max_delay: Duration::minutes(10),
            attempt_window: Duration::hours(24),
            track_ip: true,
            max_ip_attempts: 5,
        }
    }

    /// 创建宽松的配置（适用于开发环境）
    pub fn relaxed() -> Self {
        Self {
            max_failed_attempts: 10,
            lockout_duration: Duration::minutes(5),
            progressive_delay: false,
            base_delay: Duration::seconds(0),
            max_delay: Duration::seconds(0),
            attempt_window: Duration::minutes(30),
            track_ip: false,
            max_ip_attempts: 0,
        }
    }

    /// 验证配置有效性
    pub fn validate(&self) -> Result<()> {
        if self.max_failed_attempts == 0 {
            return Err(Error::validation(
                "max_failed_attempts must be greater than 0",
            ));
        }
        if self.lockout_duration.num_seconds() <= 0 {
            return Err(Error::validation("lockout_duration must be greater than 0"));
        }
        Ok(())
    }
}

/// 登录尝试记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginAttempt {
    /// 尝试时间
    pub timestamp: DateTime<Utc>,

    /// 是否成功
    pub success: bool,

    /// IP 地址（可选）
    pub ip_address: Option<IpAddr>,

    /// 用户代理（可选）
    pub user_agent: Option<String>,

    /// 额外的元数据
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl LoginAttempt {
    /// 创建失败的登录尝试记录
    pub fn failed() -> Self {
        Self {
            timestamp: Utc::now(),
            success: false,
            ip_address: None,
            user_agent: None,
            metadata: HashMap::new(),
        }
    }

    /// 创建成功的登录尝试记录
    pub fn success() -> Self {
        Self {
            timestamp: Utc::now(),
            success: true,
            ip_address: None,
            user_agent: None,
            metadata: HashMap::new(),
        }
    }

    /// 设置 IP 地址
    pub fn with_ip(mut self, ip: IpAddr) -> Self {
        self.ip_address = Some(ip);
        self
    }

    /// 设置用户代理
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// 添加元数据
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// 账户锁定状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountLockStatus {
    /// 账户标识符
    pub account_id: String,

    /// 是否被锁定
    pub is_locked: bool,

    /// 锁定开始时间
    pub locked_at: Option<DateTime<Utc>>,

    /// 锁定结束时间
    pub locked_until: Option<DateTime<Utc>>,

    /// 当前失败尝试次数
    pub failed_attempts: u32,

    /// 最后一次尝试时间
    pub last_attempt_at: Option<DateTime<Utc>>,

    /// 最后一次成功登录时间
    pub last_success_at: Option<DateTime<Utc>>,

    /// 当前延迟时间（递增延迟）
    pub current_delay: Duration,

    /// 锁定原因
    pub lock_reason: Option<LockReason>,
}

/// 锁定原因
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockReason {
    /// 登录失败次数过多
    TooManyFailedAttempts,
    /// 可疑活动
    SuspiciousActivity,
    /// 管理员手动锁定
    AdminAction,
    /// IP 地址被封禁
    IpBanned,
    /// 其他原因
    Other,
}

impl AccountLockStatus {
    /// 创建新的账户状态
    pub fn new(account_id: impl Into<String>) -> Self {
        Self {
            account_id: account_id.into(),
            is_locked: false,
            locked_at: None,
            locked_until: None,
            failed_attempts: 0,
            last_attempt_at: None,
            last_success_at: None,
            current_delay: Duration::zero(),
            lock_reason: None,
        }
    }

    /// 检查账户是否当前被锁定
    pub fn is_currently_locked(&self) -> bool {
        if !self.is_locked {
            return false;
        }

        // 检查锁定是否已过期
        if let Some(locked_until) = self.locked_until {
            locked_until > Utc::now()
        } else {
            // 永久锁定
            true
        }
    }

    /// 获取剩余锁定时间
    pub fn remaining_lockout_time(&self) -> Option<Duration> {
        if !self.is_currently_locked() {
            return None;
        }

        self.locked_until.map(|until| {
            let remaining = until - Utc::now();
            if remaining.num_seconds() > 0 {
                remaining
            } else {
                Duration::zero()
            }
        })
    }

    /// 获取下次可以尝试登录的时间
    pub fn next_attempt_allowed_at(&self) -> Option<DateTime<Utc>> {
        if self.is_currently_locked() {
            return self.locked_until;
        }

        // 如果有递增延迟
        if self.current_delay.num_seconds() > 0 {
            self.last_attempt_at.map(|t| t + self.current_delay)
        } else {
            None
        }
    }

    /// 检查是否可以立即尝试登录
    pub fn can_attempt_now(&self) -> bool {
        if self.is_currently_locked() {
            return false;
        }

        // 检查递增延迟
        if let Some(next_allowed) = self.next_attempt_allowed_at() {
            Utc::now() >= next_allowed
        } else {
            true
        }
    }
}

/// 检查登录的结果
#[derive(Debug, Clone)]
pub enum LoginCheckResult {
    /// 允许登录尝试
    Allowed,

    /// 账户被锁定
    Locked {
        /// 锁定原因
        reason: LockReason,
        /// 剩余锁定时间
        remaining: Option<Duration>,
    },

    /// 需要等待（递增延迟）
    DelayRequired {
        /// 需要等待的时间
        wait_time: Duration,
    },

    /// IP 被封禁
    IpBanned {
        /// IP 地址
        ip: IpAddr,
    },
}

/// 账户锁定追踪器
#[derive(Debug)]
pub struct LoginAttemptTracker {
    /// 配置
    config: AccountLockoutConfig,

    /// 账户状态存储
    accounts: HashMap<String, AccountLockStatus>,

    /// IP 地址失败计数
    ip_attempts: HashMap<IpAddr, (u32, DateTime<Utc>)>,
}

impl LoginAttemptTracker {
    /// 创建新的追踪器
    pub fn new(config: AccountLockoutConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            config,
            accounts: HashMap::new(),
            ip_attempts: HashMap::new(),
        })
    }

    /// 使用默认配置创建追踪器
    pub fn with_default_config() -> Self {
        Self {
            config: AccountLockoutConfig::default(),
            accounts: HashMap::new(),
            ip_attempts: HashMap::new(),
        }
    }

    /// 获取配置引用
    pub fn config(&self) -> &AccountLockoutConfig {
        &self.config
    }

    /// 检查账户是否可以尝试登录
    pub fn check_login_allowed(
        &mut self,
        account_id: &str,
        ip: Option<IpAddr>,
    ) -> LoginCheckResult {
        // 清理过期数据
        self.cleanup_expired();

        // 检查 IP 封禁
        if let Some(ip_addr) = ip
            && self.is_ip_banned(ip_addr)
        {
            return LoginCheckResult::IpBanned { ip: ip_addr };
        }

        // 获取或创建账户状态
        let status = self
            .accounts
            .entry(account_id.to_string())
            .or_insert_with(|| AccountLockStatus::new(account_id));

        // 检查是否被锁定
        if status.is_currently_locked() {
            return LoginCheckResult::Locked {
                reason: status
                    .lock_reason
                    .unwrap_or(LockReason::TooManyFailedAttempts),
                remaining: status.remaining_lockout_time(),
            };
        }

        // 检查递增延迟
        if !status.can_attempt_now()
            && let Some(next_allowed) = status.next_attempt_allowed_at()
        {
            let wait_time = next_allowed - Utc::now();
            if wait_time.num_seconds() > 0 {
                return LoginCheckResult::DelayRequired {
                    wait_time: Duration::seconds(wait_time.num_seconds()),
                };
            }
        }

        LoginCheckResult::Allowed
    }

    /// 记录登录尝试
    pub fn record_attempt(&mut self, account_id: &str, attempt: &LoginAttempt) {
        let now = Utc::now();

        // 更新 IP 计数
        if self.config.track_ip
            && let Some(ip) = attempt.ip_address
        {
            if !attempt.success {
                let entry = self.ip_attempts.entry(ip).or_insert((0, now));
                entry.0 += 1;
                entry.1 = now;
            } else {
                // 成功登录时重置 IP 计数
                self.ip_attempts.remove(&ip);
            }
        }

        // 获取当前失败次数（用于计算延迟）
        let current_failed_attempts = self
            .accounts
            .get(account_id)
            .map(|s| s.failed_attempts)
            .unwrap_or(0);

        // 预先计算需要的值（避免后面的借用冲突）
        let progressive_delay = self.config.progressive_delay;
        let max_failed_attempts = self.config.max_failed_attempts;
        let lockout_duration = self.config.lockout_duration;

        // 计算新的失败次数和延迟
        let (new_failed_attempts, new_delay) = if attempt.success {
            (0, Duration::zero())
        } else {
            let new_count = current_failed_attempts + 1;
            let delay = if progressive_delay {
                self.calculate_delay(new_count)
            } else {
                Duration::zero()
            };
            (new_count, delay)
        };

        // 获取或创建账户状态
        let status = self
            .accounts
            .entry(account_id.to_string())
            .or_insert_with(|| AccountLockStatus::new(account_id));

        status.last_attempt_at = Some(now);

        if attempt.success {
            // 成功登录：重置状态
            status.failed_attempts = 0;
            status.is_locked = false;
            status.locked_at = None;
            status.locked_until = None;
            status.last_success_at = Some(now);
            status.current_delay = Duration::zero();
            status.lock_reason = None;
        } else {
            // 失败登录：更新状态
            status.failed_attempts = new_failed_attempts;
            status.current_delay = new_delay;

            // 检查是否需要锁定
            if status.failed_attempts >= max_failed_attempts {
                status.is_locked = true;
                status.locked_at = Some(now);
                status.locked_until = Some(now + lockout_duration);
                status.lock_reason = Some(LockReason::TooManyFailedAttempts);
            }
        }
    }

    /// 记录失败登录（简便方法）
    pub fn record_failed_attempt(&mut self, account_id: &str, ip: Option<IpAddr>) {
        let mut attempt = LoginAttempt::failed();
        if let Some(ip_addr) = ip {
            attempt = attempt.with_ip(ip_addr);
        }
        self.record_attempt(account_id, &attempt);
    }

    /// 记录成功登录（简便方法）
    pub fn record_successful_login(&mut self, account_id: &str, ip: Option<IpAddr>) {
        let mut attempt = LoginAttempt::success();
        if let Some(ip_addr) = ip {
            attempt = attempt.with_ip(ip_addr);
        }
        self.record_attempt(account_id, &attempt);
    }

    /// 获取账户状态
    pub fn get_account_status(&self, account_id: &str) -> Option<&AccountLockStatus> {
        self.accounts.get(account_id)
    }

    /// 手动锁定账户
    pub fn lock_account(
        &mut self,
        account_id: &str,
        reason: LockReason,
        duration: Option<Duration>,
    ) {
        let now = Utc::now();
        let status = self
            .accounts
            .entry(account_id.to_string())
            .or_insert_with(|| AccountLockStatus::new(account_id));

        status.is_locked = true;
        status.locked_at = Some(now);
        status.locked_until = duration.map(|d| now + d);
        status.lock_reason = Some(reason);
    }

    /// 解锁账户
    pub fn unlock_account(&mut self, account_id: &str) {
        if let Some(status) = self.accounts.get_mut(account_id) {
            status.is_locked = false;
            status.locked_at = None;
            status.locked_until = None;
            status.failed_attempts = 0;
            status.current_delay = Duration::zero();
            status.lock_reason = None;
        }
    }

    /// 重置账户的失败尝试计数
    pub fn reset_failed_attempts(&mut self, account_id: &str) {
        if let Some(status) = self.accounts.get_mut(account_id) {
            status.failed_attempts = 0;
            status.current_delay = Duration::zero();
        }
    }

    /// 封禁 IP 地址
    pub fn ban_ip(&mut self, ip: IpAddr) {
        // 设置一个非常高的失败计数来触发封禁
        self.ip_attempts
            .insert(ip, (self.config.max_ip_attempts + 1, Utc::now()));
    }

    /// 解封 IP 地址
    pub fn unban_ip(&mut self, ip: &IpAddr) {
        self.ip_attempts.remove(ip);
    }

    /// 检查 IP 是否被封禁
    fn is_ip_banned(&self, ip: IpAddr) -> bool {
        if self.config.max_ip_attempts == 0 {
            return false;
        }

        if let Some((count, _)) = self.ip_attempts.get(&ip) {
            *count >= self.config.max_ip_attempts
        } else {
            false
        }
    }

    /// 计算递增延迟时间
    fn calculate_delay(&self, failed_attempts: u32) -> Duration {
        if failed_attempts == 0 {
            return Duration::zero();
        }

        // 指数退避：base_delay * 2^(attempts - 1)
        let multiplier = 2_i64.pow(failed_attempts.saturating_sub(1));
        let delay_seconds = self.config.base_delay.num_seconds() * multiplier;

        let delay = Duration::seconds(delay_seconds);

        // 限制最大延迟
        if delay > self.config.max_delay {
            self.config.max_delay
        } else {
            delay
        }
    }

    /// 清理过期数据
    fn cleanup_expired(&mut self) {
        let now = Utc::now();
        let window = self.config.attempt_window;

        // 清理过期的账户状态
        self.accounts.retain(|_, status| {
            // 保留被锁定的账户
            if status.is_currently_locked() {
                return true;
            }

            // 清理超过窗口期的账户
            if let Some(last_attempt) = status.last_attempt_at {
                now - last_attempt < window
            } else {
                false
            }
        });

        // 清理过期的 IP 记录
        self.ip_attempts
            .retain(|_, (_, timestamp)| now - *timestamp < window);
    }

    /// 获取所有被锁定的账户
    pub fn get_locked_accounts(&self) -> Vec<&AccountLockStatus> {
        self.accounts
            .values()
            .filter(|s| s.is_currently_locked())
            .collect()
    }

    /// 获取追踪器统计信息
    pub fn stats(&self) -> TrackerStats {
        let locked_count = self
            .accounts
            .values()
            .filter(|s| s.is_currently_locked())
            .count();
        let total_accounts = self.accounts.len();
        let banned_ips = self
            .ip_attempts
            .iter()
            .filter(|(_, (count, _))| *count >= self.config.max_ip_attempts)
            .count();

        TrackerStats {
            total_tracked_accounts: total_accounts,
            currently_locked_accounts: locked_count,
            banned_ip_addresses: banned_ips,
            total_tracked_ips: self.ip_attempts.len(),
        }
    }
}

/// 追踪器统计信息
#[derive(Debug, Clone)]
pub struct TrackerStats {
    /// 总追踪账户数
    pub total_tracked_accounts: usize,
    /// 当前被锁定的账户数
    pub currently_locked_accounts: usize,
    /// 被封禁的 IP 数
    pub banned_ip_addresses: usize,
    /// 总追踪的 IP 数
    pub total_tracked_ips: usize,
}

/// 账户锁定存储 trait
///
/// 实现此 trait 以提供持久化存储支持
pub trait AccountLockStore: Send + Sync {
    /// 保存账户状态
    fn save(&mut self, status: &AccountLockStatus) -> Result<()>;

    /// 加载账户状态
    fn load(&self, account_id: &str) -> Result<Option<AccountLockStatus>>;

    /// 删除账户状态
    fn delete(&mut self, account_id: &str) -> Result<()>;

    /// 列出所有被锁定的账户
    fn list_locked(&self) -> Result<Vec<AccountLockStatus>>;
}

/// 内存存储实现
#[derive(Debug, Default)]
pub struct InMemoryAccountLockStore {
    data: HashMap<String, AccountLockStatus>,
}

impl InMemoryAccountLockStore {
    /// 创建新的内存存储
    pub fn new() -> Self {
        Self::default()
    }
}

impl AccountLockStore for InMemoryAccountLockStore {
    fn save(&mut self, status: &AccountLockStatus) -> Result<()> {
        self.data.insert(status.account_id.clone(), status.clone());
        Ok(())
    }

    fn load(&self, account_id: &str) -> Result<Option<AccountLockStatus>> {
        Ok(self.data.get(account_id).cloned())
    }

    fn delete(&mut self, account_id: &str) -> Result<()> {
        self.data
            .remove(account_id)
            .ok_or_else(|| Error::Storage(StorageError::NotFound(account_id.to_string())))?;
        Ok(())
    }

    fn list_locked(&self) -> Result<Vec<AccountLockStatus>> {
        Ok(self
            .data
            .values()
            .filter(|s| s.is_currently_locked())
            .cloned()
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_default_config() {
        let config = AccountLockoutConfig::default();
        assert_eq!(config.max_failed_attempts, 5);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_strict_config() {
        let config = AccountLockoutConfig::strict();
        assert_eq!(config.max_failed_attempts, 3);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_account_locking() {
        let mut tracker = LoginAttemptTracker::with_default_config();

        // 模拟多次失败登录
        for _ in 0..5 {
            tracker.record_failed_attempt("user1", None);
        }

        // 检查账户是否被锁定
        let result = tracker.check_login_allowed("user1", None);
        assert!(matches!(result, LoginCheckResult::Locked { .. }));
    }

    #[test]
    fn test_successful_login_resets() {
        let mut tracker = LoginAttemptTracker::with_default_config();

        // 模拟几次失败
        for _ in 0..3 {
            tracker.record_failed_attempt("user1", None);
        }

        // 成功登录
        tracker.record_successful_login("user1", None);

        // 检查状态已重置
        let status = tracker.get_account_status("user1").unwrap();
        assert_eq!(status.failed_attempts, 0);
        assert!(!status.is_locked);
    }

    #[test]
    fn test_progressive_delay() {
        let config = AccountLockoutConfig {
            progressive_delay: true,
            base_delay: Duration::seconds(1),
            max_delay: Duration::minutes(5),
            ..Default::default()
        };

        let mut tracker = LoginAttemptTracker::new(config).unwrap();

        // 第一次失败
        tracker.record_failed_attempt("user1", None);
        let status = tracker.get_account_status("user1").unwrap();
        assert_eq!(status.current_delay.num_seconds(), 1);

        // 第二次失败
        tracker.record_failed_attempt("user1", None);
        let status = tracker.get_account_status("user1").unwrap();
        assert_eq!(status.current_delay.num_seconds(), 2);

        // 第三次失败
        tracker.record_failed_attempt("user1", None);
        let status = tracker.get_account_status("user1").unwrap();
        assert_eq!(status.current_delay.num_seconds(), 4);
    }

    #[test]
    fn test_ip_tracking() {
        let config = AccountLockoutConfig {
            track_ip: true,
            max_ip_attempts: 3,
            ..Default::default()
        };

        let mut tracker = LoginAttemptTracker::new(config).unwrap();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // 模拟来自同一 IP 的多次失败
        for _ in 0..3 {
            tracker.record_failed_attempt("user1", Some(ip));
        }

        // 检查 IP 是否被封禁
        let result = tracker.check_login_allowed("user2", Some(ip));
        assert!(matches!(result, LoginCheckResult::IpBanned { .. }));
    }

    #[test]
    fn test_manual_lock_unlock() {
        let mut tracker = LoginAttemptTracker::with_default_config();

        // 手动锁定
        tracker.lock_account("user1", LockReason::AdminAction, None);

        let result = tracker.check_login_allowed("user1", None);
        assert!(matches!(
            result,
            LoginCheckResult::Locked {
                reason: LockReason::AdminAction,
                ..
            }
        ));

        // 解锁
        tracker.unlock_account("user1");

        let result = tracker.check_login_allowed("user1", None);
        assert!(matches!(result, LoginCheckResult::Allowed));
    }

    #[test]
    fn test_lock_status() {
        let mut status = AccountLockStatus::new("user1");
        assert!(!status.is_currently_locked());

        status.is_locked = true;
        status.locked_until = Some(Utc::now() + Duration::hours(1));

        assert!(status.is_currently_locked());
        assert!(status.remaining_lockout_time().is_some());
    }

    #[test]
    fn test_tracker_stats() {
        let mut tracker = LoginAttemptTracker::with_default_config();

        // 锁定一个账户
        tracker.lock_account("user1", LockReason::AdminAction, None);

        let stats = tracker.stats();
        assert_eq!(stats.total_tracked_accounts, 1);
        assert_eq!(stats.currently_locked_accounts, 1);
    }

    #[test]
    fn test_in_memory_store() {
        let mut store = InMemoryAccountLockStore::new();

        let status = AccountLockStatus::new("user1");
        store.save(&status).unwrap();

        let loaded = store.load("user1").unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().account_id, "user1");

        store.delete("user1").unwrap();
        assert!(store.load("user1").unwrap().is_none());
    }

    #[test]
    fn test_login_attempt_builder() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let attempt = LoginAttempt::failed()
            .with_ip(ip)
            .with_user_agent("Mozilla/5.0")
            .with_metadata("reason", "invalid_password");

        assert!(!attempt.success);
        assert_eq!(attempt.ip_address, Some(ip));
        assert_eq!(attempt.user_agent, Some("Mozilla/5.0".to_string()));
        assert_eq!(
            attempt.metadata.get("reason"),
            Some(&"invalid_password".to_string())
        );
    }
}
