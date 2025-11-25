//! 速率限制模块
//!
//! 提供基于滑动窗口和令牌桶算法的速率限制实现，用于防止暴力破解攻击。
//!
//! ## 功能特性
//!
//! - **滑动窗口算法**: 精确的时间窗口内请求计数
//! - **令牌桶算法**: 支持突发流量的平滑限流
//! - **可插拔存储**: 支持内存存储，可扩展为 Redis 等
//! - **灵活配置**: 支持不同场景的限流策略
//!
//! ## 示例
//!
//! ```rust
//! use authrs::security::rate_limit::{RateLimiter, RateLimitConfig};
//! use std::time::Duration;
//!
//! // 创建速率限制器：每分钟最多 5 次请求
//! let config = RateLimitConfig::new()
//!     .with_max_requests(5)
//!     .with_window(Duration::from_secs(60));
//! let limiter = RateLimiter::new(config);
//!
//! // 检查请求
//! let key = "user:123:login";
//! let result = limiter.check(key);
//! assert!(result.is_ok());
//! ```

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

/// 速率限制配置
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// 时间窗口内允许的最大请求数
    pub max_requests: u32,
    /// 时间窗口大小
    pub window: Duration,
    /// 是否启用滑动窗口（默认启用）
    pub sliding_window: bool,
    /// 封禁时长（超过限制后的额外封禁时间）
    pub ban_duration: Option<Duration>,
    /// 封禁阈值（连续超限次数达到此值后触发封禁）
    pub ban_threshold: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window: Duration::from_secs(60),
            sliding_window: true,
            ban_duration: None,
            ban_threshold: 3,
        }
    }
}

impl RateLimitConfig {
    /// 创建新的配置
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置最大请求数
    pub fn with_max_requests(mut self, max: u32) -> Self {
        self.max_requests = max;
        self
    }

    /// 设置时间窗口
    pub fn with_window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }

    /// 设置是否使用滑动窗口
    pub fn with_sliding_window(mut self, enabled: bool) -> Self {
        self.sliding_window = enabled;
        self
    }

    /// 设置封禁时长
    pub fn with_ban_duration(mut self, duration: Duration) -> Self {
        self.ban_duration = Some(duration);
        self
    }

    /// 设置封禁阈值
    pub fn with_ban_threshold(mut self, threshold: u32) -> Self {
        self.ban_threshold = threshold;
        self
    }

    /// 登录场景的预设配置
    ///
    /// 每分钟最多 5 次尝试，连续 3 次超限后封禁 15 分钟
    pub fn for_login() -> Self {
        Self {
            max_requests: 5,
            window: Duration::from_secs(60),
            sliding_window: true,
            ban_duration: Some(Duration::from_secs(900)), // 15 分钟
            ban_threshold: 3,
        }
    }

    /// API 场景的预设配置
    ///
    /// 每分钟最多 60 次请求
    pub fn for_api() -> Self {
        Self {
            max_requests: 60,
            window: Duration::from_secs(60),
            sliding_window: true,
            ban_duration: None,
            ban_threshold: 5,
        }
    }

    /// 密码重置场景的预设配置
    ///
    /// 每小时最多 3 次尝试
    pub fn for_password_reset() -> Self {
        Self {
            max_requests: 3,
            window: Duration::from_secs(3600),
            sliding_window: true,
            ban_duration: Some(Duration::from_secs(3600)),
            ban_threshold: 2,
        }
    }
}

/// 速率限制信息
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    /// 剩余请求次数
    pub remaining: u32,
    /// 总限制次数
    pub limit: u32,
    /// 窗口重置时间（距现在的秒数）
    pub reset_after: Duration,
    /// 是否被封禁
    pub is_banned: bool,
    /// 封禁剩余时间（如果被封禁）
    pub ban_remaining: Option<Duration>,
}

impl RateLimitInfo {
    /// 创建一个表示允许请求的信息
    pub fn allowed(remaining: u32, limit: u32, reset_after: Duration) -> Self {
        Self {
            remaining,
            limit,
            reset_after,
            is_banned: false,
            ban_remaining: None,
        }
    }

    /// 创建一个表示被限制的信息
    pub fn limited(limit: u32, reset_after: Duration) -> Self {
        Self {
            remaining: 0,
            limit,
            reset_after,
            is_banned: false,
            ban_remaining: None,
        }
    }

    /// 创建一个表示被封禁的信息
    pub fn banned(limit: u32, ban_remaining: Duration) -> Self {
        Self {
            remaining: 0,
            limit,
            reset_after: ban_remaining,
            is_banned: true,
            ban_remaining: Some(ban_remaining),
        }
    }
}

/// 请求记录（用于滑动窗口）
#[derive(Debug, Clone)]
struct RequestRecord {
    /// 请求时间戳列表
    timestamps: Vec<Instant>,
    /// 连续超限次数
    violation_count: u32,
    /// 封禁结束时间
    banned_until: Option<Instant>,
}

impl RequestRecord {
    fn new() -> Self {
        Self {
            timestamps: Vec::new(),
            violation_count: 0,
            banned_until: None,
        }
    }

    /// 清理过期的时间戳
    fn cleanup(&mut self, window: Duration) {
        let cutoff = Instant::now() - window;
        self.timestamps.retain(|&ts| ts > cutoff);
    }

    /// 检查是否被封禁
    fn is_banned(&self) -> bool {
        if let Some(until) = self.banned_until {
            Instant::now() < until
        } else {
            false
        }
    }

    /// 获取封禁剩余时间
    fn ban_remaining(&self) -> Option<Duration> {
        self.banned_until.and_then(|until| {
            let now = Instant::now();
            if now < until { Some(until - now) } else { None }
        })
    }
}

/// 固定窗口记录
#[derive(Debug, Clone)]
struct FixedWindowRecord {
    /// 当前窗口的请求计数
    count: u32,
    /// 窗口开始时间
    window_start: Instant,
    /// 连续超限次数
    violation_count: u32,
    /// 封禁结束时间
    banned_until: Option<Instant>,
}

impl FixedWindowRecord {
    fn new() -> Self {
        Self {
            count: 0,
            window_start: Instant::now(),
            violation_count: 0,
            banned_until: None,
        }
    }

    /// 检查并重置窗口
    fn check_reset(&mut self, window: Duration) {
        if self.window_start.elapsed() >= window {
            self.count = 0;
            self.window_start = Instant::now();
        }
    }

    /// 检查是否被封禁
    fn is_banned(&self) -> bool {
        if let Some(until) = self.banned_until {
            Instant::now() < until
        } else {
            false
        }
    }

    /// 获取封禁剩余时间
    fn ban_remaining(&self) -> Option<Duration> {
        self.banned_until.and_then(|until| {
            let now = Instant::now();
            if now < until { Some(until - now) } else { None }
        })
    }
}

/// 速率限制器存储 trait
#[async_trait]
pub trait RateLimitStore: Send + Sync {
    /// 检查并记录请求
    ///
    /// 返回 `Ok(RateLimitInfo)` 如果请求被允许，
    /// 返回 `Err` 如果请求被限制
    async fn check_and_record(&self, key: &str, config: &RateLimitConfig) -> Result<RateLimitInfo>;

    /// 重置某个 key 的限制
    async fn reset(&self, key: &str);

    /// 获取当前状态（不记录请求）
    async fn get_status(&self, key: &str, config: &RateLimitConfig) -> RateLimitInfo;

    /// 手动封禁某个 key
    async fn ban(&self, key: &str, duration: Duration);

    /// 解除封禁
    async fn unban(&self, key: &str);

    /// 清理过期记录
    async fn cleanup(&self);
}

/// 内存速率限制存储（滑动窗口）
#[derive(Debug)]
pub struct InMemorySlidingWindowStore {
    records: RwLock<HashMap<String, RequestRecord>>,
}

impl Default for InMemorySlidingWindowStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemorySlidingWindowStore {
    /// 创建新的内存存储
    pub fn new() -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl RateLimitStore for InMemorySlidingWindowStore {
    async fn check_and_record(&self, key: &str, config: &RateLimitConfig) -> Result<RateLimitInfo> {
        let mut records = self
            .records
            .write()
            .map_err(|_| Error::internal("Failed to acquire lock"))?;

        let record = records
            .entry(key.to_string())
            .or_insert_with(RequestRecord::new);

        // 检查是否被封禁
        if record.is_banned() {
            let ban_remaining = record.ban_remaining().unwrap_or(Duration::ZERO);
            return Err(Error::rate_limited(ban_remaining));
        }

        // 清理封禁状态（如果已过期）
        if record.banned_until.is_some() && !record.is_banned() {
            record.banned_until = None;
            record.violation_count = 0;
        }

        // 清理过期时间戳
        record.cleanup(config.window);

        let current_count = record.timestamps.len() as u32;

        // 检查是否超过限制
        if current_count >= config.max_requests {
            record.violation_count += 1;

            // 检查是否需要封禁
            if let Some(ban_duration) = config.ban_duration
                && record.violation_count >= config.ban_threshold
            {
                record.banned_until = Some(Instant::now() + ban_duration);
                return Err(Error::rate_limited(ban_duration));
            }

            let reset_after = record
                .timestamps
                .first()
                .map(|ts| config.window.saturating_sub(ts.elapsed()))
                .unwrap_or(config.window);

            return Err(Error::rate_limited(reset_after));
        }

        // 记录请求
        record.timestamps.push(Instant::now());

        let remaining = config.max_requests - current_count - 1;
        let reset_after = record
            .timestamps
            .first()
            .map(|ts| config.window.saturating_sub(ts.elapsed()))
            .unwrap_or(config.window);

        Ok(RateLimitInfo::allowed(
            remaining,
            config.max_requests,
            reset_after,
        ))
    }

    async fn reset(&self, key: &str) {
        if let Ok(mut records) = self.records.write() {
            records.remove(key);
        }
    }

    async fn get_status(&self, key: &str, config: &RateLimitConfig) -> RateLimitInfo {
        let records = match self.records.read() {
            Ok(r) => r,
            Err(_) => {
                return RateLimitInfo::allowed(
                    config.max_requests,
                    config.max_requests,
                    config.window,
                );
            }
        };

        match records.get(key) {
            Some(record) => {
                if record.is_banned() {
                    let ban_remaining = record.ban_remaining().unwrap_or(Duration::ZERO);
                    RateLimitInfo::banned(config.max_requests, ban_remaining)
                } else {
                    let cutoff = Instant::now() - config.window;
                    let count = record.timestamps.iter().filter(|&&ts| ts > cutoff).count() as u32;
                    let remaining = config.max_requests.saturating_sub(count);
                    let reset_after = record
                        .timestamps
                        .iter()
                        .find(|&&ts| ts > cutoff)
                        .map(|ts| config.window.saturating_sub(ts.elapsed()))
                        .unwrap_or(config.window);
                    RateLimitInfo::allowed(remaining, config.max_requests, reset_after)
                }
            }
            None => RateLimitInfo::allowed(config.max_requests, config.max_requests, config.window),
        }
    }

    async fn ban(&self, key: &str, duration: Duration) {
        if let Ok(mut records) = self.records.write() {
            let record = records
                .entry(key.to_string())
                .or_insert_with(RequestRecord::new);
            record.banned_until = Some(Instant::now() + duration);
        }
    }

    async fn unban(&self, key: &str) {
        if let Ok(mut records) = self.records.write()
            && let Some(record) = records.get_mut(key)
        {
            record.banned_until = None;
            record.violation_count = 0;
        }
    }

    async fn cleanup(&self) {
        if let Ok(mut records) = self.records.write() {
            let now = Instant::now();
            records.retain(|_, record| {
                // 保留被封禁的记录
                if let Some(until) = record.banned_until
                    && now < until
                {
                    return true;
                }
                // 保留最近有请求的记录（最近 1 小时）
                if let Some(last) = record.timestamps.last() {
                    last.elapsed() < Duration::from_secs(3600)
                } else {
                    false
                }
            });
        }
    }
}

/// 内存速率限制存储（固定窗口）
#[derive(Debug)]
pub struct InMemoryFixedWindowStore {
    records: RwLock<HashMap<String, FixedWindowRecord>>,
}

impl Default for InMemoryFixedWindowStore {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryFixedWindowStore {
    /// 创建新的内存存储
    pub fn new() -> Self {
        Self {
            records: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl RateLimitStore for InMemoryFixedWindowStore {
    async fn check_and_record(&self, key: &str, config: &RateLimitConfig) -> Result<RateLimitInfo> {
        let mut records = self
            .records
            .write()
            .map_err(|_| Error::internal("Failed to acquire lock"))?;

        let record = records
            .entry(key.to_string())
            .or_insert_with(FixedWindowRecord::new);

        // 检查是否被封禁
        if record.is_banned() {
            let ban_remaining = record.ban_remaining().unwrap_or(Duration::ZERO);
            return Err(Error::rate_limited(ban_remaining));
        }

        // 清理封禁状态
        if record.banned_until.is_some() && !record.is_banned() {
            record.banned_until = None;
            record.violation_count = 0;
        }

        // 检查并重置窗口
        record.check_reset(config.window);

        // 检查是否超过限制
        if record.count >= config.max_requests {
            record.violation_count += 1;

            // 检查是否需要封禁
            if let Some(ban_duration) = config.ban_duration
                && record.violation_count >= config.ban_threshold
            {
                record.banned_until = Some(Instant::now() + ban_duration);
                return Err(Error::rate_limited(ban_duration));
            }

            let reset_after = config.window.saturating_sub(record.window_start.elapsed());
            return Err(Error::rate_limited(reset_after));
        }

        // 记录请求
        record.count += 1;

        let remaining = config.max_requests - record.count;
        let reset_after = config.window.saturating_sub(record.window_start.elapsed());

        Ok(RateLimitInfo::allowed(
            remaining,
            config.max_requests,
            reset_after,
        ))
    }

    async fn reset(&self, key: &str) {
        if let Ok(mut records) = self.records.write() {
            records.remove(key);
        }
    }

    async fn get_status(&self, key: &str, config: &RateLimitConfig) -> RateLimitInfo {
        let records = match self.records.read() {
            Ok(r) => r,
            Err(_) => {
                return RateLimitInfo::allowed(
                    config.max_requests,
                    config.max_requests,
                    config.window,
                );
            }
        };

        match records.get(key) {
            Some(record) => {
                if record.is_banned() {
                    let ban_remaining = record.ban_remaining().unwrap_or(Duration::ZERO);
                    RateLimitInfo::banned(config.max_requests, ban_remaining)
                } else {
                    let elapsed = record.window_start.elapsed();
                    if elapsed >= config.window {
                        RateLimitInfo::allowed(
                            config.max_requests,
                            config.max_requests,
                            config.window,
                        )
                    } else {
                        let remaining = config.max_requests.saturating_sub(record.count);
                        let reset_after = config.window.saturating_sub(elapsed);
                        RateLimitInfo::allowed(remaining, config.max_requests, reset_after)
                    }
                }
            }
            None => RateLimitInfo::allowed(config.max_requests, config.max_requests, config.window),
        }
    }

    async fn ban(&self, key: &str, duration: Duration) {
        if let Ok(mut records) = self.records.write() {
            let record = records
                .entry(key.to_string())
                .or_insert_with(FixedWindowRecord::new);
            record.banned_until = Some(Instant::now() + duration);
        }
    }

    async fn unban(&self, key: &str) {
        if let Ok(mut records) = self.records.write()
            && let Some(record) = records.get_mut(key)
        {
            record.banned_until = None;
            record.violation_count = 0;
        }
    }

    async fn cleanup(&self) {
        if let Ok(mut records) = self.records.write() {
            let now = Instant::now();
            records.retain(|_, record| {
                // 保留被封禁的记录
                if let Some(until) = record.banned_until
                    && now < until
                {
                    return true;
                }
                // 保留最近 1 小时内活跃的窗口
                record.window_start.elapsed() < Duration::from_secs(3600)
            });
        }
    }
}

/// 速率限制器
///
/// 提供便捷的速率限制 API，内部使用可配置的存储后端。
///
/// ## 示例
///
/// ```rust
/// use authrs::security::rate_limit::{RateLimiter, RateLimitConfig};
/// use std::time::Duration;
///
/// // 创建登录场景的限制器
/// let limiter = RateLimiter::with_config(RateLimitConfig::for_login());
///
/// // 检查请求
/// let key = "login:user@example.com";
/// match limiter.check(key) {
///     Ok(info) => println!("允许，剩余 {} 次", info.remaining),
///     Err(e) => println!("被限制: {:?}", e),
/// }
/// ```
pub struct RateLimiter {
    config: RateLimitConfig,
    store: Arc<dyn RateLimitStore>,
}

impl RateLimiter {
    /// 使用默认配置创建限制器
    pub fn new(config: RateLimitConfig) -> Self {
        let store: Arc<dyn RateLimitStore> = if config.sliding_window {
            Arc::new(InMemorySlidingWindowStore::new())
        } else {
            Arc::new(InMemoryFixedWindowStore::new())
        };

        Self { config, store }
    }

    /// 使用指定配置创建限制器
    pub fn with_config(config: RateLimitConfig) -> Self {
        Self::new(config)
    }

    /// 使用自定义存储创建限制器
    pub fn with_store<S: RateLimitStore + 'static>(config: RateLimitConfig, store: S) -> Self {
        Self {
            config,
            store: Arc::new(store),
        }
    }

    /// 检查请求是否被允许
    ///
    /// 如果允许，记录请求并返回限制信息；
    /// 如果被限制，返回错误。
    pub async fn check(&self, key: &str) -> Result<RateLimitInfo> {
        self.store.check_and_record(key, &self.config).await
    }

    /// 获取当前状态（不记录请求）
    pub async fn status(&self, key: &str) -> RateLimitInfo {
        self.store.get_status(key, &self.config).await
    }

    /// 重置某个 key 的限制
    pub async fn reset(&self, key: &str) {
        self.store.reset(key).await;
    }

    /// 手动封禁某个 key
    pub async fn ban(&self, key: &str, duration: Duration) {
        self.store.ban(key, duration).await;
    }

    /// 解除封禁
    pub async fn unban(&self, key: &str) {
        self.store.unban(key).await;
    }

    /// 清理过期记录
    pub async fn cleanup(&self) {
        self.store.cleanup().await;
    }

    /// 获取配置
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }
}

/// 令牌桶配置
#[derive(Debug, Clone)]
pub struct TokenBucketConfig {
    /// 桶容量（最大令牌数）
    pub capacity: u32,
    /// 令牌补充速率（每秒补充的令牌数）
    pub refill_rate: f64,
    /// 每次请求消耗的令牌数
    pub tokens_per_request: u32,
}

impl Default for TokenBucketConfig {
    fn default() -> Self {
        Self {
            capacity: 100,
            refill_rate: 10.0, // 每秒 10 个令牌
            tokens_per_request: 1,
        }
    }
}

impl TokenBucketConfig {
    /// 创建新配置
    pub fn new(capacity: u32, refill_rate: f64) -> Self {
        Self {
            capacity,
            refill_rate,
            tokens_per_request: 1,
        }
    }

    /// 设置每次请求消耗的令牌数
    pub fn with_tokens_per_request(mut self, tokens: u32) -> Self {
        self.tokens_per_request = tokens;
        self
    }
}

/// 令牌桶状态
#[derive(Debug, Clone)]
struct TokenBucket {
    /// 当前令牌数
    tokens: f64,
    /// 上次更新时间
    last_update: Instant,
}

impl TokenBucket {
    fn new(capacity: u32) -> Self {
        Self {
            tokens: capacity as f64,
            last_update: Instant::now(),
        }
    }

    /// 补充令牌
    fn refill(&mut self, config: &TokenBucketConfig) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        let refilled = elapsed * config.refill_rate;
        self.tokens = (self.tokens + refilled).min(config.capacity as f64);
        self.last_update = now;
    }

    /// 尝试消耗令牌
    fn try_consume(&mut self, tokens: u32, config: &TokenBucketConfig) -> bool {
        self.refill(config);
        let tokens = tokens as f64;
        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    /// 获取当前令牌数
    fn current_tokens(&mut self, config: &TokenBucketConfig) -> f64 {
        self.refill(config);
        self.tokens
    }
}

/// 令牌桶限制器
///
/// 使用令牌桶算法进行速率限制，支持突发流量。
///
/// ## 示例
///
/// ```rust
/// use authrs::security::rate_limit::{TokenBucketLimiter, TokenBucketConfig};
///
/// // 创建令牌桶：容量 100，每秒补充 10 个
/// let config = TokenBucketConfig::new(100, 10.0);
/// let limiter = TokenBucketLimiter::new(config);
///
/// // 检查请求
/// let allowed = limiter.check("api:user:123");
/// ```
pub struct TokenBucketLimiter {
    config: TokenBucketConfig,
    buckets: RwLock<HashMap<String, TokenBucket>>,
}

impl TokenBucketLimiter {
    /// 创建新的令牌桶限制器
    pub fn new(config: TokenBucketConfig) -> Self {
        Self {
            config,
            buckets: RwLock::new(HashMap::new()),
        }
    }

    /// 检查请求是否被允许
    pub fn check(&self, key: &str) -> bool {
        self.try_consume(key, self.config.tokens_per_request)
    }

    /// 尝试消耗指定数量的令牌
    pub fn try_consume(&self, key: &str, tokens: u32) -> bool {
        let mut buckets = match self.buckets.write() {
            Ok(b) => b,
            Err(_) => return false,
        };

        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(self.config.capacity));

        bucket.try_consume(tokens, &self.config)
    }

    /// 获取当前可用令牌数
    pub fn available_tokens(&self, key: &str) -> f64 {
        let mut buckets = match self.buckets.write() {
            Ok(b) => b,
            Err(_) => return 0.0,
        };

        let bucket = buckets
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(self.config.capacity));

        bucket.current_tokens(&self.config)
    }

    /// 重置某个 key 的令牌桶
    pub fn reset(&self, key: &str) {
        if let Ok(mut buckets) = self.buckets.write() {
            buckets.remove(key);
        }
    }

    /// 清理空闲的令牌桶
    pub fn cleanup(&self) {
        if let Ok(mut buckets) = self.buckets.write() {
            buckets.retain(|_, bucket| {
                // 保留最近 1 小时内活跃的桶
                bucket.last_update.elapsed() < Duration::from_secs(3600)
            });
        }
    }
}

/// 组合限制器
///
/// 将多个限制器组合在一起，所有限制器都必须允许才能通过。
///
/// ## 示例
///
/// ```rust
/// use authrs::security::rate_limit::{
///     CompositeRateLimiter, RateLimiter, RateLimitConfig,
/// };
/// use std::sync::Arc;
///
/// // 创建组合限制器：同时限制每秒和每分钟请求数
/// let per_second = Arc::new(RateLimiter::new(
///     RateLimitConfig::new()
///         .with_max_requests(10)
///         .with_window(std::time::Duration::from_secs(1))
/// ));
/// let per_minute = Arc::new(RateLimiter::new(
///     RateLimitConfig::new()
///         .with_max_requests(100)
///         .with_window(std::time::Duration::from_secs(60))
/// ));
///
/// let composite = CompositeRateLimiter::new(vec![per_second, per_minute]);
///
/// // 所有限制器都必须允许
/// let result = composite.check("user:123");
/// ```
pub struct CompositeRateLimiter {
    limiters: Vec<Arc<RateLimiter>>,
}

impl CompositeRateLimiter {
    /// 创建组合限制器
    pub fn new(limiters: Vec<Arc<RateLimiter>>) -> Self {
        Self { limiters }
    }

    /// 检查所有限制器
    ///
    /// 所有限制器都必须允许请求才能通过。
    /// 注意：即使后面的限制器拒绝，前面的限制器仍会记录请求。
    pub async fn check(&self, key: &str) -> Result<Vec<RateLimitInfo>> {
        let mut infos = Vec::with_capacity(self.limiters.len());

        for limiter in &self.limiters {
            let info = limiter.check(key).await?;
            infos.push(info);
        }

        Ok(infos)
    }

    /// 获取所有限制器的状态
    pub async fn status(&self, key: &str) -> Vec<RateLimitInfo> {
        let mut results = Vec::new();

        for limiter in &self.limiters {
            results.push(limiter.status(key).await);
        }

        results
    }

    /// 重置所有限制器
    pub async fn reset(&self, key: &str) {
        for limiter in &self.limiters {
            limiter.reset(key).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[tokio::test]
    async fn test_rate_limiter_basic() {
        let config = RateLimitConfig::new()
            .with_max_requests(3)
            .with_window(Duration::from_secs(60));
        let limiter = RateLimiter::new(config);

        let key = "test:user";

        // 前三次应该成功
        assert!(limiter.check(key).await.is_ok());
        assert!(limiter.check(key).await.is_ok());
        assert!(limiter.check(key).await.is_ok());

        // 第四次应该失败
        assert!(limiter.check(key).await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_reset() {
        let config = RateLimitConfig::new()
            .with_max_requests(2)
            .with_window(Duration::from_secs(60));
        let limiter = RateLimiter::new(config);

        let key = "test:reset";

        assert!(limiter.check(key).await.is_ok());
        assert!(limiter.check(key).await.is_ok());
        assert!(limiter.check(key).await.is_err());

        // 重置后应该可以继续
        limiter.reset(key).await;
        assert!(limiter.check(key).await.is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter_status() {
        let config = RateLimitConfig::new()
            .with_max_requests(5)
            .with_window(Duration::from_secs(60));
        let limiter = RateLimiter::new(config);

        let key = "test:status";

        let status = limiter.status(key).await;
        assert_eq!(status.remaining, 5);
        assert_eq!(status.limit, 5);

        limiter.check(key).await.unwrap();
        limiter.check(key).await.unwrap();

        let status = limiter.status(key).await;
        assert_eq!(status.remaining, 3);
    }

    #[tokio::test]
    async fn test_rate_limiter_ban() {
        let config = RateLimitConfig::new()
            .with_max_requests(5)
            .with_window(Duration::from_secs(60));
        let limiter = RateLimiter::new(config);

        let key = "test:ban";

        // 手动封禁
        limiter.ban(key, Duration::from_secs(60)).await;

        // 应该被拒绝
        assert!(limiter.check(key).await.is_err());

        // 解除封禁
        limiter.unban(key).await;

        // 应该可以继续
        assert!(limiter.check(key).await.is_ok());
    }

    #[tokio::test]
    async fn test_fixed_window_limiter() {
        let config = RateLimitConfig::new()
            .with_max_requests(3)
            .with_window(Duration::from_secs(60))
            .with_sliding_window(false);
        let limiter = RateLimiter::new(config);

        let key = "test:fixed";

        assert!(limiter.check(key).await.is_ok());
        assert!(limiter.check(key).await.is_ok());
        assert!(limiter.check(key).await.is_ok());
        assert!(limiter.check(key).await.is_err());
    }

    #[test]
    fn test_token_bucket_basic() {
        let config = TokenBucketConfig::new(5, 1.0);
        let limiter = TokenBucketLimiter::new(config);

        let key = "test:bucket";

        // 消耗所有令牌
        for _ in 0..5 {
            assert!(limiter.check(key));
        }

        // 没有令牌了
        assert!(!limiter.check(key));
    }

    #[test]
    fn test_token_bucket_refill() {
        let config = TokenBucketConfig::new(10, 100.0); // 每秒 100 个令牌
        let limiter = TokenBucketLimiter::new(config);

        let key = "test:refill";

        // 消耗所有令牌
        for _ in 0..10 {
            limiter.check(key);
        }

        // 等待一小段时间让令牌补充
        thread::sleep(Duration::from_millis(50));

        // 应该有一些令牌了
        let tokens = limiter.available_tokens(key);
        assert!(tokens > 0.0);
    }

    #[tokio::test]
    async fn test_composite_limiter() {
        let limiter1 = Arc::new(RateLimiter::new(
            RateLimitConfig::new()
                .with_max_requests(2)
                .with_window(Duration::from_secs(60)),
        ));
        let limiter2 = Arc::new(RateLimiter::new(
            RateLimitConfig::new()
                .with_max_requests(5)
                .with_window(Duration::from_secs(60)),
        ));

        let composite = CompositeRateLimiter::new(vec![limiter1, limiter2]);

        let key = "test:composite";

        // 前两次应该成功
        assert!(composite.check(key).await.is_ok());
        assert!(composite.check(key).await.is_ok());

        // 第三次应该失败（limiter1 限制）
        assert!(composite.check(key).await.is_err());
    }

    #[test]
    fn test_login_config() {
        let config = RateLimitConfig::for_login();
        assert_eq!(config.max_requests, 5);
        assert_eq!(config.window, Duration::from_secs(60));
        assert!(config.ban_duration.is_some());
    }

    #[test]
    fn test_api_config() {
        let config = RateLimitConfig::for_api();
        assert_eq!(config.max_requests, 60);
        assert_eq!(config.window, Duration::from_secs(60));
    }

    #[tokio::test]
    async fn test_remaining_count() {
        let config = RateLimitConfig::new()
            .with_max_requests(5)
            .with_window(Duration::from_secs(60));
        let limiter = RateLimiter::new(config);

        let key = "test:remaining";

        let info = limiter.check(key).await.unwrap();
        assert_eq!(info.remaining, 4);
        assert_eq!(info.limit, 5);

        let info = limiter.check(key).await.unwrap();
        assert_eq!(info.remaining, 3);

        let info = limiter.check(key).await.unwrap();
        assert_eq!(info.remaining, 2);
    }
}
