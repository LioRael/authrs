//! 安全防护模块
//!
//! 提供各种安全防护机制的实现。
//!
//! ## 子模块
//!
//! - **rate_limit**: 速率限制，防止暴力破解
//! - **csrf**: CSRF (跨站请求伪造) 防护
//! - **account**: 账户安全，包括锁定机制和登录追踪
//! - **cookie**: 安全 Cookie 助手，签名与验证
//!
//! ## 速率限制示例
//!
//! ```rust
//! # tokio::runtime::Runtime::new().unwrap().block_on(async {
//! use authrs::security::rate_limit::{RateLimiter, RateLimitConfig};
//! use std::time::Duration;
//!
//! // 创建速率限制器
//! let config = RateLimitConfig::new()
//!     .with_max_requests(5)
//!     .with_window(Duration::from_secs(60));
//! let limiter = RateLimiter::new(config);
//!
//! // 检查请求是否被允许
//! let key = "user:123:login";
//! match limiter.check(key).await {
//!     Ok(info) => println!("允许请求，剩余: {}", info.remaining),
//!     Err(_) => println!("请求被限制"),
//! }
//! # });
//! ```
//!
//! ## CSRF 防护示例
//!
//! ```rust
//! use authrs::security::csrf::{CsrfProtection, CsrfConfig};
//!
//! // 创建 CSRF 防护器
//! let config = CsrfConfig::default();
//! let csrf = CsrfProtection::new(config);
//!
//! // 生成 token
//! let token = csrf.generate_token().unwrap();
//! println!("CSRF Token: {}", token.token);
//!
//! // 验证 token
//! let is_valid = csrf.verify(&token.token).unwrap();
//! assert!(is_valid);
//! ```
//!
//! ## 账户锁定示例
//!
//! ```rust
//! use authrs::security::account::{LoginAttemptTracker, AccountLockoutConfig, LoginCheckResult};
//!
//! // 创建登录追踪器
//! let mut tracker = LoginAttemptTracker::with_default_config();
//!
//! // 检查是否允许登录
//! match tracker.check_login_allowed("user@example.com", None) {
//!     LoginCheckResult::Allowed => {
//!         // 允许登录尝试
//!         println!("Login attempt allowed");
//!     }
//!     LoginCheckResult::Locked { reason, remaining } => {
//!         // 账户被锁定
//!         println!("Account locked: {:?}", reason);
//!     }
//!     LoginCheckResult::DelayRequired { wait_time } => {
//!         // 需要等待
//!         println!("Please wait {:?}", wait_time);
//!     }
//!     LoginCheckResult::IpBanned { ip } => {
//!         // IP 被封禁
//!         println!("IP banned: {}", ip);
//!     }
//! }
//!
//! // 记录失败登录
//! tracker.record_failed_attempt("user@example.com", None);
//!
//! // 记录成功登录（重置失败计数）
//! tracker.record_successful_login("user@example.com", None);
//! ```

pub mod account;
pub mod cookie;
pub mod csrf;
pub mod rate_limit;

pub use account::{
    AccountLockStatus, AccountLockStore, AccountLockoutConfig, InMemoryAccountLockStore,
    LockReason, LoginAttempt, LoginAttemptTracker, LoginCheckResult,
};
pub use cookie::{SameSite, SecureCookie, delete_cookie_header, sign_cookie, verify_cookie};
pub use csrf::{CsrfConfig, CsrfProtection, CsrfToken};
pub use rate_limit::{RateLimitConfig, RateLimitInfo, RateLimiter};
