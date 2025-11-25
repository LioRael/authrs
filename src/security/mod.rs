//! 安全防护模块
//!
//! 提供各种安全防护机制的实现。
//!
//! ## 子模块
//!
//! - **rate_limit**: 速率限制，防止暴力破解
//! - **csrf**: CSRF (跨站请求伪造) 防护
//!
//! ## 速率限制示例
//!
//! ```rust
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
//! match limiter.check(key) {
//!     Ok(info) => println!("允许请求，剩余: {}", info.remaining),
//!     Err(_) => println!("请求被限制"),
//! }
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

pub mod csrf;
pub mod rate_limit;

pub use csrf::{CsrfConfig, CsrfProtection, CsrfToken};
pub use rate_limit::{RateLimitConfig, RateLimitInfo, RateLimiter};
