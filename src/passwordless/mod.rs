//! 无密码认证模块
//!
//! 提供多种无密码认证方式，包括魔法链接 (Magic Link) 和一次性密码 (OTP)。
//!
//! ## 功能特性
//!
//! - **Magic Link**: 生成安全的一次性登录链接，通过邮件发送给用户
//! - **Email OTP**: 生成数字验证码，通过邮件发送
//! - **SMS OTP**: 生成数字验证码，通过短信发送
//!
//! ## 设计原则
//!
//! 本模块只负责 Token/OTP 的生成和验证逻辑，**不包含**实际的邮件/短信发送功能。
//! 发送功能应该由应用层通过集成第三方服务（如 SendGrid、Twilio 等）来实现。
//!
//! ## 示例
//!
//! ### Magic Link 认证
//!
//! ```rust
//! # tokio::runtime::Runtime::new().unwrap().block_on(async {
//! use authrs::passwordless::{MagicLinkManager, MagicLinkConfig};
//!
//! // 创建管理器
//! let manager = MagicLinkManager::new(MagicLinkConfig::default());
//!
//! // 为用户生成魔法链接 token
//! let token_data = manager.generate("user@example.com").await.unwrap();
//!
//! // 构建完整的魔法链接 URL（应用层负责）
//! let login_url = format!(
//!     "https://example.com/auth/magic?token={}",
//!     token_data.token
//! );
//!
//! // 发送邮件（应用层负责）
//! // send_email(user_email, login_url);
//!
//! // 用户点击链接后，验证 token
//! match manager.verify(&token_data.token).await {
//!     Ok(email) => println!("验证成功，用户: {}", email),
//!     Err(e) => println!("验证失败: {}", e),
//! }
//! # });
//! ```
//!
//! ### Email/SMS OTP 认证
//!
//! ```rust
//! # tokio::runtime::Runtime::new().unwrap().block_on(async {
//! use authrs::passwordless::{OtpManager, OtpConfig, OtpPurpose};
//!
//! // 创建管理器
//! let manager = OtpManager::new(OtpConfig::default());
//!
//! // 生成 OTP
//! let otp_data = manager
//!     .generate("user@example.com", OtpPurpose::Login)
//!     .await
//!     .unwrap();
//!
//! // 发送 OTP（应用层负责）
//! // send_email(user_email, otp_data.code);
//! // 或 send_sms(user_phone, otp_data.code);
//!
//! // 用户输入验证码后，验证 OTP
//! match manager
//!     .verify("user@example.com", "123456", OtpPurpose::Login)
//!     .await
//! {
//!     Ok(()) => println!("验证成功"),
//!     Err(e) => println!("验证失败: {}", e),
//! }
//! # });
//! ```
//!
//! ## 安全考虑
//!
//! - Magic Link token 使用密码学安全的随机数生成
//! - OTP 验证使用常量时间比较，防止时序攻击
//! - 支持配置过期时间和最大尝试次数
//! - Token/OTP 使用后自动失效（一次性使用）
//! - 支持速率限制集成

pub mod magic_link;
pub mod otp;

pub use magic_link::{
    InMemoryMagicLinkStore, MagicLinkConfig, MagicLinkData, MagicLinkManager, MagicLinkStore,
};
pub use otp::{InMemoryOtpStore, OtpConfig, OtpData, OtpManager, OtpPurpose, OtpStore};
