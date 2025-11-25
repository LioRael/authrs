//! 多因素认证 (MFA) 模块
//!
//! 提供多种多因素认证方式的实现。
//!
//! ## 支持的认证方式
//!
//! - **TOTP**: 基于时间的一次性密码 (Google Authenticator 兼容)
//! - **HOTP**: 基于计数器的一次性密码
//! - **恢复码**: 备用恢复码生成与验证
//!
//! ## Features
//!
//! - `mfa` - 启用 TOTP/HOTP 支持（默认启用）
//!
//! ## TOTP 示例
//!
#![cfg_attr(feature = "mfa", doc = "```rust")]
#![cfg_attr(not(feature = "mfa"), doc = "```rust,ignore")]
//! use authrs::mfa::totp::{TotpManager, TotpConfig};
//!
//! // 创建 TOTP 管理器
//! let config = TotpConfig::default();
//! let manager = TotpManager::new(config);
//!
//! // 为用户生成密钥
//! let secret = manager.generate_secret().unwrap();
//!
//! // 生成当前 TOTP 码
//! let code = manager.generate_code(&secret).unwrap();
//! println!("当前验证码: {}", code);
//!
//! // 验证用户输入的码
//! let is_valid = manager.verify(&secret, &code).unwrap();
//! assert!(is_valid);
//! ```
//!
//! ## 恢复码示例
//!
#![cfg_attr(feature = "mfa", doc = "```rust")]
#![cfg_attr(not(feature = "mfa"), doc = "```rust,ignore")]
//! use authrs::mfa::recovery::{RecoveryCodeManager, RecoveryConfig};
//!
//! // 生成恢复码
//! let config = RecoveryConfig::default();
//! let manager = RecoveryCodeManager::new(config);
//!
//! // 生成一组恢复码
//! let codes = manager.generate().unwrap();
//!
//! // 验证恢复码（使用其中一个明文码）
//! let result = manager.verify(&codes.plain_codes[0], &codes.hashed_codes).unwrap();
//! assert!(result.is_some());
//! ```

#[cfg(feature = "mfa")]
pub mod hotp;
#[cfg(feature = "mfa")]
pub mod recovery;
#[cfg(feature = "mfa")]
pub mod totp;

#[cfg(feature = "mfa")]
pub use hotp::{HotpConfig, HotpGenerator};
#[cfg(feature = "mfa")]
pub use recovery::{RecoveryCodeManager, RecoveryCodeSet, RecoveryConfig};
#[cfg(feature = "mfa")]
pub use totp::{TotpConfig, TotpManager, TotpSecret};
