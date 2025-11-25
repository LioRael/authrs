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
//! ## TOTP 示例
//!
//! ```rust
//! use authrs::mfa::totp::{TotpGenerator, TotpConfig};
//!
//! // 创建 TOTP 生成器
//! let config = TotpConfig::default();
//! let generator = TotpGenerator::new(config);
//!
//! // 生成密钥和二维码 URI
//! let secret = generator.generate_secret();
//! let uri = generator.get_otpauth_uri(&secret, "user@example.com", "MyApp");
//!
//! // 验证用户输入的验证码
//! let code = "123456"; // 用户输入
//! let is_valid = generator.verify(&secret, code).unwrap();
//! ```
//!
//! ## 恢复码示例
//!
//! ```rust
//! use authrs::mfa::recovery::{RecoveryCodeManager, RecoveryConfig};
//!
//! // 生成恢复码
//! let config = RecoveryConfig::default();
//! let manager = RecoveryCodeManager::new(config);
//!
//! // 生成一组恢复码
//! let codes = manager.generate();
//!
//! // 验证恢复码
//! let is_valid = manager.verify(&codes.hashed_codes, "XXXX-XXXX");
//! ```

pub mod hotp;
pub mod recovery;
pub mod totp;

pub use hotp::{HotpConfig, HotpGenerator};
pub use recovery::{RecoveryCodeManager, RecoveryCodeSet, RecoveryConfig};
pub use totp::{TotpConfig, TotpGenerator, TotpSecret};
