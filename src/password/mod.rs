//! 密码哈希模块
//!
//! 提供安全的密码哈希和验证功能，支持多种哈希算法。
//!
//! ## 支持的算法
//!
//! - **Argon2** (推荐): 内存硬哈希算法，抵抗 GPU/ASIC 攻击（需启用 `argon2` feature）
//! - **bcrypt**: 经典的密码哈希算法，广泛使用（需启用 `bcrypt` feature）
//!
//! ## Features
//!
//! - `argon2` - 启用 Argon2id 密码哈希支持（默认启用）
//! - `bcrypt` - 启用 bcrypt 密码哈希支持
//!
//! ## 示例
//!
//! ### 使用默认算法
//!
//! ```rust
//! use authrs::password::{hash_password, verify_password};
//!
//! // 哈希密码
//! let hash = hash_password("my_secure_password").unwrap();
//!
//! // 验证密码
//! let is_valid = verify_password("my_secure_password", &hash).unwrap();
//! assert!(is_valid);
//! ```
//!
//! ### 使用指定算法
//!
#![cfg_attr(feature = "bcrypt", doc = "```rust")]
#![cfg_attr(not(feature = "bcrypt"), doc = "```rust,ignore")]
//! use authrs::password::{PasswordHasher, Algorithm};
//!
//! let hasher = PasswordHasher::new(Algorithm::Bcrypt);
//! let hash = hasher.hash("my_password").unwrap();
//! let is_valid = hasher.verify("my_password", &hash).unwrap();
//! ```
//!
//! ### 密码强度检查
//!
//! ```rust
//! use authrs::password::validate_password_strength;
//!
//! let result = validate_password_strength("weak");
//! assert!(result.is_err());
//!
//! let result = validate_password_strength("Str0ng_P@ssword!");
//! assert!(result.is_ok());
//! ```

mod hasher;
pub mod strength;

pub use hasher::{Algorithm, PasswordHasher, hash_password, verify_password};
pub use strength::{
    PasswordFeatures, PasswordRequirements, PasswordStrength, StrengthResult,
    check_password_strength, validate_password_strength, validate_password_with_requirements,
};
