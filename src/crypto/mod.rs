//! 密码学工具模块
//!
//! 提供各种密码学原语和工具函数。
//!
//! ## 功能
//!
//! - **密钥派生函数 (KDF)**: HKDF-SHA256 和 HKDF-SHA512 实现
//!
//! ## 示例
//!
//! ### 使用 HKDF 派生密钥
//!
//! ```rust
//! use authrs::crypto::kdf::{hkdf_sha256, Hkdf};
//!
//! // 使用便捷函数
//! let key = hkdf_sha256(b"secret", Some(b"salt".as_ref()), b"context", 32).unwrap();
//!
//! // 使用构建器 API
//! let key = Hkdf::default()
//!     .with_salt(b"salt")
//!     .with_info(b"context")
//!     .derive(b"secret", 32)
//!     .unwrap();
//! ```
//!
//! ### 从主密钥派生多个子密钥
//!
//! ```rust
//! use authrs::crypto::kdf::derive_subkeys;
//!
//! let master_key = b"my-master-key";
//! let labels = &["encryption", "signing", "authentication"];
//!
//! let keys = derive_subkeys(master_key, Some(b"salt"), labels, 32).unwrap();
//! assert_eq!(keys.len(), 3);
//! ```

pub mod kdf;

pub use kdf::{
    Hkdf, HkdfAlgorithm, derive_key_from_password, derive_subkeys, hkdf_sha256, hkdf_sha512,
};
