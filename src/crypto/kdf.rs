//! 密钥派生函数模块
//!
//! 提供基于 HMAC 的密钥派生函数 (HKDF) 实现，符合 RFC 5869 规范。
//! HKDF 用于从主密钥派生出多个子密钥，适用于：
//!
//! - 从用户密码派生加密密钥
//! - 从主密钥派生多个应用专用密钥
//! - 密钥轮换和密钥分离
//!
//! ## 示例
//!
//! ### 基本使用
//!
//! ```rust
//! use authrs::crypto::kdf::{hkdf_sha256, hkdf_sha512};
//!
//! let secret = b"my-secret-key";
//! let salt = b"random-salt";
//! let info = b"application-specific-context";
//!
//! // 派生 32 字节的密钥
//! let derived_key = hkdf_sha256(secret, Some(salt), info, 32).unwrap();
//! assert_eq!(derived_key.len(), 32);
//!
//! // 使用 SHA-512 派生更长的密钥
//! let long_key = hkdf_sha512(secret, Some(salt), info, 64).unwrap();
//! assert_eq!(long_key.len(), 64);
//! ```
//!
//! ### 使用 HkdfConfig 构建器
//!
//! ```rust
//! use authrs::crypto::kdf::{Hkdf, HkdfAlgorithm};
//!
//! let hkdf = Hkdf::new(HkdfAlgorithm::Sha256)
//!     .with_salt(b"my-salt")
//!     .with_info(b"context-info");
//!
//! let key = hkdf.derive(b"input-key-material", 32).unwrap();
//! ```
//!
//! ### 派生多个密钥
//!
//! ```rust
//! use authrs::crypto::kdf::Hkdf;
//!
//! let hkdf = Hkdf::default().with_salt(b"shared-salt");
//!
//! // 为不同目的派生不同的密钥
//! let encryption_key = hkdf.clone().with_info(b"encryption").derive(b"master", 32).unwrap();
//! let signing_key = hkdf.clone().with_info(b"signing").derive(b"master", 32).unwrap();
//! let auth_key = hkdf.with_info(b"authentication").derive(b"master", 32).unwrap();
//!
//! // 每个密钥都是唯一的
//! assert_ne!(encryption_key, signing_key);
//! assert_ne!(signing_key, auth_key);
//! ```

use hmac::{Hmac, Mac};
use sha2::{Sha256, Sha512};

use crate::error::{Error, Result};

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

/// HKDF 支持的哈希算法
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HkdfAlgorithm {
    /// SHA-256 (推荐，输出长度 32 字节)
    #[default]
    Sha256,
    /// SHA-512 (更长的输出，64 字节)
    Sha512,
}

impl HkdfAlgorithm {
    /// 获取算法的哈希输出长度（字节）
    pub fn hash_length(&self) -> usize {
        match self {
            HkdfAlgorithm::Sha256 => 32,
            HkdfAlgorithm::Sha512 => 64,
        }
    }

    /// 获取算法允许的最大输出长度
    ///
    /// 根据 RFC 5869，最大输出长度为 255 * HashLen
    pub fn max_output_length(&self) -> usize {
        255 * self.hash_length()
    }
}

/// HKDF 配置构建器
///
/// 提供流式 API 来配置 HKDF 参数。
///
/// ## 示例
///
/// ```rust
/// use authrs::crypto::kdf::{Hkdf, HkdfAlgorithm};
///
/// let hkdf = Hkdf::new(HkdfAlgorithm::Sha256)
///     .with_salt(b"my-salt")
///     .with_info(b"context");
///
/// let key = hkdf.derive(b"secret", 32).unwrap();
/// ```
#[derive(Debug, Clone, Default)]
pub struct Hkdf {
    /// 使用的哈希算法
    algorithm: HkdfAlgorithm,
    /// 可选的盐值
    salt: Option<Vec<u8>>,
    /// 应用上下文信息
    info: Option<Vec<u8>>,
}

impl Hkdf {
    /// 创建新的 HKDF 配置
    ///
    /// # Arguments
    ///
    /// * `algorithm` - 要使用的哈希算法
    ///
    /// # Example
    ///
    /// ```rust
    /// use authrs::crypto::kdf::{Hkdf, HkdfAlgorithm};
    ///
    /// let hkdf = Hkdf::new(HkdfAlgorithm::Sha512);
    /// ```
    pub fn new(algorithm: HkdfAlgorithm) -> Self {
        Self {
            algorithm,
            salt: None,
            info: None,
        }
    }

    /// 设置盐值
    ///
    /// 盐值是可选的，但强烈建议使用。如果不提供盐值，
    /// HKDF 将使用全零字节作为默认盐（长度等于哈希输出长度）。
    ///
    /// # Arguments
    ///
    /// * `salt` - 盐值字节
    ///
    /// # Example
    ///
    /// ```rust
    /// use authrs::crypto::kdf::Hkdf;
    ///
    /// let hkdf = Hkdf::default().with_salt(b"random-salt-value");
    /// ```
    pub fn with_salt(mut self, salt: impl AsRef<[u8]>) -> Self {
        self.salt = Some(salt.as_ref().to_vec());
        self
    }

    /// 设置应用上下文信息
    ///
    /// info 参数用于将派生的密钥绑定到特定的应用上下文。
    /// 不同的 info 值会产生不同的密钥，即使输入密钥材料和盐相同。
    ///
    /// # Arguments
    ///
    /// * `info` - 上下文信息字节
    ///
    /// # Example
    ///
    /// ```rust
    /// use authrs::crypto::kdf::Hkdf;
    ///
    /// let hkdf = Hkdf::default().with_info(b"my-application-v1");
    /// ```
    pub fn with_info(mut self, info: impl AsRef<[u8]>) -> Self {
        self.info = Some(info.as_ref().to_vec());
        self
    }

    /// 派生密钥
    ///
    /// 使用配置的参数从输入密钥材料派生指定长度的密钥。
    ///
    /// # Arguments
    ///
    /// * `ikm` - 输入密钥材料 (Input Keying Material)
    /// * `output_len` - 需要派生的密钥长度（字节）
    ///
    /// # Returns
    ///
    /// 成功返回派生的密钥，失败返回错误。
    ///
    /// # Errors
    ///
    /// - 如果 `output_len` 超过算法允许的最大值
    /// - 如果 `output_len` 为 0
    ///
    /// # Example
    ///
    /// ```rust
    /// use authrs::crypto::kdf::Hkdf;
    ///
    /// let key = Hkdf::default()
    ///     .with_salt(b"salt")
    ///     .derive(b"secret", 32)
    ///     .unwrap();
    /// ```
    pub fn derive(&self, ikm: impl AsRef<[u8]>, output_len: usize) -> Result<Vec<u8>> {
        let salt = self.salt.as_deref();
        let info = self.info.as_deref().unwrap_or(&[]);

        match self.algorithm {
            HkdfAlgorithm::Sha256 => hkdf_sha256_impl(ikm.as_ref(), salt, info, output_len),
            HkdfAlgorithm::Sha512 => hkdf_sha512_impl(ikm.as_ref(), salt, info, output_len),
        }
    }

    /// 获取当前配置的算法
    pub fn algorithm(&self) -> HkdfAlgorithm {
        self.algorithm
    }
}

/// 使用 HKDF-SHA256 派生密钥
///
/// 这是最常用的 HKDF 变体，使用 SHA-256 作为底层哈希函数。
///
/// # Arguments
///
/// * `secret` - 输入密钥材料（如主密钥或密码）
/// * `salt` - 可选的盐值（建议提供，增强安全性）
/// * `info` - 应用特定的上下文信息（用于域分离）
/// * `output_len` - 需要派生的密钥长度（字节），最大 8160 字节
///
/// # Returns
///
/// 成功返回指定长度的派生密钥。
///
/// # Errors
///
/// - `output_len` 为 0
/// - `output_len` 超过 8160 字节 (255 * 32)
///
/// # Example
///
/// ```rust
/// use authrs::crypto::kdf::hkdf_sha256;
///
/// // 基本使用
/// let key = hkdf_sha256(b"secret", Some(b"salt".as_ref()), b"context", 32).unwrap();
/// assert_eq!(key.len(), 32);
///
/// // 不使用盐
/// let key_no_salt = hkdf_sha256(b"secret", None, b"context", 32).unwrap();
/// ```
pub fn hkdf_sha256(
    secret: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>> {
    hkdf_sha256_impl(secret, salt, info, output_len)
}

/// 使用 HKDF-SHA512 派生密钥
///
/// 使用 SHA-512 作为底层哈希函数，适合需要更长密钥或更高安全边际的场景。
///
/// # Arguments
///
/// * `secret` - 输入密钥材料
/// * `salt` - 可选的盐值
/// * `info` - 应用特定的上下文信息
/// * `output_len` - 需要派生的密钥长度（字节），最大 16320 字节
///
/// # Returns
///
/// 成功返回指定长度的派生密钥。
///
/// # Errors
///
/// - `output_len` 为 0
/// - `output_len` 超过 16320 字节 (255 * 64)
///
/// # Example
///
/// ```rust
/// use authrs::crypto::kdf::hkdf_sha512;
///
/// let key = hkdf_sha512(b"secret", Some(b"salt".as_ref()), b"context", 64).unwrap();
/// assert_eq!(key.len(), 64);
/// ```
pub fn hkdf_sha512(
    secret: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>> {
    hkdf_sha512_impl(secret, salt, info, output_len)
}

/// HKDF-SHA256 内部实现
fn hkdf_sha256_impl(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>> {
    const HASH_LEN: usize = 32;

    // 验证输出长度
    if output_len == 0 {
        return Err(Error::validation("output_len must be greater than 0"));
    }

    let max_output = 255 * HASH_LEN;
    if output_len > max_output {
        return Err(Error::validation(format!(
            "output_len {} exceeds maximum {} for this algorithm",
            output_len, max_output
        )));
    }

    // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
    let default_salt = [0u8; HASH_LEN];
    let salt = salt.unwrap_or(&default_salt);

    let mut extract_mac =
        HmacSha256::new_from_slice(salt).map_err(|_| Error::validation("invalid salt length"))?;
    extract_mac.update(ikm);
    let prk = extract_mac.finalize().into_bytes();

    // HKDF-Expand
    let n = output_len.div_ceil(HASH_LEN);
    let mut okm = Vec::with_capacity(n * HASH_LEN);
    let mut t_prev: Vec<u8> = Vec::new();

    for i in 1..=n {
        let mut expand_mac = HmacSha256::new_from_slice(&prk)
            .map_err(|_| Error::validation("invalid PRK length"))?;
        expand_mac.update(&t_prev);
        expand_mac.update(info);
        expand_mac.update(&[i as u8]);
        let t_i = expand_mac.finalize().into_bytes();
        okm.extend_from_slice(&t_i);
        t_prev = t_i.to_vec();
    }

    okm.truncate(output_len);
    Ok(okm)
}

/// HKDF-SHA512 内部实现
fn hkdf_sha512_impl(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>> {
    const HASH_LEN: usize = 64;

    // 验证输出长度
    if output_len == 0 {
        return Err(Error::validation("output_len must be greater than 0"));
    }

    let max_output = 255 * HASH_LEN;
    if output_len > max_output {
        return Err(Error::validation(format!(
            "output_len {} exceeds maximum {} for this algorithm",
            output_len, max_output
        )));
    }

    // HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
    let default_salt = [0u8; HASH_LEN];
    let salt = salt.unwrap_or(&default_salt);

    let mut extract_mac =
        HmacSha512::new_from_slice(salt).map_err(|_| Error::validation("invalid salt length"))?;
    extract_mac.update(ikm);
    let prk = extract_mac.finalize().into_bytes();

    // HKDF-Expand
    let n = output_len.div_ceil(HASH_LEN);
    let mut okm = Vec::with_capacity(n * HASH_LEN);
    let mut t_prev: Vec<u8> = Vec::new();

    for i in 1..=n {
        let mut expand_mac = HmacSha512::new_from_slice(&prk)
            .map_err(|_| Error::validation("invalid PRK length"))?;
        expand_mac.update(&t_prev);
        expand_mac.update(info);
        expand_mac.update(&[i as u8]);
        let t_i = expand_mac.finalize().into_bytes();
        okm.extend_from_slice(&t_i);
        t_prev = t_i.to_vec();
    }

    okm.truncate(output_len);
    Ok(okm)
}

/// 从密码派生加密密钥
///
/// 这是一个便捷函数，用于从用户密码派生加密密钥。
/// 它使用 HKDF-SHA256 并强制要求盐值。
///
/// **注意**: 对于密码哈希存储，应该使用 `password::PasswordHasher`，
/// 它使用 Argon2 或 bcrypt 等专门的密码哈希算法。
/// 此函数适用于从密码派生加密密钥的场景。
///
/// # Arguments
///
/// * `password` - 用户密码
/// * `salt` - 盐值（必须提供，建议至少 16 字节）
/// * `context` - 应用上下文（如 "file-encryption-v1"）
/// * `key_len` - 需要的密钥长度
///
/// # Example
///
/// ```rust
/// use authrs::crypto::kdf::derive_key_from_password;
///
/// let salt = b"unique-per-user-salt-16b";
/// let key = derive_key_from_password(
///     "user-password",
///     salt,
///     "my-app-encryption",
///     32
/// ).unwrap();
/// ```
pub fn derive_key_from_password(
    password: impl AsRef<[u8]>,
    salt: impl AsRef<[u8]>,
    context: impl AsRef<[u8]>,
    key_len: usize,
) -> Result<Vec<u8>> {
    let salt = salt.as_ref();
    if salt.len() < 8 {
        return Err(Error::validation(
            "salt should be at least 8 bytes for password derivation",
        ));
    }

    hkdf_sha256(password.as_ref(), Some(salt), context.as_ref(), key_len)
}

/// 从主密钥派生多个子密钥
///
/// 使用单个主密钥派生多个独立的子密钥，每个子密钥用于不同的目的。
///
/// # Arguments
///
/// * `master_key` - 主密钥
/// * `salt` - 可选的盐值
/// * `labels` - 子密钥标签列表
/// * `key_len` - 每个子密钥的长度
///
/// # Returns
///
/// 返回与 labels 对应的子密钥列表。
///
/// # Example
///
/// ```rust
/// use authrs::crypto::kdf::derive_subkeys;
///
/// let master = b"master-secret-key";
/// let labels = &["encryption", "signing", "authentication"];
/// let keys = derive_subkeys(master, None, labels, 32).unwrap();
///
/// assert_eq!(keys.len(), 3);
/// // 每个密钥都是唯一的
/// assert_ne!(keys[0], keys[1]);
/// assert_ne!(keys[1], keys[2]);
/// ```
pub fn derive_subkeys(
    master_key: &[u8],
    salt: Option<&[u8]>,
    labels: &[&str],
    key_len: usize,
) -> Result<Vec<Vec<u8>>> {
    labels
        .iter()
        .map(|label| hkdf_sha256(master_key, salt, label.as_bytes(), key_len))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_sha256_basic() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"context info";

        let key = hkdf_sha256(ikm, Some(salt), info, 32).unwrap();
        assert_eq!(key.len(), 32);

        // 相同输入应产生相同输出
        let key2 = hkdf_sha256(ikm, Some(salt), info, 32).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_hkdf_sha512_basic() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"context info";

        let key = hkdf_sha512(ikm, Some(salt), info, 64).unwrap();
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn test_hkdf_different_lengths() {
        let ikm = b"secret";
        let salt = b"salt";
        let info = b"info";

        // 测试不同长度
        for len in [16, 32, 48, 64, 128] {
            let key = hkdf_sha256(ikm, Some(salt), info, len).unwrap();
            assert_eq!(key.len(), len);
        }
    }

    #[test]
    fn test_hkdf_no_salt() {
        let ikm = b"secret";
        let info = b"info";

        let key = hkdf_sha256(ikm, None, info, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hkdf_empty_info() {
        let ikm = b"secret";
        let salt = b"salt";

        let key = hkdf_sha256(ikm, Some(salt), &[], 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hkdf_different_info_produces_different_keys() {
        let ikm = b"secret";
        let salt = b"salt";

        let key1 = hkdf_sha256(ikm, Some(salt), b"context1", 32).unwrap();
        let key2 = hkdf_sha256(ikm, Some(salt), b"context2", 32).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_hkdf_different_salt_produces_different_keys() {
        let ikm = b"secret";
        let info = b"info";

        let key1 = hkdf_sha256(ikm, Some(b"salt1"), info, 32).unwrap();
        let key2 = hkdf_sha256(ikm, Some(b"salt2"), info, 32).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_hkdf_max_output_length() {
        let ikm = b"secret";

        // SHA-256 最大输出: 255 * 32 = 8160 字节
        let max_len = 255 * 32;
        let key = hkdf_sha256(ikm, None, &[], max_len).unwrap();
        assert_eq!(key.len(), max_len);

        // 超过最大长度应该失败
        assert!(hkdf_sha256(ikm, None, &[], max_len + 1).is_err());
    }

    #[test]
    fn test_hkdf_zero_length_error() {
        let ikm = b"secret";
        assert!(hkdf_sha256(ikm, None, &[], 0).is_err());
    }

    #[test]
    fn test_hkdf_builder() {
        let hkdf = Hkdf::new(HkdfAlgorithm::Sha256)
            .with_salt(b"my-salt")
            .with_info(b"my-info");

        let key = hkdf.derive(b"secret", 32).unwrap();
        assert_eq!(key.len(), 32);

        // 验证与直接调用函数产生相同结果
        let direct_key = hkdf_sha256(b"secret", Some(b"my-salt"), b"my-info", 32).unwrap();
        assert_eq!(key, direct_key);
    }

    #[test]
    fn test_hkdf_builder_default() {
        let hkdf = Hkdf::default();
        assert_eq!(hkdf.algorithm(), HkdfAlgorithm::Sha256);

        let key = hkdf.derive(b"secret", 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hkdf_builder_sha512() {
        let hkdf = Hkdf::new(HkdfAlgorithm::Sha512);
        let key = hkdf.derive(b"secret", 64).unwrap();
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn test_derive_key_from_password() {
        let password = "my-secure-password";
        let salt = b"16-byte-salt-val";

        let key = derive_key_from_password(password, salt, "encryption", 32).unwrap();
        assert_eq!(key.len(), 32);

        // 相同输入应产生相同密钥
        let key2 = derive_key_from_password(password, salt, "encryption", 32).unwrap();
        assert_eq!(key, key2);

        // 不同上下文应产生不同密钥
        let key3 = derive_key_from_password(password, salt, "signing", 32).unwrap();
        assert_ne!(key, key3);
    }

    #[test]
    fn test_derive_key_from_password_short_salt_error() {
        let password = "password";
        let short_salt = b"short"; // 只有 5 字节

        assert!(derive_key_from_password(password, short_salt, "ctx", 32).is_err());
    }

    #[test]
    fn test_derive_subkeys() {
        let master = b"master-key";
        let labels = &["encryption", "signing", "auth"];

        let keys = derive_subkeys(master, Some(b"salt"), labels, 32).unwrap();

        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].len(), 32);
        assert_eq!(keys[1].len(), 32);
        assert_eq!(keys[2].len(), 32);

        // 所有密钥应该不同
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
        assert_ne!(keys[0], keys[2]);
    }

    #[test]
    fn test_algorithm_properties() {
        assert_eq!(HkdfAlgorithm::Sha256.hash_length(), 32);
        assert_eq!(HkdfAlgorithm::Sha512.hash_length(), 64);

        assert_eq!(HkdfAlgorithm::Sha256.max_output_length(), 255 * 32);
        assert_eq!(HkdfAlgorithm::Sha512.max_output_length(), 255 * 64);
    }

    // RFC 5869 测试向量
    #[test]
    fn test_rfc5869_test_case_1() {
        // Test Case 1 from RFC 5869
        let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let salt = hex_decode("000102030405060708090a0b0c");
        let info = hex_decode("f0f1f2f3f4f5f6f7f8f9");
        let expected_okm = hex_decode(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        );

        let okm = hkdf_sha256(&ikm, Some(&salt), &info, 42).unwrap();
        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn test_rfc5869_test_case_2() {
        // Test Case 2 from RFC 5869 (longer inputs/outputs)
        let ikm = hex_decode(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             404142434445464748494a4b4c4d4e4f",
        );
        let salt = hex_decode(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
             808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
             a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        );
        let info = hex_decode(
            "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
             d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
             f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        );
        let expected_okm = hex_decode(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
             59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
             cc30c58179ec3e87c14c01d5c1f3434f1d87",
        );

        let okm = hkdf_sha256(&ikm, Some(&salt), &info, 82).unwrap();
        assert_eq!(okm, expected_okm);
    }

    #[test]
    fn test_rfc5869_test_case_3() {
        // Test Case 3 from RFC 5869 (zero-length salt/info)
        let ikm = hex_decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let expected_okm = hex_decode(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
             9d201395faa4b61a96c8",
        );

        let okm = hkdf_sha256(&ikm, None, &[], 42).unwrap();
        assert_eq!(okm, expected_okm);
    }

    // 辅助函数：将十六进制字符串转换为字节
    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
