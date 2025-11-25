//! 密码哈希实现
//!
//! 提供密码哈希和验证的核心功能。

#[cfg(feature = "argon2")]
use argon2::Argon2;

#[cfg(any(feature = "argon2", feature = "scrypt"))]
use password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString};

#[cfg(feature = "scrypt")]
use scrypt::{Params as ScryptParams, Scrypt};

use crate::error::{Error, PasswordHashError, Result};

/// 支持的哈希算法
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// Argon2id - 推荐的默认算法
    /// 结合了 Argon2i（抵抗侧信道攻击）和 Argon2d（抵抗 GPU 攻击）的优点
    #[cfg(feature = "argon2")]
    Argon2id,

    /// bcrypt - 经典算法，广泛支持
    #[cfg(feature = "bcrypt")]
    Bcrypt,

    /// scrypt - 适用于受限计算资源、抵抗 GPU 攻击
    #[cfg(feature = "scrypt")]
    Scrypt,
}

// 编译时检查：至少需要启用一个密码哈希算法
#[cfg(not(any(feature = "argon2", feature = "bcrypt", feature = "scrypt")))]
compile_error!(
    "At least one password hashing algorithm (argon2, bcrypt, or scrypt) must be enabled. Enable one of the password hashing features."
);

#[allow(clippy::derivable_impls)]
impl Default for Algorithm {
    fn default() -> Self {
        #[cfg(feature = "argon2")]
        {
            Algorithm::Argon2id
        }
        #[cfg(all(not(feature = "argon2"), feature = "bcrypt"))]
        {
            Algorithm::Bcrypt
        }
        #[cfg(all(not(any(feature = "argon2", feature = "bcrypt")), feature = "scrypt"))]
        {
            Algorithm::Scrypt
        }
    }
}

/// 密码哈希器配置
#[derive(Debug, Clone)]
pub struct PasswordHasher {
    /// 使用的哈希算法
    algorithm: Algorithm,

    /// bcrypt 的 cost 参数 (4-31, 默认 12)
    #[cfg(feature = "bcrypt")]
    bcrypt_cost: u32,

    /// scrypt 参数（N, r, p）
    #[cfg(feature = "scrypt")]
    scrypt_params: ScryptParams,
}

impl Default for PasswordHasher {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::default(),
            #[cfg(feature = "bcrypt")]
            bcrypt_cost: 12,
            #[cfg(feature = "scrypt")]
            scrypt_params: ScryptParams::recommended(),
        }
    }
}

impl PasswordHasher {
    /// 创建新的密码哈希器
    ///
    /// # Arguments
    ///
    /// * `algorithm` - 要使用的哈希算法
    ///
    /// # Example
    ///
    /// ```rust
    /// use authrs::password::{PasswordHasher, Algorithm};
    ///
    /// # #[cfg(feature = "argon2")]
    /// let hasher = PasswordHasher::new(Algorithm::Argon2id);
    /// ```
    pub fn new(algorithm: Algorithm) -> Self {
        Self {
            algorithm,
            #[cfg(feature = "bcrypt")]
            bcrypt_cost: 12,
            #[cfg(feature = "scrypt")]
            scrypt_params: ScryptParams::recommended(),
        }
    }

    /// 设置 bcrypt 的 cost 参数
    ///
    /// # Arguments
    ///
    /// * `cost` - cost 参数，范围 4-31，默认 12
    ///
    /// # Panics
    ///
    /// 如果 cost 不在 4-31 范围内会 panic
    #[cfg(feature = "bcrypt")]
    pub fn with_bcrypt_cost(mut self, cost: u32) -> Self {
        assert!(
            (4..=31).contains(&cost),
            "bcrypt cost must be between 4 and 31"
        );
        self.bcrypt_cost = cost;
        self
    }

    /// 设置 scrypt 参数（log_n、r、p、输出长度）
    #[cfg(feature = "scrypt")]
    pub fn with_scrypt_params(mut self, params: ScryptParams) -> Self {
        self.scrypt_params = params;
        self
    }

    /// 哈希密码
    ///
    /// # Arguments
    ///
    /// * `password` - 要哈希的明文密码
    ///
    /// # Returns
    ///
    /// 返回哈希后的密码字符串
    ///
    /// # Example
    ///
    /// ```rust
    /// use authrs::password::PasswordHasher;
    ///
    /// let hasher = PasswordHasher::default();
    /// let hash = hasher.hash("my_password").unwrap();
    /// # #[cfg(feature = "argon2")]
    /// assert!(hash.starts_with("$argon2"));
    /// ```
    pub fn hash(&self, password: &str) -> Result<String> {
        match self.algorithm {
            #[cfg(feature = "argon2")]
            Algorithm::Argon2id => self.hash_argon2(password),
            #[cfg(feature = "bcrypt")]
            Algorithm::Bcrypt => self.hash_bcrypt(password),
            #[cfg(feature = "scrypt")]
            Algorithm::Scrypt => self.hash_scrypt(password),
        }
    }

    /// 验证密码
    ///
    /// # Arguments
    ///
    /// * `password` - 要验证的明文密码
    /// * `hash` - 存储的哈希值
    ///
    /// # Returns
    ///
    /// 如果密码正确返回 `Ok(true)`，密码错误返回 `Ok(false)`
    ///
    /// # Example
    ///
    /// ```rust
    /// use authrs::password::PasswordHasher;
    ///
    /// let hasher = PasswordHasher::default();
    /// let hash = hasher.hash("my_password").unwrap();
    ///
    /// assert!(hasher.verify("my_password", &hash).unwrap());
    /// assert!(!hasher.verify("wrong_password", &hash).unwrap());
    /// ```
    pub fn verify(&self, password: &str, hash: &str) -> Result<bool> {
        // 自动检测哈希格式
        #[cfg(feature = "argon2")]
        if hash.starts_with("$argon2") {
            return self.verify_argon2(password, hash);
        }
        #[cfg(feature = "bcrypt")]
        if hash.starts_with("$2") {
            return self.verify_bcrypt(password, hash);
        }
        #[cfg(feature = "scrypt")]
        if hash.starts_with("$scrypt$") {
            return self.verify_scrypt(password, hash);
        }
        Err(Error::PasswordHash(PasswordHashError::InvalidFormat(
            "unknown hash format".to_string(),
        )))
    }

    /// 检查哈希是否需要重新生成
    ///
    /// 当算法或参数升级时，旧哈希可能需要重新生成
    ///
    /// # Arguments
    ///
    /// * `hash` - 要检查的哈希值
    ///
    /// # Returns
    ///
    /// 如果需要重新生成返回 `true`
    pub fn needs_rehash(&self, hash: &str) -> bool {
        match self.algorithm {
            #[cfg(feature = "argon2")]
            Algorithm::Argon2id => !hash.starts_with("$argon2id"),
            #[cfg(feature = "bcrypt")]
            Algorithm::Bcrypt => {
                if !hash.starts_with("$2") {
                    return true;
                }
                // 检查 cost 是否匹配
                if let Some(cost_str) = hash.get(4..6)
                    && let Ok(cost) = cost_str.parse::<u32>()
                {
                    return cost < self.bcrypt_cost;
                }
                true
            }
            #[cfg(feature = "scrypt")]
            Algorithm::Scrypt => !hash.starts_with("$scrypt$"),
        }
    }

    // ========================================================================
    // Argon2 实现
    // ========================================================================

    #[cfg(feature = "argon2")]
    fn hash_argon2(&self, password: &str) -> Result<String> {
        // Generate 16 bytes of random data for salt using getrandom
        let mut salt_bytes = [0u8; 16];
        getrandom::fill(&mut salt_bytes).map_err(|e| {
            Error::PasswordHash(PasswordHashError::HashFailed(format!(
                "Failed to generate random salt: {}",
                e
            )))
        })?;
        let salt = SaltString::encode_b64(&salt_bytes).map_err(|e| {
            Error::PasswordHash(PasswordHashError::HashFailed(format!(
                "Failed to encode salt: {}",
                e
            )))
        })?;
        let argon2 = Argon2::default();

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| {
                Error::PasswordHash(PasswordHashError::HashFailed(format!(
                    "Argon2 hash failed: {}",
                    e
                )))
            })
    }

    #[cfg(feature = "argon2")]
    fn verify_argon2(&self, password: &str, hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(hash).map_err(|e| {
            Error::PasswordHash(PasswordHashError::InvalidFormat(format!(
                "invalid Argon2 hash: {}",
                e
            )))
        })?;

        let argon2 = Argon2::default();
        Ok(argon2
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    // ========================================================================
    // bcrypt 实现
    // ========================================================================

    #[cfg(feature = "bcrypt")]
    fn hash_bcrypt(&self, password: &str) -> Result<String> {
        bcrypt::hash(password, self.bcrypt_cost).map_err(|e| {
            Error::PasswordHash(PasswordHashError::HashFailed(format!(
                "bcrypt hash failed: {}",
                e
            )))
        })
    }

    #[cfg(feature = "bcrypt")]
    fn verify_bcrypt(&self, password: &str, hash: &str) -> Result<bool> {
        bcrypt::verify(password, hash).map_err(|e| {
            Error::PasswordHash(PasswordHashError::InvalidFormat(format!(
                "bcrypt verify failed: {}",
                e
            )))
        })
    }

    // ========================================================================
    // scrypt 实现
    // ========================================================================

    #[cfg(feature = "scrypt")]
    fn hash_scrypt(&self, password: &str) -> Result<String> {
        let mut salt_bytes = [0u8; 16];
        getrandom::fill(&mut salt_bytes).map_err(|e| {
            Error::PasswordHash(PasswordHashError::HashFailed(format!(
                "Failed to generate random salt: {}",
                e
            )))
        })?;
        let salt = SaltString::encode_b64(&salt_bytes).map_err(|e| {
            Error::PasswordHash(PasswordHashError::HashFailed(format!(
                "Failed to encode salt: {}",
                e
            )))
        })?;

        Scrypt
            .hash_password_customized(password.as_bytes(), None, None, self.scrypt_params, &salt)
            .map(|h| h.to_string())
            .map_err(|e| {
                Error::PasswordHash(PasswordHashError::HashFailed(format!(
                    "scrypt hash failed: {}",
                    e
                )))
            })
    }

    #[cfg(feature = "scrypt")]
    fn verify_scrypt(&self, password: &str, hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(hash).map_err(|e| {
            Error::PasswordHash(PasswordHashError::InvalidFormat(format!(
                "invalid scrypt hash: {}",
                e
            )))
        })?;

        Ok(Scrypt
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }
}

// ============================================================================
// 便捷函数
// ============================================================================

/// 使用默认算法哈希密码
///
/// 默认使用 Argon2id（如果启用），否则回退到 bcrypt，再否则使用 scrypt
///
/// # Arguments
///
/// * `password` - 要哈希的明文密码
///
/// # Returns
///
/// 返回哈希后的密码字符串
///
/// # Example
///
/// ```rust
/// use authrs::password::hash_password;
///
/// let hash = hash_password("my_secure_password").unwrap();
/// println!("Hash: {}", hash);
/// ```
pub fn hash_password(password: &str) -> Result<String> {
    PasswordHasher::default().hash(password)
}

/// 验证密码是否匹配哈希
///
/// 自动检测哈希格式（支持 Argon2 / bcrypt / scrypt，取决于启用的 feature）
///
/// # Arguments
///
/// * `password` - 要验证的明文密码
/// * `hash` - 存储的哈希值
///
/// # Returns
///
/// 如果密码正确返回 `Ok(true)`，密码错误返回 `Ok(false)`
///
/// # Example
///
/// ```rust
/// use authrs::password::{hash_password, verify_password};
///
/// let hash = hash_password("my_secure_password").unwrap();
///
/// assert!(verify_password("my_secure_password", &hash).unwrap());
/// assert!(!verify_password("wrong_password", &hash).unwrap());
/// ```
pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    PasswordHasher::default().verify(password, hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "argon2")]
    fn test_argon2_hash_and_verify() {
        let hasher = PasswordHasher::new(Algorithm::Argon2id);
        let password = "test_password_123";

        let hash = hasher.hash(password).unwrap();
        assert!(hash.starts_with("$argon2id"));

        assert!(hasher.verify(password, &hash).unwrap());
        assert!(!hasher.verify("wrong_password", &hash).unwrap());
    }

    #[test]
    #[cfg(feature = "bcrypt")]
    fn test_bcrypt_hash_and_verify() {
        let hasher = PasswordHasher::new(Algorithm::Bcrypt).with_bcrypt_cost(4); // 使用低 cost 加快测试
        let password = "test_password_123";

        let hash = hasher.hash(password).unwrap();
        assert!(hash.starts_with("$2"));

        assert!(hasher.verify(password, &hash).unwrap());
        assert!(!hasher.verify("wrong_password", &hash).unwrap());
    }

    #[test]
    #[cfg(feature = "scrypt")]
    fn test_scrypt_hash_and_verify() {
        let hasher = PasswordHasher::new(Algorithm::Scrypt);
        let password = "test_password_123";

        let hash = hasher.hash(password).unwrap();
        assert!(hash.starts_with("$scrypt$"));

        assert!(hasher.verify(password, &hash).unwrap());
        assert!(!hasher.verify("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_convenience_functions() {
        let password = "my_secure_password";

        let hash = hash_password(password).unwrap();
        assert!(verify_password(password, &hash).unwrap());
        assert!(!verify_password("wrong", &hash).unwrap());
    }

    #[test]
    fn test_auto_detect_algorithm() {
        let hasher = PasswordHasher::default();

        // 测试默认算法哈希
        let default_hash = hasher.hash("test").unwrap();
        assert!(hasher.verify("test", &default_hash).unwrap());

        #[cfg(feature = "argon2")]
        {
            // 测试 Argon2 哈希
            let argon2_hasher = PasswordHasher::new(Algorithm::Argon2id);
            let argon2_hash = argon2_hasher.hash("test").unwrap();
            assert!(hasher.verify("test", &argon2_hash).unwrap());
        }

        #[cfg(feature = "bcrypt")]
        {
            // 测试 bcrypt 哈希
            let bcrypt_hasher = PasswordHasher::new(Algorithm::Bcrypt).with_bcrypt_cost(4);
            let bcrypt_hash = bcrypt_hasher.hash("test").unwrap();
            assert!(hasher.verify("test", &bcrypt_hash).unwrap());
        }

        #[cfg(feature = "scrypt")]
        {
            // 测试 scrypt 哈希
            let scrypt_hasher = PasswordHasher::new(Algorithm::Scrypt);
            let scrypt_hash = scrypt_hasher.hash("test").unwrap();
            assert!(hasher.verify("test", &scrypt_hash).unwrap());
        }
    }

    #[test]
    #[cfg(feature = "argon2")]
    fn test_needs_rehash_argon2() {
        let argon2_hasher = PasswordHasher::new(Algorithm::Argon2id);

        // Argon2 哈希使用 Argon2 hasher 不需要 rehash
        let argon2_hash = argon2_hasher.hash("test").unwrap();
        assert!(!argon2_hasher.needs_rehash(&argon2_hash));
    }

    #[test]
    #[cfg(feature = "bcrypt")]
    fn test_needs_rehash_bcrypt() {
        let bcrypt_hasher = PasswordHasher::new(Algorithm::Bcrypt).with_bcrypt_cost(12);

        // 低 cost 的 bcrypt 哈希需要 rehash
        let low_cost_hasher = PasswordHasher::new(Algorithm::Bcrypt).with_bcrypt_cost(4);
        let low_cost_hash = low_cost_hasher.hash("test").unwrap();
        assert!(bcrypt_hasher.needs_rehash(&low_cost_hash));
    }

    #[test]
    #[cfg(feature = "scrypt")]
    fn test_needs_rehash_scrypt() {
        let hasher = PasswordHasher::new(Algorithm::Scrypt);
        let hash = hasher.hash("test").unwrap();
        assert!(!hasher.needs_rehash(&hash));
        assert!(hasher.needs_rehash("$argon2id$dummy"));
    }

    #[test]
    #[cfg(all(feature = "argon2", feature = "bcrypt"))]
    fn test_needs_rehash_cross_algorithm() {
        let argon2_hasher = PasswordHasher::new(Algorithm::Argon2id);
        let bcrypt_hasher = PasswordHasher::new(Algorithm::Bcrypt).with_bcrypt_cost(12);

        // Argon2 哈希使用 bcrypt hasher 需要 rehash
        let argon2_hash = argon2_hasher.hash("test").unwrap();
        assert!(bcrypt_hasher.needs_rehash(&argon2_hash));
    }

    #[test]
    fn test_invalid_hash_format() {
        let hasher = PasswordHasher::default();
        let result = hasher.verify("test", "invalid_hash");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_password() {
        let hasher = PasswordHasher::default();

        // 空密码应该也能正常哈希
        let hash = hasher.hash("").unwrap();
        assert!(hasher.verify("", &hash).unwrap());
        assert!(!hasher.verify("not_empty", &hash).unwrap());
    }

    #[test]
    fn test_unicode_password() {
        let hasher = PasswordHasher::default();
        let password = "密码测试🔐émoji";

        let hash = hasher.hash(password).unwrap();
        assert!(hasher.verify(password, &hash).unwrap());
        assert!(!hasher.verify("wrong", &hash).unwrap());
    }

    #[test]
    fn test_long_password() {
        let hasher = PasswordHasher::default();
        let password = "a".repeat(1000);

        let hash = hasher.hash(&password).unwrap();
        assert!(hasher.verify(&password, &hash).unwrap());
    }

    #[test]
    #[should_panic(expected = "bcrypt cost must be between 4 and 31")]
    #[cfg(feature = "bcrypt")]
    fn test_invalid_bcrypt_cost_low() {
        PasswordHasher::new(Algorithm::Bcrypt).with_bcrypt_cost(3);
    }

    #[test]
    #[should_panic(expected = "bcrypt cost must be between 4 and 31")]
    #[cfg(feature = "bcrypt")]
    fn test_invalid_bcrypt_cost_high() {
        PasswordHasher::new(Algorithm::Bcrypt).with_bcrypt_cost(32);
    }

    #[test]
    fn test_different_hashes_same_password() {
        let hasher = PasswordHasher::default();
        let password = "same_password";

        let hash1 = hasher.hash(password).unwrap();
        let hash2 = hasher.hash(password).unwrap();

        // 由于 salt 不同，同一密码每次生成的哈希应该不同
        assert_ne!(hash1, hash2);

        // 但两个哈希都应该能验证成功
        assert!(hasher.verify(password, &hash1).unwrap());
        assert!(hasher.verify(password, &hash2).unwrap());
    }
}
