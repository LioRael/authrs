//! TOTP (基于时间的一次性密码) 实现模块
//!
//! 提供 TOTP 的生成、验证和管理功能，兼容 Google Authenticator、Authy 等应用。
//!
//! ## 特性
//!
//! - 符合 RFC 6238 标准
//! - 支持自定义时间步长和位数
//! - 生成 otpauth:// URI 和二维码
//! - 备用恢复码生成
//!
//! ## 示例
//!
//! ```rust
//! use authrs::mfa::totp::{TotpManager, TotpConfig};
//!
//! // 创建 TOTP 管理器
//! let config = TotpConfig::default();
//! let manager = TotpManager::new(config);
//!
//! // 为用户生成密钥
//! let secret = manager.generate_secret();
//!
//! // 生成当前 TOTP 码
//! let code = manager.generate_code(&secret).unwrap();
//! println!("当前验证码: {}", code);
//!
//! // 验证用户输入的码
//! let is_valid = manager.verify(&secret, &code).unwrap();
//! assert!(is_valid);
//! ```

use base32::{decode as base32_decode, encode as base32_encode, Alphabet};
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result, ValidationError};
use crate::random::generate_random_bytes;

/// TOTP 哈希算法
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TotpAlgorithm {
    /// SHA-1（默认，最广泛支持）
    #[default]
    SHA1,
    /// SHA-256
    SHA256,
    /// SHA-512
    SHA512,
}

impl TotpAlgorithm {
    /// 获取算法名称（用于 otpauth URI）
    pub fn as_str(&self) -> &'static str {
        match self {
            TotpAlgorithm::SHA1 => "SHA1",
            TotpAlgorithm::SHA256 => "SHA256",
            TotpAlgorithm::SHA512 => "SHA512",
        }
    }
}

/// TOTP 配置
#[derive(Debug, Clone)]
pub struct TotpConfig {
    /// 时间步长（秒），默认 30 秒
    pub time_step: u64,

    /// 验证码位数，默认 6 位
    pub digits: u32,

    /// 哈希算法
    pub algorithm: TotpAlgorithm,

    /// 允许的时间偏差窗口（前后各多少个时间步）
    /// 默认为 1，即允许前后各 30 秒的误差
    pub skew: u64,

    /// 密钥长度（字节），默认 20 字节（160 位）
    pub secret_length: usize,

    /// 签发者名称（显示在认证器应用中）
    pub issuer: Option<String>,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            time_step: 30,
            digits: 6,
            algorithm: TotpAlgorithm::SHA1,
            skew: 1,
            secret_length: 20,
            issuer: None,
        }
    }
}

impl TotpConfig {
    /// 创建新的配置
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置时间步长
    pub fn with_time_step(mut self, seconds: u64) -> Self {
        self.time_step = seconds;
        self
    }

    /// 设置验证码位数
    pub fn with_digits(mut self, digits: u32) -> Self {
        assert!(digits >= 6 && digits <= 8, "digits must be between 6 and 8");
        self.digits = digits;
        self
    }

    /// 设置哈希算法
    pub fn with_algorithm(mut self, algorithm: TotpAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// 设置时间偏差窗口
    pub fn with_skew(mut self, skew: u64) -> Self {
        self.skew = skew;
        self
    }

    /// 设置签发者
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// 设置密钥长度
    pub fn with_secret_length(mut self, length: usize) -> Self {
        assert!(length >= 16, "secret length must be at least 16 bytes");
        self.secret_length = length;
        self
    }

    /// 创建 Google Authenticator 兼容配置
    pub fn google_authenticator() -> Self {
        Self {
            time_step: 30,
            digits: 6,
            algorithm: TotpAlgorithm::SHA1,
            skew: 1,
            secret_length: 20,
            issuer: None,
        }
    }

    /// 创建高安全性配置
    pub fn high_security() -> Self {
        Self {
            time_step: 30,
            digits: 8,
            algorithm: TotpAlgorithm::SHA256,
            skew: 0,
            secret_length: 32,
            issuer: None,
        }
    }
}

/// TOTP 密钥信息
#[derive(Debug, Clone)]
pub struct TotpSecret {
    /// 原始密钥字节
    pub raw: Vec<u8>,

    /// Base32 编码的密钥（用于显示和 URI）
    pub base32: String,
}

impl TotpSecret {
    /// 从原始字节创建
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let base32 = base32_encode(Alphabet::Rfc4648 { padding: false }, &bytes);
        Self { raw: bytes, base32 }
    }

    /// 从 Base32 字符串创建
    pub fn from_base32(base32: &str) -> Result<Self> {
        let clean = base32.replace([' ', '-'], "").to_uppercase();
        let raw = base32_decode(Alphabet::Rfc4648 { padding: false }, &clean).ok_or_else(|| {
            Error::Validation(ValidationError::Custom("invalid base32 secret".to_string()))
        })?;
        Ok(Self { raw, base32: clean })
    }
}

/// TOTP 验证结果
#[derive(Debug, Clone)]
pub struct TotpVerifyResult {
    /// 是否验证成功
    pub valid: bool,

    /// 匹配的时间步偏移量（0 表示当前步，负数表示过去，正数表示未来）
    pub time_step_offset: i64,

    /// 验证时的时间戳
    pub verified_at: i64,
}

/// TOTP 管理器
#[derive(Debug, Clone)]
pub struct TotpManager {
    config: TotpConfig,
}

impl TotpManager {
    /// 创建新的 TOTP 管理器
    pub fn new(config: TotpConfig) -> Self {
        Self { config }
    }

    /// 使用默认配置创建管理器
    pub fn default_manager() -> Self {
        Self::new(TotpConfig::default())
    }

    /// 生成新的 TOTP 密钥
    pub fn generate_secret(&self) -> Result<TotpSecret> {
        let bytes = generate_random_bytes(self.config.secret_length)?;
        Ok(TotpSecret::from_bytes(bytes))
    }

    /// 生成当前的 TOTP 验证码
    pub fn generate_code(&self, secret: &TotpSecret) -> Result<String> {
        let timestamp = self.current_timestamp();
        self.generate_code_at(secret, timestamp)
    }

    /// 生成指定时间的 TOTP 验证码
    pub fn generate_code_at(&self, secret: &TotpSecret, timestamp: u64) -> Result<String> {
        let counter = timestamp / self.config.time_step;
        self.generate_hotp(&secret.raw, counter)
    }

    /// 验证 TOTP 验证码
    pub fn verify(&self, secret: &TotpSecret, code: &str) -> Result<bool> {
        let result = self.verify_with_result(secret, code)?;
        Ok(result.valid)
    }

    /// 验证 TOTP 验证码并返回详细结果
    pub fn verify_with_result(&self, secret: &TotpSecret, code: &str) -> Result<TotpVerifyResult> {
        let timestamp = self.current_timestamp();
        let current_counter = timestamp / self.config.time_step;

        // 规范化输入码
        let normalized_code = code.replace([' ', '-'], "");

        // 检查码的长度
        if normalized_code.len() != self.config.digits as usize {
            return Ok(TotpVerifyResult {
                valid: false,
                time_step_offset: 0,
                verified_at: timestamp as i64,
            });
        }

        // 在允许的时间窗口内检查
        for offset in -(self.config.skew as i64)..=(self.config.skew as i64) {
            let check_counter = (current_counter as i64 + offset) as u64;
            let expected_code = self.generate_hotp(&secret.raw, check_counter)?;

            if constant_time_eq(normalized_code.as_bytes(), expected_code.as_bytes()) {
                return Ok(TotpVerifyResult {
                    valid: true,
                    time_step_offset: offset,
                    verified_at: timestamp as i64,
                });
            }
        }

        Ok(TotpVerifyResult {
            valid: false,
            time_step_offset: 0,
            verified_at: timestamp as i64,
        })
    }

    /// 生成 otpauth:// URI
    ///
    /// 此 URI 可用于生成二维码，供认证器应用扫描
    pub fn generate_uri(&self, secret: &TotpSecret, account: &str) -> String {
        let mut uri = format!(
            "otpauth://totp/{}?secret={}&digits={}&period={}&algorithm={}",
            urlencoding::encode(account),
            secret.base32,
            self.config.digits,
            self.config.time_step,
            self.config.algorithm.as_str()
        );

        if let Some(ref issuer) = self.config.issuer {
            uri.push_str(&format!("&issuer={}", urlencoding::encode(issuer)));
        }

        uri
    }

    /// 生成带签发者前缀的 otpauth:// URI
    ///
    /// 格式: otpauth://totp/Issuer:account?...
    pub fn generate_uri_with_issuer(
        &self,
        secret: &TotpSecret,
        account: &str,
        issuer: &str,
    ) -> String {
        let label = format!("{}:{}", issuer, account);
        let mut uri = format!(
            "otpauth://totp/{}?secret={}&digits={}&period={}&algorithm={}&issuer={}",
            urlencoding::encode(&label),
            secret.base32,
            self.config.digits,
            self.config.time_step,
            self.config.algorithm.as_str(),
            urlencoding::encode(issuer)
        );

        uri
    }

    /// 获取当前验证码的剩余有效时间（秒）
    pub fn time_remaining(&self) -> u64 {
        let timestamp = self.current_timestamp();
        self.config.time_step - (timestamp % self.config.time_step)
    }

    /// 获取配置
    pub fn config(&self) -> &TotpConfig {
        &self.config
    }

    // ========================================================================
    // 内部方法
    // ========================================================================

    /// 获取当前 Unix 时间戳
    fn current_timestamp(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs()
    }

    /// 生成 HOTP 验证码
    fn generate_hotp(&self, secret: &[u8], counter: u64) -> Result<String> {
        let counter_bytes = counter.to_be_bytes();

        let hash = match self.config.algorithm {
            TotpAlgorithm::SHA1 => {
                let mut mac = Hmac::<Sha1>::new_from_slice(secret).map_err(|_| {
                    Error::Validation(ValidationError::Custom("invalid secret key".to_string()))
                })?;
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            TotpAlgorithm::SHA256 => {
                let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| {
                    Error::Validation(ValidationError::Custom("invalid secret key".to_string()))
                })?;
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
            TotpAlgorithm::SHA512 => {
                let mut mac = Hmac::<Sha512>::new_from_slice(secret).map_err(|_| {
                    Error::Validation(ValidationError::Custom("invalid secret key".to_string()))
                })?;
                mac.update(&counter_bytes);
                mac.finalize().into_bytes().to_vec()
            }
        };

        // 动态截断
        let offset = (hash.last().unwrap() & 0x0f) as usize;
        let binary = ((hash[offset] & 0x7f) as u32) << 24
            | (hash[offset + 1] as u32) << 16
            | (hash[offset + 2] as u32) << 8
            | (hash[offset + 3] as u32);

        // 取模得到指定位数的码
        let modulo = 10u32.pow(self.config.digits);
        let code = binary % modulo;

        // 左填充零
        Ok(format!(
            "{:0width$}",
            code,
            width = self.config.digits as usize
        ))
    }
}

/// 常量时间字符串比较
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// 恢复码管理器
#[derive(Debug, Clone)]
pub struct RecoveryCodeManager {
    /// 恢复码数量
    code_count: usize,
    /// 恢复码长度（不含分隔符）
    code_length: usize,
}

impl Default for RecoveryCodeManager {
    fn default() -> Self {
        Self {
            code_count: 10,
            code_length: 8,
        }
    }
}

impl RecoveryCodeManager {
    /// 创建新的恢复码管理器
    pub fn new(code_count: usize, code_length: usize) -> Self {
        Self {
            code_count,
            code_length,
        }
    }

    /// 生成恢复码列表
    pub fn generate(&self) -> Result<Vec<String>> {
        crate::random::generate_recovery_codes(self.code_count)
    }

    /// 验证恢复码
    ///
    /// 返回匹配的恢复码索引（如果找到）
    pub fn verify(&self, code: &str, stored_codes: &[String]) -> Option<usize> {
        let normalized = code.replace([' ', '-'], "").to_uppercase();

        for (index, stored) in stored_codes.iter().enumerate() {
            let stored_normalized = stored.replace([' ', '-'], "").to_uppercase();
            if constant_time_eq(normalized.as_bytes(), stored_normalized.as_bytes()) {
                return Some(index);
            }
        }

        None
    }

    /// 生成恢复码的哈希版本（用于安全存储）
    pub fn hash_codes(&self, codes: &[String]) -> Result<Vec<String>> {
        codes
            .iter()
            .map(|code| {
                let normalized = code.replace([' ', '-'], "").to_uppercase();
                crate::password::hash_password(&normalized)
            })
            .collect()
    }

    /// 验证恢复码（与哈希版本比较）
    pub fn verify_hashed(&self, code: &str, hashed_codes: &[String]) -> Result<Option<usize>> {
        let normalized = code.replace([' ', '-'], "").to_uppercase();

        for (index, hashed) in hashed_codes.iter().enumerate() {
            if crate::password::verify_password(&normalized, hashed)? {
                return Ok(Some(index));
            }
        }

        Ok(None)
    }
}

/// MFA 设置结果
#[derive(Debug, Clone)]
pub struct MfaSetupResult {
    /// TOTP 密钥
    pub secret: TotpSecret,
    /// otpauth:// URI（用于二维码）
    pub uri: String,
    /// 恢复码列表
    pub recovery_codes: Vec<String>,
}

/// 便捷函数：设置用户的 MFA
pub fn setup_mfa(account: &str, issuer: &str) -> Result<MfaSetupResult> {
    let config = TotpConfig::default().with_issuer(issuer);
    let manager = TotpManager::new(config);
    let secret = manager.generate_secret()?;
    let uri = manager.generate_uri_with_issuer(&secret, account, issuer);

    let recovery_manager = RecoveryCodeManager::default();
    let recovery_codes = recovery_manager.generate()?;

    Ok(MfaSetupResult {
        secret,
        uri,
        recovery_codes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_totp_config_default() {
        let config = TotpConfig::default();
        assert_eq!(config.time_step, 30);
        assert_eq!(config.digits, 6);
        assert_eq!(config.algorithm, TotpAlgorithm::SHA1);
        assert_eq!(config.skew, 1);
    }

    #[test]
    fn test_totp_config_builder() {
        let config = TotpConfig::new()
            .with_time_step(60)
            .with_digits(8)
            .with_algorithm(TotpAlgorithm::SHA256)
            .with_issuer("MyApp")
            .with_skew(2);

        assert_eq!(config.time_step, 60);
        assert_eq!(config.digits, 8);
        assert_eq!(config.algorithm, TotpAlgorithm::SHA256);
        assert_eq!(config.issuer, Some("MyApp".to_string()));
        assert_eq!(config.skew, 2);
    }

    #[test]
    fn test_generate_secret() {
        let manager = TotpManager::default_manager();
        let secret = manager.generate_secret().unwrap();

        assert_eq!(secret.raw.len(), 20);
        assert!(!secret.base32.is_empty());
    }

    #[test]
    fn test_secret_from_base32() {
        let original = TotpManager::default_manager().generate_secret().unwrap();
        let restored = TotpSecret::from_base32(&original.base32).unwrap();

        assert_eq!(original.raw, restored.raw);
    }

    #[test]
    fn test_generate_and_verify_code() {
        let manager = TotpManager::default_manager();
        let secret = manager.generate_secret().unwrap();

        let code = manager.generate_code(&secret).unwrap();
        assert_eq!(code.len(), 6);

        let is_valid = manager.verify(&secret, &code).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_verify_with_spaces() {
        let manager = TotpManager::default_manager();
        let secret = manager.generate_secret().unwrap();

        let code = manager.generate_code(&secret).unwrap();
        let spaced_code = format!("{} {}", &code[..3], &code[3..]);

        let is_valid = manager.verify(&secret, &spaced_code).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_verify_invalid_code() {
        let manager = TotpManager::default_manager();
        let secret = manager.generate_secret().unwrap();

        let is_valid = manager.verify(&secret, "000000").unwrap();
        // 可能偶然有效，但概率极低
        // 这里只是测试不会崩溃
        let _ = is_valid;
    }

    #[test]
    fn test_verify_wrong_length() {
        let manager = TotpManager::default_manager();
        let secret = manager.generate_secret().unwrap();

        let result = manager.verify_with_result(&secret, "12345").unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_generate_uri() {
        let config = TotpConfig::default().with_issuer("MyApp");
        let manager = TotpManager::new(config);
        let secret = TotpSecret::from_bytes(vec![0u8; 20]);

        let uri = manager.generate_uri(&secret, "user@example.com");

        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("secret="));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
        assert!(uri.contains("issuer=MyApp"));
    }

    #[test]
    fn test_generate_uri_with_issuer() {
        let manager = TotpManager::default_manager();
        let secret = TotpSecret::from_bytes(vec![0u8; 20]);

        let uri = manager.generate_uri_with_issuer(&secret, "user@example.com", "MyApp");

        assert!(uri.contains("MyApp%3Auser%40example.com") || uri.contains("MyApp:user"));
        assert!(uri.contains("issuer=MyApp"));
    }

    #[test]
    fn test_time_remaining() {
        let manager = TotpManager::default_manager();
        let remaining = manager.time_remaining();

        assert!(remaining > 0);
        assert!(remaining <= 30);
    }

    #[test]
    fn test_totp_with_different_algorithms() {
        for algorithm in [
            TotpAlgorithm::SHA1,
            TotpAlgorithm::SHA256,
            TotpAlgorithm::SHA512,
        ] {
            let config = TotpConfig::default().with_algorithm(algorithm);
            let manager = TotpManager::new(config);
            let secret = manager.generate_secret().unwrap();

            let code = manager.generate_code(&secret).unwrap();
            let is_valid = manager.verify(&secret, &code).unwrap();
            assert!(is_valid, "Failed for algorithm {:?}", algorithm);
        }
    }

    #[test]
    fn test_totp_8_digits() {
        let config = TotpConfig::default().with_digits(8);
        let manager = TotpManager::new(config);
        let secret = manager.generate_secret().unwrap();

        let code = manager.generate_code(&secret).unwrap();
        assert_eq!(code.len(), 8);

        let is_valid = manager.verify(&secret, &code).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_verify_with_result() {
        let manager = TotpManager::default_manager();
        let secret = manager.generate_secret().unwrap();

        let code = manager.generate_code(&secret).unwrap();
        let result = manager.verify_with_result(&secret, &code).unwrap();

        assert!(result.valid);
        assert_eq!(result.time_step_offset, 0);
    }

    #[test]
    fn test_recovery_code_manager() {
        let manager = RecoveryCodeManager::default();
        let codes = manager.generate().unwrap();

        assert_eq!(codes.len(), 10);
        for code in &codes {
            assert_eq!(code.len(), 9); // 8 chars + 1 hyphen
        }
    }

    #[test]
    fn test_recovery_code_verify() {
        let manager = RecoveryCodeManager::default();
        let codes = manager.generate().unwrap();

        // 验证存在的码
        let index = manager.verify(&codes[0], &codes);
        assert_eq!(index, Some(0));

        // 验证不存在的码
        let index = manager.verify("INVALID-CODE", &codes);
        assert!(index.is_none());
    }

    #[test]
    fn test_recovery_code_verify_case_insensitive() {
        let manager = RecoveryCodeManager::default();
        let codes = manager.generate().unwrap();

        let lowercase = codes[0].to_lowercase();
        let index = manager.verify(&lowercase, &codes);
        assert_eq!(index, Some(0));
    }

    #[test]
    fn test_setup_mfa() {
        let result = setup_mfa("user@example.com", "MyApp").unwrap();

        assert!(!result.secret.base32.is_empty());
        assert!(result.uri.starts_with("otpauth://totp/"));
        assert_eq!(result.recovery_codes.len(), 10);
    }

    #[test]
    fn test_config_presets() {
        let google = TotpConfig::google_authenticator();
        assert_eq!(google.digits, 6);
        assert_eq!(google.time_step, 30);
        assert_eq!(google.algorithm, TotpAlgorithm::SHA1);

        let high_sec = TotpConfig::high_security();
        assert_eq!(high_sec.digits, 8);
        assert_eq!(high_sec.algorithm, TotpAlgorithm::SHA256);
    }

    #[test]
    fn test_algorithm_as_str() {
        assert_eq!(TotpAlgorithm::SHA1.as_str(), "SHA1");
        assert_eq!(TotpAlgorithm::SHA256.as_str(), "SHA256");
        assert_eq!(TotpAlgorithm::SHA512.as_str(), "SHA512");
    }

    // RFC 6238 测试向量
    #[test]
    fn test_rfc6238_test_vectors() {
        // 测试密钥（ASCII "12345678901234567890"）
        let secret = TotpSecret::from_bytes(b"12345678901234567890".to_vec());

        let config = TotpConfig::default()
            .with_algorithm(TotpAlgorithm::SHA1)
            .with_digits(8);
        let manager = TotpManager::new(config);

        // 测试时间: 59 秒 (counter = 1)
        let code = manager.generate_code_at(&secret, 59).unwrap();
        assert_eq!(code, "94287082");

        // 测试时间: 1111111109 秒
        let code = manager.generate_code_at(&secret, 1111111109).unwrap();
        assert_eq!(code, "07081804");
    }
}
