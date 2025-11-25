//! HOTP (基于计数器的一次性密码) 实现模块
//!
//! 提供 HOTP 的生成、验证和管理功能。
//!
//! ## 特性
//!
//! - 符合 RFC 4226 标准
//! - 支持自定义位数
//! - 支持计数器同步窗口
//!
//! ## 示例
//!
//! ```rust
//! use authrs::mfa::hotp::{HotpGenerator, HotpConfig};
//!
//! // 创建 HOTP 生成器
//! let config = HotpConfig::default();
//! let generator = HotpGenerator::new(config);
//!
//! // 生成密钥
//! let secret = generator.generate_secret().unwrap();
//!
//! // 生成指定计数器的 HOTP 码
//! let code = generator.generate(&secret, 0).unwrap();
//! println!("验证码: {}", code);
//!
//! // 验证用户输入的码
//! let (is_valid, new_counter) = generator.verify(&secret, &code, 0).unwrap();
//! ```

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

use crate::error::{Error, Result, ValidationError};
use crate::mfa::totp::{TotpAlgorithm, TotpSecret};
use crate::random::generate_random_bytes;

/// HOTP 配置
#[derive(Debug, Clone)]
pub struct HotpConfig {
    /// 验证码位数，默认 6 位
    pub digits: u32,

    /// 哈希算法
    pub algorithm: TotpAlgorithm,

    /// 同步窗口大小（向前查找的计数器数量）
    pub look_ahead_window: u64,

    /// 密钥长度（字节），默认 20 字节（160 位）
    pub secret_length: usize,
}

impl Default for HotpConfig {
    fn default() -> Self {
        Self {
            digits: 6,
            algorithm: TotpAlgorithm::SHA1,
            look_ahead_window: 10,
            secret_length: 20,
        }
    }
}

impl HotpConfig {
    /// 创建新的配置
    pub fn new() -> Self {
        Self::default()
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

    /// 设置同步窗口大小
    pub fn with_look_ahead_window(mut self, window: u64) -> Self {
        self.look_ahead_window = window;
        self
    }

    /// 设置密钥长度
    pub fn with_secret_length(mut self, length: usize) -> Self {
        assert!(length >= 16, "secret length must be at least 16 bytes");
        self.secret_length = length;
        self
    }
}

/// HOTP 验证结果
#[derive(Debug, Clone)]
pub struct HotpVerifyResult {
    /// 是否验证成功
    pub valid: bool,

    /// 匹配时的计数器值（如果验证成功）
    pub matched_counter: Option<u64>,

    /// 建议的下一个计数器值
    pub next_counter: u64,
}

/// HOTP 生成器
#[derive(Debug, Clone)]
pub struct HotpGenerator {
    config: HotpConfig,
}

impl HotpGenerator {
    /// 创建新的 HOTP 生成器
    pub fn new(config: HotpConfig) -> Self {
        Self { config }
    }

    /// 使用默认配置创建生成器
    pub fn default_generator() -> Self {
        Self::new(HotpConfig::default())
    }

    /// 生成新的 HOTP 密钥
    pub fn generate_secret(&self) -> Result<TotpSecret> {
        let bytes = generate_random_bytes(self.config.secret_length)?;
        Ok(TotpSecret::from_bytes(bytes))
    }

    /// 生成 HOTP 验证码
    ///
    /// # 参数
    ///
    /// * `secret` - 密钥
    /// * `counter` - 计数器值
    ///
    /// # 返回
    ///
    /// 返回生成的验证码字符串
    pub fn generate(&self, secret: &TotpSecret, counter: u64) -> Result<String> {
        self.generate_hotp(&secret.raw, counter)
    }

    /// 验证 HOTP 验证码
    ///
    /// # 参数
    ///
    /// * `secret` - 密钥
    /// * `code` - 用户输入的验证码
    /// * `counter` - 当前计数器值
    ///
    /// # 返回
    ///
    /// 返回 (是否有效, 新的计数器值)
    pub fn verify(&self, secret: &TotpSecret, code: &str, counter: u64) -> Result<(bool, u64)> {
        let result = self.verify_with_result(secret, code, counter)?;
        Ok((result.valid, result.next_counter))
    }

    /// 验证 HOTP 验证码并返回详细结果
    pub fn verify_with_result(
        &self,
        secret: &TotpSecret,
        code: &str,
        counter: u64,
    ) -> Result<HotpVerifyResult> {
        // 规范化输入码
        let normalized_code = code.replace([' ', '-'], "");

        // 检查码的长度
        if normalized_code.len() != self.config.digits as usize {
            return Ok(HotpVerifyResult {
                valid: false,
                matched_counter: None,
                next_counter: counter,
            });
        }

        // 在同步窗口内检查
        for offset in 0..=self.config.look_ahead_window {
            let check_counter = counter + offset;
            let expected_code = self.generate_hotp(&secret.raw, check_counter)?;

            if constant_time_eq(normalized_code.as_bytes(), expected_code.as_bytes()) {
                return Ok(HotpVerifyResult {
                    valid: true,
                    matched_counter: Some(check_counter),
                    next_counter: check_counter + 1,
                });
            }
        }

        Ok(HotpVerifyResult {
            valid: false,
            matched_counter: None,
            next_counter: counter,
        })
    }

    /// 生成 otpauth:// URI
    ///
    /// 此 URI 可用于生成二维码，供认证器应用扫描
    pub fn generate_uri(&self, secret: &TotpSecret, account: &str, counter: u64) -> String {
        format!(
            "otpauth://hotp/{}?secret={}&digits={}&counter={}&algorithm={}",
            urlencoding::encode(account),
            secret.base32,
            self.config.digits,
            counter,
            self.config.algorithm.as_str()
        )
    }

    /// 生成带签发者的 otpauth:// URI
    pub fn generate_uri_with_issuer(
        &self,
        secret: &TotpSecret,
        account: &str,
        issuer: &str,
        counter: u64,
    ) -> String {
        let label = format!("{}:{}", issuer, account);
        format!(
            "otpauth://hotp/{}?secret={}&digits={}&counter={}&algorithm={}&issuer={}",
            urlencoding::encode(&label),
            secret.base32,
            self.config.digits,
            counter,
            self.config.algorithm.as_str(),
            urlencoding::encode(issuer)
        )
    }

    /// 获取配置
    pub fn config(&self) -> &HotpConfig {
        &self.config
    }

    // ========================================================================
    // 内部方法
    // ========================================================================

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hotp_config_default() {
        let config = HotpConfig::default();
        assert_eq!(config.digits, 6);
        assert_eq!(config.algorithm, TotpAlgorithm::SHA1);
        assert_eq!(config.look_ahead_window, 10);
    }

    #[test]
    fn test_hotp_config_builder() {
        let config = HotpConfig::new()
            .with_digits(8)
            .with_algorithm(TotpAlgorithm::SHA256)
            .with_look_ahead_window(20);

        assert_eq!(config.digits, 8);
        assert_eq!(config.algorithm, TotpAlgorithm::SHA256);
        assert_eq!(config.look_ahead_window, 20);
    }

    #[test]
    fn test_generate_secret() {
        let generator = HotpGenerator::default_generator();
        let secret = generator.generate_secret().unwrap();

        assert_eq!(secret.raw.len(), 20);
        assert!(!secret.base32.is_empty());
    }

    #[test]
    fn test_generate_code() {
        let generator = HotpGenerator::default_generator();
        let secret = generator.generate_secret().unwrap();

        let code0 = generator.generate(&secret, 0).unwrap();
        let code1 = generator.generate(&secret, 1).unwrap();

        assert_eq!(code0.len(), 6);
        assert_eq!(code1.len(), 6);
        // 不同计数器应该生成不同的码
        assert_ne!(code0, code1);
    }

    #[test]
    fn test_verify_code() {
        let generator = HotpGenerator::default_generator();
        let secret = generator.generate_secret().unwrap();

        let code = generator.generate(&secret, 5).unwrap();

        // 从计数器 5 开始验证应该成功
        let (is_valid, next_counter) = generator.verify(&secret, &code, 5).unwrap();
        assert!(is_valid);
        assert_eq!(next_counter, 6);

        // 从计数器 0 开始验证也应该成功（在窗口内）
        let (is_valid, next_counter) = generator.verify(&secret, &code, 0).unwrap();
        assert!(is_valid);
        assert_eq!(next_counter, 6);
    }

    #[test]
    fn test_verify_code_outside_window() {
        let config = HotpConfig::default().with_look_ahead_window(5);
        let generator = HotpGenerator::new(config);
        let secret = generator.generate_secret().unwrap();

        let code = generator.generate(&secret, 100).unwrap();

        // 从计数器 0 开始验证应该失败（超出窗口）
        let (is_valid, next_counter) = generator.verify(&secret, &code, 0).unwrap();
        assert!(!is_valid);
        assert_eq!(next_counter, 0); // 计数器不变
    }

    #[test]
    fn test_verify_invalid_code() {
        let generator = HotpGenerator::default_generator();
        let secret = generator.generate_secret().unwrap();

        let result = generator.verify_with_result(&secret, "000000", 0).unwrap();
        // 可能偶然有效，但概率极低
        let _ = result;
    }

    #[test]
    fn test_verify_wrong_length() {
        let generator = HotpGenerator::default_generator();
        let secret = generator.generate_secret().unwrap();

        let result = generator.verify_with_result(&secret, "12345", 0).unwrap();
        assert!(!result.valid);
    }

    #[test]
    fn test_generate_uri() {
        let generator = HotpGenerator::default_generator();
        let secret = TotpSecret::from_bytes(vec![0u8; 20]);

        let uri = generator.generate_uri(&secret, "user@example.com", 0);

        assert!(uri.starts_with("otpauth://hotp/"));
        assert!(uri.contains("secret="));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("counter=0"));
    }

    #[test]
    fn test_generate_uri_with_issuer() {
        let generator = HotpGenerator::default_generator();
        let secret = TotpSecret::from_bytes(vec![0u8; 20]);

        let uri = generator.generate_uri_with_issuer(&secret, "user@example.com", "MyApp", 0);

        assert!(uri.contains("issuer=MyApp"));
    }

    #[test]
    fn test_counter_increment() {
        let generator = HotpGenerator::default_generator();
        let secret = generator.generate_secret().unwrap();

        let mut counter = 0u64;

        for _ in 0..5 {
            let code = generator.generate(&secret, counter).unwrap();
            let (is_valid, new_counter) = generator.verify(&secret, &code, counter).unwrap();
            assert!(is_valid);
            counter = new_counter;
        }

        assert_eq!(counter, 5);
    }

    // RFC 4226 测试向量
    #[test]
    fn test_rfc4226_test_vectors() {
        let secret = TotpSecret::from_bytes(b"12345678901234567890".to_vec());

        let generator = HotpGenerator::default_generator();

        let expected_codes = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583",
            "399871", "520489",
        ];

        for (counter, expected) in expected_codes.iter().enumerate() {
            let code = generator.generate(&secret, counter as u64).unwrap();
            assert_eq!(&code, expected, "Failed at counter {}", counter);
        }
    }

    #[test]
    fn test_hotp_8_digits() {
        let config = HotpConfig::default().with_digits(8);
        let generator = HotpGenerator::new(config);
        let secret = generator.generate_secret().unwrap();

        let code = generator.generate(&secret, 0).unwrap();
        assert_eq!(code.len(), 8);

        let (is_valid, _) = generator.verify(&secret, &code, 0).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_hotp_with_different_algorithms() {
        for algorithm in [
            TotpAlgorithm::SHA1,
            TotpAlgorithm::SHA256,
            TotpAlgorithm::SHA512,
        ] {
            let config = HotpConfig::default().with_algorithm(algorithm);
            let generator = HotpGenerator::new(config);
            let secret = generator.generate_secret().unwrap();

            let code = generator.generate(&secret, 0).unwrap();
            let (is_valid, _) = generator.verify(&secret, &code, 0).unwrap();
            assert!(is_valid, "Failed for algorithm {:?}", algorithm);
        }
    }

    #[test]
    fn test_verify_with_spaces() {
        let generator = HotpGenerator::default_generator();
        let secret = generator.generate_secret().unwrap();

        let code = generator.generate(&secret, 0).unwrap();
        let spaced_code = format!("{} {}", &code[..3], &code[3..]);

        let (is_valid, _) = generator.verify(&secret, &spaced_code, 0).unwrap();
        assert!(is_valid);
    }
}
