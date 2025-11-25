//! 恢复码模块
//!
//! 提供 MFA 恢复码的生成、存储和验证功能。
//!
//! ## 特性
//!
//! - 生成易读的恢复码（排除易混淆字符）
//! - 支持哈希存储（安全）
//! - 一次性使用验证
//! - 批量生成和管理
//!
//! ## 示例
//!
//! ```rust
//! use authrs::mfa::recovery::{RecoveryCodeManager, RecoveryConfig};
//!
//! // 创建恢复码管理器
//! let config = RecoveryConfig::default();
//! let manager = RecoveryCodeManager::new(config);
//!
//! // 生成恢复码
//! let code_set = manager.generate().unwrap();
//! println!("请保存以下恢复码:");
//! for code in &code_set.plain_codes {
//!     println!("  {}", code);
//! }
//!
//! // 验证恢复码
//! let result = manager.verify(&code_set.plain_codes[0], &code_set.hashed_codes).unwrap();
//! if let Some(index) = result {
//!     println!("恢复码有效，索引: {}", index);
//! }
//! ```

use std::collections::HashSet;

use crate::error::Result;
use crate::password::{hash_password, verify_password};
use crate::random::generate_random_bytes;

/// 恢复码配置
#[derive(Debug, Clone)]
pub struct RecoveryConfig {
    /// 生成的恢复码数量
    pub code_count: usize,

    /// 每组字符数（不含分隔符）
    pub group_length: usize,

    /// 组数
    pub group_count: usize,

    /// 分隔符
    pub separator: char,

    /// 是否使用哈希存储
    pub hash_codes: bool,
}

impl Default for RecoveryConfig {
    fn default() -> Self {
        Self {
            code_count: 10,
            group_length: 4,
            group_count: 2,
            separator: '-',
            hash_codes: true,
        }
    }
}

impl RecoveryConfig {
    /// 创建新的配置
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置恢复码数量
    pub fn with_code_count(mut self, count: usize) -> Self {
        assert!(
            count > 0 && count <= 20,
            "code count must be between 1 and 20"
        );
        self.code_count = count;
        self
    }

    /// 设置每组字符数
    pub fn with_group_length(mut self, length: usize) -> Self {
        assert!(
            length >= 4 && length <= 8,
            "group length must be between 4 and 8"
        );
        self.group_length = length;
        self
    }

    /// 设置组数
    pub fn with_group_count(mut self, count: usize) -> Self {
        assert!(
            count >= 1 && count <= 4,
            "group count must be between 1 and 4"
        );
        self.group_count = count;
        self
    }

    /// 设置分隔符
    pub fn with_separator(mut self, separator: char) -> Self {
        self.separator = separator;
        self
    }

    /// 设置是否使用哈希存储
    pub fn with_hash(mut self, hash: bool) -> Self {
        self.hash_codes = hash;
        self
    }

    /// 创建高安全性配置
    pub fn high_security() -> Self {
        Self {
            code_count: 16,
            group_length: 5,
            group_count: 3,
            separator: '-',
            hash_codes: true,
        }
    }

    /// 创建简单配置（用于测试）
    pub fn simple() -> Self {
        Self {
            code_count: 5,
            group_length: 4,
            group_count: 2,
            separator: '-',
            hash_codes: false,
        }
    }
}

/// 恢复码集合
#[derive(Debug, Clone)]
pub struct RecoveryCodeSet {
    /// 明文恢复码（仅在生成时返回一次，应显示给用户）
    pub plain_codes: Vec<String>,

    /// 哈希后的恢复码（用于存储）
    pub hashed_codes: Vec<String>,

    /// 生成时间戳
    pub generated_at: i64,
}

/// 恢复码使用状态
#[derive(Debug, Clone)]
pub struct RecoveryCodeStatus {
    /// 总数
    pub total: usize,

    /// 已使用数量
    pub used: usize,

    /// 剩余数量
    pub remaining: usize,
}

/// 恢复码管理器
#[derive(Debug, Clone)]
pub struct RecoveryCodeManager {
    config: RecoveryConfig,
}

impl RecoveryCodeManager {
    /// 创建新的恢复码管理器
    pub fn new(config: RecoveryConfig) -> Self {
        Self { config }
    }

    /// 使用默认配置创建管理器
    pub fn default_manager() -> Self {
        Self::new(RecoveryConfig::default())
    }

    /// 生成恢复码集合
    pub fn generate(&self) -> Result<RecoveryCodeSet> {
        let mut plain_codes = Vec::with_capacity(self.config.code_count);
        let mut seen = HashSet::new();

        // 生成唯一的恢复码
        while plain_codes.len() < self.config.code_count {
            let code = self.generate_single_code()?;
            if seen.insert(code.clone()) {
                plain_codes.push(code);
            }
        }

        // 哈希恢复码
        let hashed_codes = if self.config.hash_codes {
            self.hash_codes(&plain_codes)?
        } else {
            plain_codes.clone()
        };

        Ok(RecoveryCodeSet {
            plain_codes,
            hashed_codes,
            generated_at: chrono::Utc::now().timestamp(),
        })
    }

    /// 验证恢复码
    ///
    /// # 参数
    ///
    /// * `code` - 用户输入的恢复码
    /// * `stored_codes` - 存储的恢复码列表（可能是哈希或明文）
    ///
    /// # 返回
    ///
    /// 如果验证成功，返回匹配的恢复码索引
    pub fn verify(&self, code: &str, stored_codes: &[String]) -> Result<Option<usize>> {
        let normalized = self.normalize_code(code);

        if self.config.hash_codes {
            // 与哈希版本比较
            for (index, hashed) in stored_codes.iter().enumerate() {
                if verify_password(&normalized, hashed)? {
                    return Ok(Some(index));
                }
            }
        } else {
            // 与明文版本比较（常量时间）
            for (index, stored) in stored_codes.iter().enumerate() {
                let stored_normalized = self.normalize_code(stored);
                if constant_time_eq(normalized.as_bytes(), stored_normalized.as_bytes()) {
                    return Ok(Some(index));
                }
            }
        }

        Ok(None)
    }

    /// 验证并消耗恢复码
    ///
    /// 如果验证成功，从列表中移除该恢复码
    ///
    /// # 返回
    ///
    /// 返回 (是否成功, 更新后的恢复码列表)
    pub fn verify_and_consume(
        &self,
        code: &str,
        stored_codes: &[String],
    ) -> Result<(bool, Vec<String>)> {
        match self.verify(code, stored_codes)? {
            Some(index) => {
                let mut remaining = stored_codes.to_vec();
                remaining.remove(index);
                Ok((true, remaining))
            }
            None => Ok((false, stored_codes.to_vec())),
        }
    }

    /// 获取恢复码状态
    pub fn get_status(&self, stored_codes: &[String]) -> RecoveryCodeStatus {
        let remaining = stored_codes.len();
        RecoveryCodeStatus {
            total: self.config.code_count,
            used: self.config.code_count.saturating_sub(remaining),
            remaining,
        }
    }

    /// 重新生成恢复码
    ///
    /// 生成新的恢复码集合，替换旧的
    pub fn regenerate(&self) -> Result<RecoveryCodeSet> {
        self.generate()
    }

    /// 格式化恢复码用于显示
    pub fn format_for_display(&self, codes: &[String]) -> String {
        codes
            .iter()
            .enumerate()
            .map(|(i, code)| format!("{:2}. {}", i + 1, code))
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// 获取配置
    pub fn config(&self) -> &RecoveryConfig {
        &self.config
    }

    // ========================================================================
    // 内部方法
    // ========================================================================

    /// 生成单个恢复码
    fn generate_single_code(&self) -> Result<String> {
        // 使用的字符集（排除易混淆字符: 0, O, I, l, 1）
        const CHARSET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

        let total_chars = self.config.group_length * self.config.group_count;
        let bytes = generate_random_bytes(total_chars)?;

        let mut code = String::with_capacity(total_chars + self.config.group_count - 1);

        for (i, byte) in bytes.iter().enumerate() {
            // 添加分隔符
            if i > 0 && i % self.config.group_length == 0 {
                code.push(self.config.separator);
            }

            let char_index = (*byte as usize) % CHARSET.len();
            code.push(CHARSET[char_index] as char);
        }

        Ok(code)
    }

    /// 哈希恢复码列表
    fn hash_codes(&self, codes: &[String]) -> Result<Vec<String>> {
        codes
            .iter()
            .map(|code| {
                let normalized = self.normalize_code(code);
                hash_password(&normalized)
            })
            .collect()
    }

    /// 规范化恢复码（移除分隔符和空格，转为大写）
    fn normalize_code(&self, code: &str) -> String {
        code.chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>()
            .to_uppercase()
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

/// 便捷函数：生成默认恢复码
pub fn generate_recovery_codes() -> Result<RecoveryCodeSet> {
    RecoveryCodeManager::default_manager().generate()
}

/// 便捷函数：生成指定数量的恢复码
pub fn generate_recovery_codes_with_count(count: usize) -> Result<RecoveryCodeSet> {
    let config = RecoveryConfig::default().with_code_count(count);
    RecoveryCodeManager::new(config).generate()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_config_default() {
        let config = RecoveryConfig::default();
        assert_eq!(config.code_count, 10);
        assert_eq!(config.group_length, 4);
        assert_eq!(config.group_count, 2);
        assert_eq!(config.separator, '-');
        assert!(config.hash_codes);
    }

    #[test]
    fn test_recovery_config_builder() {
        let config = RecoveryConfig::new()
            .with_code_count(8)
            .with_group_length(5)
            .with_group_count(3)
            .with_separator('_')
            .with_hash(false);

        assert_eq!(config.code_count, 8);
        assert_eq!(config.group_length, 5);
        assert_eq!(config.group_count, 3);
        assert_eq!(config.separator, '_');
        assert!(!config.hash_codes);
    }

    #[test]
    fn test_generate_recovery_codes() {
        let manager = RecoveryCodeManager::default_manager();
        let code_set = manager.generate().unwrap();

        assert_eq!(code_set.plain_codes.len(), 10);
        assert_eq!(code_set.hashed_codes.len(), 10);

        // 检查格式
        for code in &code_set.plain_codes {
            assert_eq!(code.len(), 9); // 4 + 1 + 4
            assert!(code.contains('-'));
        }
    }

    #[test]
    fn test_codes_are_unique() {
        let manager = RecoveryCodeManager::default_manager();
        let code_set = manager.generate().unwrap();

        let unique: HashSet<_> = code_set.plain_codes.iter().collect();
        assert_eq!(unique.len(), code_set.plain_codes.len());
    }

    #[test]
    fn test_verify_plain_code() {
        let config = RecoveryConfig::default().with_hash(false);
        let manager = RecoveryCodeManager::new(config);
        let code_set = manager.generate().unwrap();

        // 验证有效的恢复码
        let result = manager
            .verify(&code_set.plain_codes[0], &code_set.hashed_codes)
            .unwrap();
        assert_eq!(result, Some(0));

        // 验证无效的恢复码
        let result = manager
            .verify("INVALID-CODE", &code_set.hashed_codes)
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_verify_hashed_code() {
        let manager = RecoveryCodeManager::default_manager();
        let code_set = manager.generate().unwrap();

        // 验证有效的恢复码
        let result = manager
            .verify(&code_set.plain_codes[0], &code_set.hashed_codes)
            .unwrap();
        assert_eq!(result, Some(0));
    }

    #[test]
    fn test_verify_case_insensitive() {
        let config = RecoveryConfig::default().with_hash(false);
        let manager = RecoveryCodeManager::new(config);
        let code_set = manager.generate().unwrap();

        let lowercase = code_set.plain_codes[0].to_lowercase();
        let result = manager.verify(&lowercase, &code_set.hashed_codes).unwrap();
        assert_eq!(result, Some(0));
    }

    #[test]
    fn test_verify_without_separator() {
        let config = RecoveryConfig::default().with_hash(false);
        let manager = RecoveryCodeManager::new(config);
        let code_set = manager.generate().unwrap();

        let without_sep = code_set.plain_codes[0].replace('-', "");
        let result = manager
            .verify(&without_sep, &code_set.hashed_codes)
            .unwrap();
        assert_eq!(result, Some(0));
    }

    #[test]
    fn test_verify_and_consume() {
        let config = RecoveryConfig::default().with_hash(false);
        let manager = RecoveryCodeManager::new(config);
        let code_set = manager.generate().unwrap();

        let (valid, remaining) = manager
            .verify_and_consume(&code_set.plain_codes[0], &code_set.hashed_codes)
            .unwrap();

        assert!(valid);
        assert_eq!(remaining.len(), 9);

        // 再次使用同一个码应该失败
        let (valid, _) = manager
            .verify_and_consume(&code_set.plain_codes[0], &remaining)
            .unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_get_status() {
        let manager = RecoveryCodeManager::default_manager();
        let code_set = manager.generate().unwrap();

        let status = manager.get_status(&code_set.hashed_codes);
        assert_eq!(status.total, 10);
        assert_eq!(status.used, 0);
        assert_eq!(status.remaining, 10);

        // 模拟使用了一些码
        let partial = code_set.hashed_codes[..7].to_vec();
        let status = manager.get_status(&partial);
        assert_eq!(status.remaining, 7);
        assert_eq!(status.used, 3);
    }

    #[test]
    fn test_format_for_display() {
        let config = RecoveryConfig::default().with_code_count(3);
        let manager = RecoveryCodeManager::new(config);
        let code_set = manager.generate().unwrap();

        let display = manager.format_for_display(&code_set.plain_codes);
        assert!(display.contains(" 1. "));
        assert!(display.contains(" 2. "));
        assert!(display.contains(" 3. "));
    }

    #[test]
    fn test_config_presets() {
        let high_sec = RecoveryConfig::high_security();
        assert_eq!(high_sec.code_count, 16);
        assert_eq!(high_sec.group_length, 5);
        assert_eq!(high_sec.group_count, 3);

        let simple = RecoveryConfig::simple();
        assert_eq!(simple.code_count, 5);
        assert!(!simple.hash_codes);
    }

    #[test]
    fn test_convenience_functions() {
        let code_set = generate_recovery_codes().unwrap();
        assert_eq!(code_set.plain_codes.len(), 10);

        let code_set = generate_recovery_codes_with_count(5).unwrap();
        assert_eq!(code_set.plain_codes.len(), 5);
    }

    #[test]
    fn test_no_confusing_characters() {
        let manager = RecoveryCodeManager::default_manager();
        let code_set = manager.generate().unwrap();

        // 检查不包含易混淆字符
        let confusing = ['0', 'O', 'I', 'l', '1'];
        for code in &code_set.plain_codes {
            for ch in confusing {
                assert!(
                    !code.contains(ch),
                    "Code {} contains confusing character {}",
                    code,
                    ch
                );
            }
        }
    }

    #[test]
    fn test_regenerate() {
        let manager = RecoveryCodeManager::default_manager();
        let code_set1 = manager.generate().unwrap();
        let code_set2 = manager.regenerate().unwrap();

        // 新生成的码应该不同
        assert_ne!(code_set1.plain_codes, code_set2.plain_codes);
    }

    #[test]
    fn test_different_group_configs() {
        // 3组5字符
        let config = RecoveryConfig::default()
            .with_group_length(5)
            .with_group_count(3);
        let manager = RecoveryCodeManager::new(config);
        let code_set = manager.generate().unwrap();

        for code in &code_set.plain_codes {
            // 5 + 1 + 5 + 1 + 5 = 17
            assert_eq!(code.len(), 17);
            assert_eq!(code.matches('-').count(), 2);
        }
    }

    #[test]
    fn test_custom_separator() {
        let config = RecoveryConfig::default().with_separator('_');
        let manager = RecoveryCodeManager::new(config);
        let code_set = manager.generate().unwrap();

        for code in &code_set.plain_codes {
            assert!(code.contains('_'));
            assert!(!code.contains('-'));
        }
    }

    #[test]
    #[should_panic(expected = "code count must be between 1 and 20")]
    fn test_invalid_code_count() {
        RecoveryConfig::default().with_code_count(0);
    }

    #[test]
    #[should_panic(expected = "group length must be between 4 and 8")]
    fn test_invalid_group_length() {
        RecoveryConfig::default().with_group_length(3);
    }

    #[test]
    #[should_panic(expected = "group count must be between 1 and 4")]
    fn test_invalid_group_count() {
        RecoveryConfig::default().with_group_count(5);
    }
}
