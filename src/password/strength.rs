//! 密码强度检查模块
//!
//! 提供密码强度评估和验证功能。

use crate::error::{Error, Result, ValidationError};

/// 密码强度等级
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PasswordStrength {
    /// 非常弱 - 容易被破解
    VeryWeak = 0,
    /// 弱 - 不推荐使用
    Weak = 1,
    /// 一般 - 最低可接受
    Fair = 2,
    /// 强 - 推荐使用
    Strong = 3,
    /// 非常强 - 高度安全
    VeryStrong = 4,
}

impl PasswordStrength {
    /// 获取强度的描述
    pub fn description(&self) -> &'static str {
        match self {
            PasswordStrength::VeryWeak => "Very weak - easily cracked",
            PasswordStrength::Weak => "Weak - not recommended",
            PasswordStrength::Fair => "Fair - minimum acceptable",
            PasswordStrength::Strong => "Strong - recommended",
            PasswordStrength::VeryStrong => "Very strong - highly secure",
        }
    }

    /// 获取强度分数 (0-4)
    pub fn score(&self) -> u8 {
        *self as u8
    }
}

/// 密码强度检查结果
#[derive(Debug, Clone)]
pub struct StrengthResult {
    /// 强度等级
    pub strength: PasswordStrength,
    /// 分数 (0-100)
    pub score: u32,
    /// 改进建议
    pub suggestions: Vec<String>,
    /// 密码满足的特性
    pub features: PasswordFeatures,
}

/// 密码包含的特性
#[derive(Debug, Clone, Default)]
pub struct PasswordFeatures {
    /// 长度
    pub length: usize,
    /// 包含小写字母
    pub has_lowercase: bool,
    /// 包含大写字母
    pub has_uppercase: bool,
    /// 包含数字
    pub has_digit: bool,
    /// 包含特殊字符
    pub has_special: bool,
    /// 包含 Unicode 字符（非 ASCII）
    pub has_unicode: bool,
    /// 不同字符的数量
    pub unique_chars: usize,
    /// 是否包含连续字符 (如 abc, 123)
    pub has_sequences: bool,
    /// 是否包含重复字符 (如 aaa, 111)
    pub has_repeats: bool,
}

/// 密码要求配置
#[derive(Debug, Clone)]
pub struct PasswordRequirements {
    /// 最小长度
    pub min_length: usize,
    /// 最大长度
    pub max_length: usize,
    /// 是否要求小写字母
    pub require_lowercase: bool,
    /// 是否要求大写字母
    pub require_uppercase: bool,
    /// 是否要求数字
    pub require_digit: bool,
    /// 是否要求特殊字符
    pub require_special: bool,
    /// 最低强度要求
    pub min_strength: PasswordStrength,
}

impl Default for PasswordRequirements {
    fn default() -> Self {
        Self {
            min_length: 8,
            max_length: 128,
            require_lowercase: true,
            require_uppercase: false,
            require_digit: true,
            require_special: false,
            min_strength: PasswordStrength::Fair,
        }
    }
}

impl PasswordRequirements {
    /// 创建严格的密码要求
    pub fn strict() -> Self {
        Self {
            min_length: 12,
            max_length: 128,
            require_lowercase: true,
            require_uppercase: true,
            require_digit: true,
            require_special: true,
            min_strength: PasswordStrength::Strong,
        }
    }

    /// 创建宽松的密码要求
    pub fn relaxed() -> Self {
        Self {
            min_length: 6,
            max_length: 256,
            require_lowercase: false,
            require_uppercase: false,
            require_digit: false,
            require_special: false,
            min_strength: PasswordStrength::Weak,
        }
    }

    /// 设置最小长度
    pub fn with_min_length(mut self, length: usize) -> Self {
        self.min_length = length;
        self
    }

    /// 设置最大长度
    pub fn with_max_length(mut self, length: usize) -> Self {
        self.max_length = length;
        self
    }

    /// 设置是否要求大写字母
    pub fn with_uppercase(mut self, required: bool) -> Self {
        self.require_uppercase = required;
        self
    }

    /// 设置是否要求特殊字符
    pub fn with_special(mut self, required: bool) -> Self {
        self.require_special = required;
        self
    }

    /// 设置最低强度要求
    pub fn with_min_strength(mut self, strength: PasswordStrength) -> Self {
        self.min_strength = strength;
        self
    }
}

// ============================================================================
// 常见弱密码列表
// ============================================================================

const COMMON_PASSWORDS: &[&str] = &[
    "password",
    "123456",
    "12345678",
    "qwerty",
    "abc123",
    "password1",
    "password123",
    "admin",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "master",
    "login",
    "princess",
    "starwars",
    "hello",
    "freedom",
    "whatever",
    "trustno1",
    "iloveyou",
    "sunshine",
    "shadow",
    "superman",
    "michael",
    "football",
    "baseball",
    "soccer",
    "hockey",
    "batman",
];

// ============================================================================
// 密码强度分析
// ============================================================================

/// 分析密码的特性
fn analyze_password(password: &str) -> PasswordFeatures {
    let mut features = PasswordFeatures {
        length: password.len(),
        ..Default::default()
    };

    let mut char_set = std::collections::HashSet::new();
    let chars: Vec<char> = password.chars().collect();

    for (i, c) in chars.iter().enumerate() {
        char_set.insert(*c);

        if c.is_lowercase() {
            features.has_lowercase = true;
        }
        if c.is_uppercase() {
            features.has_uppercase = true;
        }
        if c.is_ascii_digit() {
            features.has_digit = true;
        }
        if is_special_char(*c) {
            features.has_special = true;
        }
        if !c.is_ascii() {
            features.has_unicode = true;
        }

        // 检查重复字符
        if i >= 2 && chars[i] == chars[i - 1] && chars[i] == chars[i - 2] {
            features.has_repeats = true;
        }

        // 检查连续字符
        if i >= 2 {
            let c0 = chars[i - 2] as i32;
            let c1 = chars[i - 1] as i32;
            let c2 = chars[i] as i32;
            if (c1 - c0 == 1 && c2 - c1 == 1) || (c0 - c1 == 1 && c1 - c2 == 1) {
                features.has_sequences = true;
            }
        }
    }

    features.unique_chars = char_set.len();
    features
}

/// 检查字符是否为特殊字符
fn is_special_char(c: char) -> bool {
    c.is_ascii_punctuation() || (c.is_ascii() && !c.is_alphanumeric() && !c.is_whitespace())
}

/// 计算密码强度分数
fn calculate_score(password: &str, features: &PasswordFeatures) -> u32 {
    let mut score: i32 = 0;

    // 基于长度加分
    score += (features.length as i32).min(20) * 4;

    // 基于字符类型加分
    if features.has_lowercase {
        score += 10;
    }
    if features.has_uppercase {
        score += 15;
    }
    if features.has_digit {
        score += 10;
    }
    if features.has_special {
        score += 20;
    }
    if features.has_unicode {
        score += 15;
    }

    // 基于唯一字符加分
    let unique_ratio = features.unique_chars as f64 / features.length.max(1) as f64;
    score += (unique_ratio * 20.0) as i32;

    // 扣分项
    if features.has_sequences {
        score -= 15;
    }
    if features.has_repeats {
        score -= 15;
    }

    // 检查是否为常见密码
    let lower = password.to_lowercase();
    if COMMON_PASSWORDS.iter().any(|p| lower.contains(p)) {
        score -= 30;
    }

    // 确保分数在 0-100 范围内
    score.clamp(0, 100) as u32
}

/// 根据分数确定强度等级
fn score_to_strength(score: u32) -> PasswordStrength {
    match score {
        0..=19 => PasswordStrength::VeryWeak,
        20..=39 => PasswordStrength::Weak,
        40..=59 => PasswordStrength::Fair,
        60..=79 => PasswordStrength::Strong,
        _ => PasswordStrength::VeryStrong,
    }
}

/// 生成改进建议
fn generate_suggestions(features: &PasswordFeatures) -> Vec<String> {
    let mut suggestions = Vec::new();

    if features.length < 12 {
        suggestions.push("Consider using a longer password (at least 12 characters)".to_string());
    }

    if !features.has_lowercase {
        suggestions.push("Add lowercase letters".to_string());
    }

    if !features.has_uppercase {
        suggestions.push("Add uppercase letters".to_string());
    }

    if !features.has_digit {
        suggestions.push("Add numbers".to_string());
    }

    if !features.has_special {
        suggestions.push("Add special characters (e.g., !@#$%^&*)".to_string());
    }

    if features.has_sequences {
        suggestions.push("Avoid sequential characters (e.g., abc, 123)".to_string());
    }

    if features.has_repeats {
        suggestions.push("Avoid repeated characters (e.g., aaa, 111)".to_string());
    }

    if features.unique_chars < features.length / 2 {
        suggestions.push("Use more unique characters".to_string());
    }

    suggestions
}

// ============================================================================
// 公共 API
// ============================================================================

/// 检查密码强度
///
/// 返回详细的强度分析结果，包括分数、等级和改进建议。
///
/// # Arguments
///
/// * `password` - 要检查的密码
///
/// # Returns
///
/// 返回 `StrengthResult` 包含完整的分析结果
///
/// # Example
///
/// ```rust
/// use authrs::password::check_password_strength;
///
/// let result = check_password_strength("MyP@ssw0rd!");
/// println!("Strength: {:?}", result.strength);
/// println!("Score: {}", result.score);
/// ```
pub fn check_password_strength(password: &str) -> StrengthResult {
    let features = analyze_password(password);
    let score = calculate_score(password, &features);
    let strength = score_to_strength(score);
    let suggestions = generate_suggestions(&features);

    StrengthResult {
        strength,
        score,
        suggestions,
        features,
    }
}

/// 使用默认要求验证密码强度
///
/// # Arguments
///
/// * `password` - 要验证的密码
///
/// # Returns
///
/// 如果密码满足默认要求返回 `Ok(())`，否则返回错误
///
/// # Example
///
/// ```rust
/// use authrs::password::validate_password_strength;
///
/// // 弱密码会返回错误
/// assert!(validate_password_strength("weak").is_err());
///
/// // 强密码会通过验证
/// assert!(validate_password_strength("Str0ng_P@ss!").is_ok());
/// ```
pub fn validate_password_strength(password: &str) -> Result<()> {
    validate_password_with_requirements(password, &PasswordRequirements::default())
}

/// 使用自定义要求验证密码
///
/// # Arguments
///
/// * `password` - 要验证的密码
/// * `requirements` - 密码要求配置
///
/// # Returns
///
/// 如果密码满足要求返回 `Ok(())`，否则返回错误
///
/// # Example
///
/// ```rust
/// use authrs::password::{validate_password_with_requirements, PasswordRequirements};
///
/// let requirements = PasswordRequirements::strict();
/// let result = validate_password_with_requirements("MyStr0ng!Pass", &requirements);
/// ```
pub fn validate_password_with_requirements(
    password: &str,
    requirements: &PasswordRequirements,
) -> Result<()> {
    let len = password.chars().count();

    // 检查长度
    if len < requirements.min_length {
        return Err(Error::Validation(ValidationError::PasswordTooShort {
            min_length: requirements.min_length,
            actual: len,
        }));
    }

    if len > requirements.max_length {
        return Err(Error::Validation(ValidationError::PasswordTooLong {
            max_length: requirements.max_length,
            actual: len,
        }));
    }

    let features = analyze_password(password);

    // 检查字符要求
    if requirements.require_lowercase && !features.has_lowercase {
        return Err(Error::Validation(ValidationError::PasswordTooWeak(
            "must contain at least one lowercase letter".to_string(),
        )));
    }

    if requirements.require_uppercase && !features.has_uppercase {
        return Err(Error::Validation(ValidationError::PasswordTooWeak(
            "must contain at least one uppercase letter".to_string(),
        )));
    }

    if requirements.require_digit && !features.has_digit {
        return Err(Error::Validation(ValidationError::PasswordTooWeak(
            "must contain at least one digit".to_string(),
        )));
    }

    if requirements.require_special && !features.has_special {
        return Err(Error::Validation(ValidationError::PasswordTooWeak(
            "must contain at least one special character".to_string(),
        )));
    }

    // 检查强度
    let result = check_password_strength(password);
    if result.strength < requirements.min_strength {
        let msg = format!(
            "password strength is {:?}, minimum required is {:?}",
            result.strength, requirements.min_strength
        );
        return Err(Error::Validation(ValidationError::PasswordTooWeak(msg)));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_password_basic() {
        let features = analyze_password("Test123!");

        assert!(features.has_lowercase);
        assert!(features.has_uppercase);
        assert!(features.has_digit);
        assert!(features.has_special);
        assert!(!features.has_unicode);
        assert_eq!(features.length, 8);
    }

    #[test]
    fn test_analyze_password_unicode() {
        let features = analyze_password("密码Password123");

        assert!(features.has_unicode);
        assert!(features.has_lowercase);
        assert!(features.has_uppercase);
        assert!(features.has_digit);
    }

    #[test]
    fn test_analyze_password_sequences() {
        let features = analyze_password("abc123xyz");
        assert!(features.has_sequences);

        let features = analyze_password("aZx9Ky");
        assert!(!features.has_sequences);
    }

    #[test]
    fn test_analyze_password_repeats() {
        let features = analyze_password("aaabbb111");
        assert!(features.has_repeats);

        let features = analyze_password("abab1212");
        assert!(!features.has_repeats);
    }

    #[test]
    fn test_password_strength_very_weak() {
        let result = check_password_strength("123");
        // "123" 得分较低，应该是 VeryWeak 或 Weak
        assert!(result.strength <= PasswordStrength::Weak);
    }

    #[test]
    fn test_password_strength_weak() {
        let result = check_password_strength("password");
        assert!(result.strength <= PasswordStrength::Weak);
    }

    #[test]
    fn test_password_strength_strong() {
        let result = check_password_strength("MyStr0ng!P@ssword");
        assert!(result.strength >= PasswordStrength::Strong);
    }

    #[test]
    fn test_password_strength_common_password_penalty() {
        let result1 = check_password_strength("password123");
        let result2 = check_password_strength("xkT9zQ2mNv");

        // 包含常见密码的应该有更低的分数
        assert!(result1.score < result2.score);
    }

    #[test]
    fn test_validate_password_strength_default() {
        // 太短
        assert!(validate_password_strength("Ab1!").is_err());

        // 缺少数字
        assert!(validate_password_strength("abcdefgh").is_err());

        // 满足要求
        assert!(validate_password_strength("Abcdef1!").is_ok());
    }

    #[test]
    fn test_validate_password_strict_requirements() {
        let requirements = PasswordRequirements::strict();

        // 缺少特殊字符
        assert!(validate_password_with_requirements("Abcdefgh1234", &requirements).is_err());

        // 满足所有要求
        assert!(validate_password_with_requirements("Abcdefgh123!", &requirements).is_ok());
    }

    #[test]
    fn test_validate_password_relaxed_requirements() {
        let requirements = PasswordRequirements::relaxed();

        // 宽松要求下，只要满足最低长度即可
        assert!(validate_password_with_requirements("abcdef", &requirements).is_ok());
    }

    #[test]
    fn test_password_too_long() {
        let requirements = PasswordRequirements::default().with_max_length(10);
        let result =
            validate_password_with_requirements("ThisIsAVeryLongPassword123!", &requirements);

        assert!(result.is_err());
        if let Err(Error::Validation(ValidationError::PasswordTooLong { max_length, .. })) = result
        {
            assert_eq!(max_length, 10);
        } else {
            panic!("Expected PasswordTooLong error");
        }
    }

    #[test]
    fn test_suggestions_generation() {
        let result = check_password_strength("abc");

        assert!(!result.suggestions.is_empty());
        assert!(result.suggestions.iter().any(|s| s.contains("longer")));
        assert!(result.suggestions.iter().any(|s| s.contains("uppercase")));
        assert!(result.suggestions.iter().any(|s| s.contains("numbers")));
        assert!(result.suggestions.iter().any(|s| s.contains("special")));
    }

    #[test]
    fn test_strength_ordering() {
        assert!(PasswordStrength::VeryWeak < PasswordStrength::Weak);
        assert!(PasswordStrength::Weak < PasswordStrength::Fair);
        assert!(PasswordStrength::Fair < PasswordStrength::Strong);
        assert!(PasswordStrength::Strong < PasswordStrength::VeryStrong);
    }

    #[test]
    fn test_strength_score() {
        assert_eq!(PasswordStrength::VeryWeak.score(), 0);
        assert_eq!(PasswordStrength::Weak.score(), 1);
        assert_eq!(PasswordStrength::Fair.score(), 2);
        assert_eq!(PasswordStrength::Strong.score(), 3);
        assert_eq!(PasswordStrength::VeryStrong.score(), 4);
    }

    #[test]
    fn test_strength_description() {
        assert!(!PasswordStrength::VeryWeak.description().is_empty());
        assert!(!PasswordStrength::Strong.description().is_empty());
    }

    #[test]
    fn test_is_special_char() {
        assert!(is_special_char('!'));
        assert!(is_special_char('@'));
        assert!(is_special_char('#'));
        assert!(is_special_char('$'));
        assert!(!is_special_char('a'));
        assert!(!is_special_char('1'));
        assert!(!is_special_char(' '));
    }

    #[test]
    fn test_empty_password() {
        let result = check_password_strength("");
        assert_eq!(result.strength, PasswordStrength::VeryWeak);
        assert_eq!(result.score, 0);
    }

    #[test]
    fn test_requirements_builder() {
        let req = PasswordRequirements::default()
            .with_min_length(10)
            .with_max_length(50)
            .with_uppercase(true)
            .with_special(true)
            .with_min_strength(PasswordStrength::Strong);

        assert_eq!(req.min_length, 10);
        assert_eq!(req.max_length, 50);
        assert!(req.require_uppercase);
        assert!(req.require_special);
        assert_eq!(req.min_strength, PasswordStrength::Strong);
    }
}
