//! 安全随机数生成模块
//!
//! 提供密码学安全的随机数生成功能，用于生成 token、密钥等敏感数据。

use rand::{Rng, TryRngCore, distr::Alphanumeric, rngs::OsRng};

use crate::error::{CryptoError, Error, Result};

/// 生成指定长度的随机字节数组
///
/// 使用操作系统提供的密码学安全随机数生成器 (CSPRNG)
///
/// # Arguments
///
/// * `length` - 要生成的字节数
///
/// # Returns
///
/// 返回包含随机字节的 `Vec<u8>`
///
/// # Example
///
/// ```rust
/// use authrs::random::generate_random_bytes;
///
/// let bytes = generate_random_bytes(32).unwrap();
/// assert_eq!(bytes.len(), 32);
/// ```
pub fn generate_random_bytes(length: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; length];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| Error::Crypto(CryptoError::RngFailed(format!("{:?}", e))))?;
    Ok(bytes)
}

/// 生成指定长度的十六进制随机字符串
///
/// # Arguments
///
/// * `byte_length` - 要生成的字节数（最终字符串长度为字节数的两倍）
///
/// # Returns
///
/// 返回十六进制编码的随机字符串
///
/// # Example
///
/// ```rust
/// use authrs::random::generate_random_hex;
///
/// let hex = generate_random_hex(16).unwrap();
/// assert_eq!(hex.len(), 32); // 16 bytes = 32 hex chars
/// ```
pub fn generate_random_hex(byte_length: usize) -> Result<String> {
    let bytes = generate_random_bytes(byte_length)?;
    Ok(hex_encode(&bytes))
}

/// 生成指定长度的 Base64 URL 安全随机字符串
///
/// 使用 URL 安全的 Base64 编码（不含填充）
///
/// # Arguments
///
/// * `byte_length` - 要生成的字节数
///
/// # Returns
///
/// 返回 Base64 URL 安全编码的随机字符串
///
/// # Example
///
/// ```rust
/// use authrs::random::generate_random_base64_url;
///
/// let token = generate_random_base64_url(32).unwrap();
/// // URL 安全，可直接用于 URL 参数
/// assert!(!token.contains('+'));
/// assert!(!token.contains('/'));
/// ```
pub fn generate_random_base64_url(byte_length: usize) -> Result<String> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let bytes = generate_random_bytes(byte_length)?;
    Ok(URL_SAFE_NO_PAD.encode(&bytes))
}

/// 生成指定长度的字母数字随机字符串
///
/// 只包含 a-z, A-Z, 0-9 字符
///
/// # Arguments
///
/// * `length` - 要生成的字符数
///
/// # Returns
///
/// 返回只包含字母和数字的随机字符串
///
/// # Example
///
/// ```rust
/// use authrs::random::generate_random_alphanumeric;
///
/// let token = generate_random_alphanumeric(24).unwrap();
/// assert_eq!(token.len(), 24);
/// assert!(token.chars().all(|c| c.is_alphanumeric()));
/// ```
pub fn generate_random_alphanumeric(length: usize) -> Result<String> {
    let token: String = rand::rng()
        .sample_iter(Alphanumeric)
        .take(length)
        .map(char::from)
        .collect();
    Ok(token)
}

/// 生成安全的 session token
///
/// 使用 32 字节（256 位）的随机数据，提供足够的熵
///
/// # Returns
///
/// 返回 Base64 URL 安全编码的 session token
///
/// # Example
///
/// ```rust
/// use authrs::random::generate_session_token;
///
/// let token = generate_session_token().unwrap();
/// // 适合用作 session ID
/// ```
pub fn generate_session_token() -> Result<String> {
    generate_random_base64_url(32)
}

/// 生成安全的 API key
///
/// 格式：`prefix_随机字符串`
///
/// # Arguments
///
/// * `prefix` - API key 前缀，用于标识 key 类型
///
/// # Returns
///
/// 返回带前缀的 API key
///
/// # Example
///
/// ```rust
/// use authrs::random::generate_api_key;
///
/// let key = generate_api_key("sk").unwrap();
/// assert!(key.starts_with("sk_"));
/// ```
pub fn generate_api_key(prefix: &str) -> Result<String> {
    let random_part = generate_random_alphanumeric(32)?;
    Ok(format!("{}_{}", prefix, random_part))
}

/// 生成用于密码重置的 token
///
/// 使用 32 字节随机数据，返回十六进制字符串
///
/// # Returns
///
/// 返回 64 字符的十六进制 token
///
/// # Example
///
/// ```rust
/// use authrs::random::generate_reset_token;
///
/// let token = generate_reset_token().unwrap();
/// assert_eq!(token.len(), 64);
/// ```
pub fn generate_reset_token() -> Result<String> {
    generate_random_hex(32)
}

/// 生成 MFA 恢复码
///
/// 生成一组人类可读的恢复码，格式如 `XXXX-XXXX`
///
/// # Arguments
///
/// * `count` - 要生成的恢复码数量
///
/// # Returns
///
/// 返回恢复码列表
///
/// # Example
///
/// ```rust
/// use authrs::random::generate_recovery_codes;
///
/// let codes = generate_recovery_codes(10).unwrap();
/// assert_eq!(codes.len(), 10);
/// // 每个码格式为 XXXX-XXXX
/// for code in &codes {
///     assert_eq!(code.len(), 9);
///     assert_eq!(&code[4..5], "-");
/// }
/// ```
pub fn generate_recovery_codes(count: usize) -> Result<Vec<String>> {
    let mut codes = Vec::with_capacity(count);

    // 使用的字符集（排除容易混淆的字符如 0, O, I, l）
    const CHARSET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

    for _ in 0..count {
        let mut code = String::with_capacity(9);

        for i in 0..8 {
            if i == 4 {
                code.push('-');
            }
            let idx = rand::rng().random_range(0..CHARSET.len());
            code.push(CHARSET[idx] as char);
        }

        codes.push(code);
    }

    Ok(codes)
}

/// 生成 CSRF token
///
/// # Returns
///
/// 返回用于 CSRF 防护的 token
///
/// # Example
///
/// ```rust
/// use authrs::random::generate_csrf_token;
///
/// let token = generate_csrf_token().unwrap();
/// ```
pub fn generate_csrf_token() -> Result<String> {
    generate_random_base64_url(32)
}

/// 生成随机的 u64 数值
///
/// # Returns
///
/// 返回密码学安全的随机 u64
pub fn generate_random_u64() -> u64 {
    rand::rng().random()
}

/// 生成指定范围内的随机数
///
/// # Arguments
///
/// * `min` - 最小值（包含）
/// * `max` - 最大值（不包含）
///
/// # Returns
///
/// 返回 [min, max) 范围内的随机数
pub fn generate_random_in_range(min: u64, max: u64) -> u64 {
    rand::rng().random_range(min..max)
}

// ============================================================================
// 辅助函数
// ============================================================================

/// 将字节数组编码为十六进制字符串
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// 常量时间比较两个字节切片
///
/// 用于防止时序攻击
///
/// # Arguments
///
/// * `a` - 第一个字节切片
/// * `b` - 第二个字节切片
///
/// # Returns
///
/// 如果两个切片相等返回 true
///
/// # Example
///
/// ```rust
/// use authrs::random::constant_time_compare;
///
/// let a = b"secret_token";
/// let b = b"secret_token";
/// assert!(constant_time_compare(a, b));
///
/// let c = b"other_token!";
/// assert!(!constant_time_compare(a, c));
/// ```
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

/// 常量时间比较两个字符串
///
/// # Arguments
///
/// * `a` - 第一个字符串
/// * `b` - 第二个字符串
///
/// # Returns
///
/// 如果两个字符串相等返回 true
pub fn constant_time_compare_str(a: &str, b: &str) -> bool {
    constant_time_compare(a.as_bytes(), b.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_generate_random_bytes() {
        let bytes = generate_random_bytes(32).unwrap();
        assert_eq!(bytes.len(), 32);

        // 确保生成的是随机的（两次生成不应相同）
        let bytes2 = generate_random_bytes(32).unwrap();
        assert_ne!(bytes, bytes2);
    }

    #[test]
    fn test_generate_random_hex() {
        let hex = generate_random_hex(16).unwrap();
        assert_eq!(hex.len(), 32);

        // 确保只包含十六进制字符
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_random_base64_url() {
        let token = generate_random_base64_url(32).unwrap();

        // URL 安全的 base64 不应包含 + 或 /
        assert!(!token.contains('+'));
        assert!(!token.contains('/'));
        assert!(!token.contains('='));
    }

    #[test]
    fn test_generate_random_alphanumeric() {
        let token = generate_random_alphanumeric(24).unwrap();
        assert_eq!(token.len(), 24);
        assert!(token.chars().all(|c| c.is_alphanumeric()));
    }

    #[test]
    fn test_generate_session_token() {
        let token = generate_session_token().unwrap();
        assert!(!token.is_empty());
    }

    #[test]
    fn test_generate_api_key() {
        let key = generate_api_key("sk").unwrap();
        assert!(key.starts_with("sk_"));
        assert_eq!(key.len(), 3 + 32); // "sk_" + 32 chars
    }

    #[test]
    fn test_generate_reset_token() {
        let token = generate_reset_token().unwrap();
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_recovery_codes() {
        let codes = generate_recovery_codes(10).unwrap();
        assert_eq!(codes.len(), 10);

        // 检查格式
        for code in &codes {
            assert_eq!(code.len(), 9);
            assert_eq!(&code[4..5], "-");
        }

        // 确保所有码都是唯一的
        let unique: HashSet<_> = codes.iter().collect();
        assert_eq!(unique.len(), 10);
    }

    #[test]
    fn test_generate_csrf_token() {
        let token = generate_csrf_token().unwrap();
        assert!(!token.is_empty());
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare(b"hello", b"hello"));
        assert!(!constant_time_compare(b"hello", b"world"));
        assert!(!constant_time_compare(b"hello", b"hell"));
    }

    #[test]
    fn test_constant_time_compare_str() {
        assert!(constant_time_compare_str("secret", "secret"));
        assert!(!constant_time_compare_str("secret", "Secret"));
    }

    #[test]
    fn test_generate_random_u64() {
        let a = generate_random_u64();
        let b = generate_random_u64();
        // 极小概率相等
        assert_ne!(a, b);
    }

    #[test]
    fn test_generate_random_in_range() {
        for _ in 0..100 {
            let val = generate_random_in_range(10, 20);
            assert!(val >= 10 && val < 20);
        }
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0x10]), "00ff10");
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }
}
