//! 密码学模块集成测试
//!
//! 测试 HKDF 密钥派生函数的各种使用场景。

use authrs::crypto::kdf::{
    Hkdf, HkdfAlgorithm, derive_key_from_password, derive_subkeys, hkdf_sha256, hkdf_sha512,
};

/// 测试基本的 HKDF-SHA256 密钥派生
#[test]
fn test_hkdf_sha256_basic_derivation() {
    let secret = b"my-secret-key";
    let salt = b"random-salt-value";
    let info = b"application-context";

    let key = hkdf_sha256(secret, Some(salt), info, 32).unwrap();
    assert_eq!(key.len(), 32);

    // 相同输入应产生相同输出
    let key2 = hkdf_sha256(secret, Some(salt), info, 32).unwrap();
    assert_eq!(key, key2);
}

/// 测试基本的 HKDF-SHA512 密钥派生
#[test]
fn test_hkdf_sha512_basic_derivation() {
    let secret = b"my-secret-key";
    let salt = b"random-salt-value";
    let info = b"application-context";

    let key = hkdf_sha512(secret, Some(salt), info, 64).unwrap();
    assert_eq!(key.len(), 64);
}

/// 测试 Hkdf 构建器 API
#[test]
fn test_hkdf_builder_api() {
    let hkdf = Hkdf::new(HkdfAlgorithm::Sha256)
        .with_salt(b"my-salt")
        .with_info(b"my-context");

    let key = hkdf.derive(b"secret-material", 32).unwrap();
    assert_eq!(key.len(), 32);

    // 验证与直接函数调用结果一致
    let direct_key = hkdf_sha256(b"secret-material", Some(b"my-salt"), b"my-context", 32).unwrap();
    assert_eq!(key, direct_key);
}

/// 测试不同的 info 产生不同的密钥（域分离）
#[test]
fn test_domain_separation_with_different_info() {
    let secret = b"master-key";
    let salt = b"shared-salt";

    let key_encryption = hkdf_sha256(secret, Some(salt), b"encryption", 32).unwrap();
    let key_signing = hkdf_sha256(secret, Some(salt), b"signing", 32).unwrap();
    let key_auth = hkdf_sha256(secret, Some(salt), b"authentication", 32).unwrap();

    // 所有密钥应该不同
    assert_ne!(key_encryption, key_signing);
    assert_ne!(key_signing, key_auth);
    assert_ne!(key_encryption, key_auth);
}

/// 测试不同的盐产生不同的密钥
#[test]
fn test_different_salt_produces_different_keys() {
    let secret = b"shared-secret";
    let info = b"same-context";

    let key1 = hkdf_sha256(secret, Some(b"salt-one"), info, 32).unwrap();
    let key2 = hkdf_sha256(secret, Some(b"salt-two"), info, 32).unwrap();

    assert_ne!(key1, key2);
}

/// 测试无盐值的情况
#[test]
fn test_hkdf_without_salt() {
    let secret = b"my-secret";
    let info = b"context";

    let key = hkdf_sha256(secret, None, info, 32).unwrap();
    assert_eq!(key.len(), 32);

    // 无盐值应该产生确定性结果
    let key2 = hkdf_sha256(secret, None, info, 32).unwrap();
    assert_eq!(key, key2);
}

/// 测试空 info 的情况
#[test]
fn test_hkdf_with_empty_info() {
    let secret = b"my-secret";
    let salt = b"my-salt";

    let key = hkdf_sha256(secret, Some(salt), &[], 32).unwrap();
    assert_eq!(key.len(), 32);
}

/// 测试不同输出长度
#[test]
fn test_various_output_lengths() {
    let secret = b"secret";
    let salt = b"salt";
    let info = b"info";

    for len in [16, 24, 32, 48, 64, 128, 256] {
        let key = hkdf_sha256(secret, Some(salt), info, len).unwrap();
        assert_eq!(key.len(), len, "Failed for length {}", len);
    }
}

/// 测试从密码派生密钥
#[test]
fn test_derive_key_from_password() {
    let password = "my-secure-password-123!";
    let salt = b"per-user-unique-salt";

    let key = derive_key_from_password(password, salt, "file-encryption", 32).unwrap();
    assert_eq!(key.len(), 32);

    // 相同输入应产生相同密钥
    let key2 = derive_key_from_password(password, salt, "file-encryption", 32).unwrap();
    assert_eq!(key, key2);

    // 不同密码应产生不同密钥
    let key3 = derive_key_from_password("different-password", salt, "file-encryption", 32).unwrap();
    assert_ne!(key, key3);

    // 不同上下文应产生不同密钥
    let key4 = derive_key_from_password(password, salt, "message-signing", 32).unwrap();
    assert_ne!(key, key4);
}

/// 测试密码派生需要足够长的盐
#[test]
fn test_derive_key_from_password_requires_sufficient_salt() {
    let password = "password";
    let short_salt = b"short"; // 只有 5 字节

    let result = derive_key_from_password(password, short_salt, "context", 32);
    assert!(result.is_err(), "Should reject salt shorter than 8 bytes");

    // 8 字节盐应该可以
    let ok_salt = b"12345678";
    let result = derive_key_from_password(password, ok_salt, "context", 32);
    assert!(result.is_ok());
}

/// 测试批量派生子密钥
#[test]
fn test_derive_subkeys() {
    let master_key = b"master-secret-key";
    let labels = &["encryption", "signing", "authentication", "session"];

    let keys = derive_subkeys(master_key, Some(b"app-salt"), labels, 32).unwrap();

    assert_eq!(keys.len(), 4);

    // 每个密钥长度正确
    for key in &keys {
        assert_eq!(key.len(), 32);
    }

    // 所有密钥都不同
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(keys[i], keys[j], "Keys {} and {} should be different", i, j);
        }
    }
}

/// 测试子密钥派生的确定性
#[test]
fn test_derive_subkeys_deterministic() {
    let master_key = b"master-key";
    let labels = &["key1", "key2"];

    let keys1 = derive_subkeys(master_key, Some(b"salt"), labels, 32).unwrap();
    let keys2 = derive_subkeys(master_key, Some(b"salt"), labels, 32).unwrap();

    assert_eq!(keys1, keys2);
}

/// 测试 SHA-512 可以生成更长的密钥
#[test]
fn test_sha512_longer_keys() {
    let secret = b"secret";

    // SHA-256 最大输出: 255 * 32 = 8160 字节
    // SHA-512 最大输出: 255 * 64 = 16320 字节
    let key = hkdf_sha512(secret, None, &[], 10000).unwrap();
    assert_eq!(key.len(), 10000);
}

/// 测试输出长度限制
#[test]
fn test_output_length_limits() {
    let secret = b"secret";

    // 零长度应该失败
    assert!(hkdf_sha256(secret, None, &[], 0).is_err());

    // 超过最大长度应该失败
    let max_sha256 = 255 * 32;
    assert!(hkdf_sha256(secret, None, &[], max_sha256 + 1).is_err());

    // 最大长度应该成功
    let key = hkdf_sha256(secret, None, &[], max_sha256).unwrap();
    assert_eq!(key.len(), max_sha256);
}

/// 测试 HkdfAlgorithm 属性
#[test]
fn test_algorithm_properties() {
    assert_eq!(HkdfAlgorithm::Sha256.hash_length(), 32);
    assert_eq!(HkdfAlgorithm::Sha512.hash_length(), 64);

    assert_eq!(HkdfAlgorithm::Sha256.max_output_length(), 255 * 32);
    assert_eq!(HkdfAlgorithm::Sha512.max_output_length(), 255 * 64);
}

/// 测试默认算法是 SHA-256
#[test]
fn test_default_algorithm() {
    let hkdf = Hkdf::default();
    assert_eq!(hkdf.algorithm(), HkdfAlgorithm::Sha256);
}

/// 测试克隆 Hkdf 配置
#[test]
fn test_hkdf_clone_for_multiple_derivations() {
    let base_hkdf = Hkdf::default().with_salt(b"shared-salt");

    let encryption_key = base_hkdf
        .clone()
        .with_info(b"encryption")
        .derive(b"master", 32)
        .unwrap();

    let signing_key = base_hkdf
        .clone()
        .with_info(b"signing")
        .derive(b"master", 32)
        .unwrap();

    let auth_key = base_hkdf
        .with_info(b"authentication")
        .derive(b"master", 32)
        .unwrap();

    // 所有密钥应该不同
    assert_ne!(encryption_key, signing_key);
    assert_ne!(signing_key, auth_key);
    assert_ne!(encryption_key, auth_key);
}

/// 实际应用场景：派生加密和 MAC 密钥
#[test]
fn test_real_world_scenario_derive_crypto_keys() {
    // 模拟用户密码派生
    let user_password = "user-secure-password-2024!";
    let user_salt = b"unique-salt-for-user-alice";

    // 派生主密钥
    let master_key =
        derive_key_from_password(user_password, user_salt, "master-key-v1", 32).unwrap();

    // 从主密钥派生多个专用密钥
    let labels = &["aes-encryption", "hmac-authentication", "key-wrapping"];
    let keys = derive_subkeys(&master_key, Some(b"subkey-salt"), labels, 32).unwrap();

    let aes_key = &keys[0];
    let hmac_key = &keys[1];
    let wrap_key = &keys[2];

    // 验证所有密钥都是 32 字节
    assert_eq!(aes_key.len(), 32);
    assert_eq!(hmac_key.len(), 32);
    assert_eq!(wrap_key.len(), 32);

    // 验证密钥是确定性的
    let master_key2 =
        derive_key_from_password(user_password, user_salt, "master-key-v1", 32).unwrap();
    let keys2 = derive_subkeys(&master_key2, Some(b"subkey-salt"), labels, 32).unwrap();

    assert_eq!(keys, keys2);
}

/// 测试使用 UTF-8 字符串作为输入
#[test]
fn test_utf8_string_inputs() {
    let secret = "我的密钥";
    let salt = "随机盐值";
    let info = "应用上下文";

    let key = hkdf_sha256(
        secret.as_bytes(),
        Some(salt.as_bytes()),
        info.as_bytes(),
        32,
    )
    .unwrap();
    assert_eq!(key.len(), 32);

    // 应该是确定性的
    let key2 = hkdf_sha256(
        secret.as_bytes(),
        Some(salt.as_bytes()),
        info.as_bytes(),
        32,
    )
    .unwrap();
    assert_eq!(key, key2);
}
