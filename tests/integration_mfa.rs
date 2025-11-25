//! 集成测试：多因素认证 (MFA)
//!
//! 测试 TOTP/HOTP 生成验证和恢复码流程。

use authrs::mfa::hotp::{HotpConfig, HotpGenerator};
use authrs::mfa::recovery::{RecoveryCodeManager, RecoveryConfig};
use authrs::mfa::totp::{TotpConfig, TotpManager, TotpSecret};

/// 测试 TOTP 基本流程
#[test]
fn test_totp_basic_flow() {
    let config = TotpConfig::default();
    let manager = TotpManager::new(config);

    // 1. 为用户生成密钥
    let secret = manager
        .generate_secret()
        .expect("Secret generation should succeed");

    assert!(!secret.base32.is_empty(), "Secret should not be empty");

    // 2. 生成当前 TOTP 码
    let code = manager
        .generate_code(&secret)
        .expect("Code generation should succeed");

    // TOTP 码应该是 6 位数字
    assert_eq!(code.len(), 6, "TOTP code should be 6 digits");
    assert!(
        code.chars().all(|c| c.is_ascii_digit()),
        "TOTP code should only contain digits"
    );

    // 3. 验证生成的码
    let is_valid = manager
        .verify(&secret, &code)
        .expect("Verification should work");
    assert!(is_valid, "Generated code should be valid");

    // 4. 错误码应该验证失败
    let wrong_code = "000000";
    let is_wrong_valid = manager
        .verify(&secret, wrong_code)
        .expect("Verification should work");
    // 注意：有极小概率 000000 恰好是当前有效码
    // 但在实际测试中这种情况非常罕见
    if code != wrong_code {
        assert!(!is_wrong_valid, "Wrong code should fail verification");
    }
}

/// 测试 TOTP URI 生成（用于 QR 码）
#[test]
fn test_totp_uri_generation() {
    let config = TotpConfig::default().with_issuer("MyApp");
    let manager = TotpManager::new(config);

    let secret = manager.generate_secret().unwrap();

    // 生成 otpauth URI
    let uri = manager.generate_uri(&secret, "alice@example.com");

    assert!(
        uri.starts_with("otpauth://totp/"),
        "URI should start with otpauth://totp/"
    );
    assert!(
        uri.contains("secret="),
        "URI should contain secret parameter"
    );
    assert!(uri.contains("issuer=MyApp"), "URI should contain issuer");
}

/// 测试 TOTP 配置选项
#[test]
fn test_totp_configuration() {
    // 使用自定义配置
    let config = TotpConfig::new()
        .with_digits(8) // 8 位码
        .with_time_step(60) // 60 秒周期
        .with_skew(2); // 允许前后 2 个周期

    let manager = TotpManager::new(config);
    let secret = manager.generate_secret().unwrap();

    // 生成的码应该是 8 位
    let code = manager.generate_code(&secret).unwrap();
    assert_eq!(code.len(), 8, "Code should be 8 digits with custom config");

    // 验证应该工作
    let is_valid = manager.verify(&secret, &code).unwrap();
    assert!(is_valid, "Code should be valid with custom config");
}

/// 测试 TOTP 时间窗口（skew）
#[test]
fn test_totp_time_window() {
    let config = TotpConfig::new().with_time_step(30).with_skew(1); // 允许前后 1 个周期

    let manager = TotpManager::new(config);
    let secret = manager.generate_secret().unwrap();

    // 生成当前码
    let code = manager.generate_code(&secret).unwrap();

    // 验证当前码（应该在时间窗口内）
    let is_valid = manager.verify(&secret, &code).unwrap();
    assert!(is_valid, "Current code should be valid within time window");
}

/// 测试 HOTP 基本流程
#[test]
fn test_hotp_basic_flow() {
    let config = HotpConfig::default();
    let generator = HotpGenerator::new(config);

    // 生成密钥
    let secret = generator
        .generate_secret()
        .expect("Secret generation should succeed");

    // 使用计数器 0 生成码
    let code_0 = generator
        .generate(&secret, 0)
        .expect("Code generation should succeed");

    assert_eq!(code_0.len(), 6, "HOTP code should be 6 digits");

    // 验证计数器 0 的码
    let (is_valid, _) = generator
        .verify(&secret, &code_0, 0)
        .expect("Verification should work");
    assert!(is_valid, "Code for counter 0 should be valid");

    // 计数器 1 应该生成不同的码
    let code_1 = generator.generate(&secret, 1).unwrap();
    assert_ne!(
        code_0, code_1,
        "Different counters should produce different codes"
    );

    // 用错误的计数器验证应该失败
    let (wrong_counter_result, _) = generator.verify(&secret, &code_0, 1).unwrap();
    assert!(!wrong_counter_result, "Code should fail with wrong counter");
}

/// 测试 HOTP 计数器递增
#[test]
fn test_hotp_counter_sequence() {
    let config = HotpConfig::default();
    let generator = HotpGenerator::new(config);

    let secret = generator.generate_secret().unwrap();

    // 生成一系列码
    let mut codes = Vec::new();
    for counter in 0..10 {
        let code = generator.generate(&secret, counter).unwrap();
        codes.push(code.clone());

        // 每个码都应该对其计数器有效
        let (is_valid_result, _) = generator.verify(&secret, &code, counter).unwrap();
        assert!(is_valid_result, "Code should be valid for its counter");
    }

    // 所有码应该各不相同
    let unique_codes: std::collections::HashSet<_> = codes.iter().collect();
    assert_eq!(
        unique_codes.len(),
        codes.len(),
        "All codes should be unique"
    );
}

/// 测试恢复码生成和验证
#[test]
fn test_recovery_codes_basic_flow() {
    let config = RecoveryConfig::default();
    let manager = RecoveryCodeManager::new(config);

    // 1. 生成一组恢复码
    let codes = manager.generate().expect("Code generation should succeed");

    assert!(!codes.plain_codes.is_empty(), "Should generate plain codes");
    assert!(
        !codes.hashed_codes.is_empty(),
        "Should generate hashed codes"
    );
    assert_eq!(
        codes.plain_codes.len(),
        codes.hashed_codes.len(),
        "Plain and hashed counts should match"
    );

    // 默认生成 10 个恢复码
    assert_eq!(
        codes.plain_codes.len(),
        10,
        "Should generate 10 recovery codes"
    );

    // 2. 验证每个恢复码
    for plain_code in &codes.plain_codes {
        let result = manager
            .verify(plain_code, &codes.hashed_codes)
            .expect("Verification should work");
        assert!(
            result.is_some(),
            "Each plain code should verify successfully"
        );
    }

    // 3. 错误码应该验证失败
    let wrong_code = "WRONG-CODE-1234";
    let wrong_result = manager.verify(wrong_code, &codes.hashed_codes).unwrap();
    assert!(
        wrong_result.is_none(),
        "Wrong code should fail verification"
    );
}

/// 测试恢复码一次性使用
#[test]
fn test_recovery_codes_single_use() {
    let config = RecoveryConfig::default();
    let manager = RecoveryCodeManager::new(config);

    let codes = manager.generate().unwrap();
    let code_to_use = &codes.plain_codes[0];

    // 第一次使用
    let first_result = manager.verify(code_to_use, &codes.hashed_codes).unwrap();
    assert!(first_result.is_some(), "First use should succeed");

    // 获取使用后的哈希码（移除已使用的）
    let used_index = first_result.unwrap();
    let remaining_hashes: Vec<_> = codes
        .hashed_codes
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != used_index)
        .map(|(_, h)| h.clone())
        .collect();

    // 在剩余的哈希中验证同一个码应该失败
    let second_result = manager.verify(code_to_use, &remaining_hashes).unwrap();
    assert!(
        second_result.is_none(),
        "Code should not work after being used"
    );
}

/// 测试恢复码配置
#[test]
fn test_recovery_codes_configuration() {
    let config = RecoveryConfig::new().with_code_count(5); // 只生成 5 个

    let manager = RecoveryCodeManager::new(config);
    let codes = manager.generate().unwrap();

    assert_eq!(codes.plain_codes.len(), 5, "Should generate 5 codes");
}

/// 测试完整的 MFA 启用流程
#[test]
fn test_mfa_enable_flow() {
    // 模拟用户启用 MFA 的完整流程

    // 1. 用户请求启用 MFA
    let totp_config = TotpConfig::default().with_issuer("MyApp");
    let totp_manager = TotpManager::new(totp_config);

    // 2. 系统生成 TOTP 密钥
    let totp_secret = totp_manager.generate_secret().unwrap();

    // 3. 系统生成 otpauth URI 供用户扫描
    let qr_uri = totp_manager.generate_uri(&totp_secret, "user@example.com");
    assert!(!qr_uri.is_empty(), "QR URI should be generated");

    // 4. 用户使用验证器 app 扫描后输入验证码
    let verification_code = totp_manager.generate_code(&totp_secret).unwrap();

    // 5. 系统验证码（确认用户正确设置了验证器）
    let is_setup_valid = totp_manager
        .verify(&totp_secret, &verification_code)
        .unwrap();
    assert!(is_setup_valid, "Setup verification should succeed");

    // 6. 系统生成恢复码
    let recovery_config = RecoveryConfig::default();
    let recovery_manager = RecoveryCodeManager::new(recovery_config);
    let recovery_codes = recovery_manager.generate().unwrap();

    // 7. 显示恢复码给用户保存
    assert_eq!(
        recovery_codes.plain_codes.len(),
        10,
        "Should have 10 recovery codes"
    );

    // 8. MFA 启用完成，存储：
    // - totp_secret.base32 作为加密存储的 TOTP 密钥
    // - recovery_codes.hashed_codes 作为恢复码哈希

    // 模拟后续登录验证
    let login_code = totp_manager.generate_code(&totp_secret).unwrap();
    let is_login_valid = totp_manager.verify(&totp_secret, &login_code).unwrap();
    assert!(is_login_valid, "Login verification should succeed");
}

/// 测试使用恢复码登录（TOTP 不可用时）
#[test]
fn test_recovery_code_login() {
    let recovery_config = RecoveryConfig::default();
    let recovery_manager = RecoveryCodeManager::new(recovery_config);

    // 用户启用 MFA 时生成的恢复码
    let codes = recovery_manager.generate().unwrap();

    // 模拟用户保存的恢复码（通常用户只有明文）
    let user_saved_codes = codes.plain_codes.clone();

    // 模拟系统存储的哈希
    let mut stored_hashes = codes.hashed_codes.clone();

    // 用户丢失手机，使用恢复码登录
    let recovery_code = &user_saved_codes[0];

    // 验证恢复码
    let result = recovery_manager
        .verify(recovery_code, &stored_hashes)
        .unwrap();
    assert!(result.is_some(), "Recovery code should be valid");

    // 使用后移除该恢复码
    let used_index = result.unwrap();
    stored_hashes.remove(used_index);

    // 剩余 9 个恢复码
    assert_eq!(stored_hashes.len(), 9, "Should have 9 remaining codes");

    // 同一个恢复码不能再次使用
    let reuse_result = recovery_manager
        .verify(recovery_code, &stored_hashes)
        .unwrap();
    assert!(
        reuse_result.is_none(),
        "Used recovery code should not work again"
    );
}

/// 测试恢复码格式
#[test]
fn test_recovery_code_format() {
    let config = RecoveryConfig::default();
    let manager = RecoveryCodeManager::new(config);

    let codes = manager.generate().unwrap();

    for code in &codes.plain_codes {
        // 恢复码通常是大写字母和数字的组合，可能带分隔符
        let clean_code: String = code.chars().filter(|c| *c != '-' && *c != ' ').collect();
        assert!(
            clean_code.chars().all(|c| c.is_ascii_alphanumeric()),
            "Recovery code should be alphanumeric"
        );
    }
}

/// 测试 TOTP 密钥从 base32 恢复
#[test]
fn test_totp_secret_restore() {
    let config = TotpConfig::default();
    let manager = TotpManager::new(config);

    // 生成原始密钥
    let original_secret = manager.generate_secret().unwrap();
    let base32_string = original_secret.base32.clone();

    // 从 base32 恢复密钥
    let restored_secret =
        TotpSecret::from_base32(&base32_string).expect("Secret should be restored from base32");

    // 两个密钥生成的码应该相同
    let original_code = manager.generate_code(&original_secret).unwrap();
    let restored_code = manager.generate_code(&restored_secret).unwrap();

    assert_eq!(
        original_code, restored_code,
        "Restored secret should generate same code"
    );
}
