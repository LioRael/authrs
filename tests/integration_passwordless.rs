#![cfg(feature = "passwordless")]

//! Passwordless 认证模块集成测试
//!
//! 测试 Magic Link 和 OTP 功能的各种使用场景。

use authrs::passwordless::{MagicLinkConfig, MagicLinkManager, OtpConfig, OtpManager, OtpPurpose};
use std::time::Duration;

// ============================================================================
// Magic Link 测试
// ============================================================================

/// 测试基本的 Magic Link 生成和验证流程
#[test]
fn test_magic_link_basic_flow() {
    let manager = MagicLinkManager::new(MagicLinkConfig::default());

    // 生成 magic link token
    let data = manager.generate("user@example.com").unwrap();

    assert!(!data.token.is_empty());
    assert_eq!(data.identifier, "user@example.com");
    assert!(!data.is_expired());
    assert!(data.remaining_seconds() > 0);

    // 验证 token
    let email = manager.verify(&data.token).unwrap();
    assert_eq!(email, "user@example.com");
}

/// 测试 Magic Link 一次性使用
#[test]
fn test_magic_link_single_use() {
    let manager = MagicLinkManager::new(MagicLinkConfig::default());

    let data = manager.generate("user@example.com").unwrap();

    // 第一次验证成功
    assert!(manager.verify(&data.token).is_ok());

    // 第二次验证失败（已被消费）
    assert!(manager.verify(&data.token).is_err());
}

/// 测试 Magic Link 无效 token
#[test]
fn test_magic_link_invalid_token() {
    let manager = MagicLinkManager::new(MagicLinkConfig::default());

    // 验证不存在的 token
    assert!(manager.verify("invalid-token").is_err());
    assert!(manager.verify("").is_err());
}

/// 测试 Magic Link 撤销功能
#[test]
fn test_magic_link_revoke() {
    let manager = MagicLinkManager::new(MagicLinkConfig::default());

    let data = manager.generate("user@example.com").unwrap();

    // 撤销 token
    manager.revoke(&data.token).unwrap();

    // 验证失败
    assert!(manager.verify(&data.token).is_err());
}

/// 测试 Magic Link 撤销用户所有 token
#[test]
fn test_magic_link_revoke_all_for_user() {
    let config = MagicLinkConfig::default().with_max_active_per_user(10);
    let manager = MagicLinkManager::new(config);

    // 生成多个 token
    let t1 = manager.generate("alice@example.com").unwrap();
    let t2 = manager.generate("alice@example.com").unwrap();
    let t3 = manager.generate("bob@example.com").unwrap();

    // 撤销 alice 的所有 token
    let count = manager.revoke_all_for_user("alice@example.com").unwrap();
    assert_eq!(count, 2);

    // alice 的 token 都失效
    assert!(manager.verify(&t1.token).is_err());
    assert!(manager.verify(&t2.token).is_err());

    // bob 的 token 仍然有效
    assert!(manager.verify(&t3.token).is_ok());
}

/// 测试 Magic Link 高安全配置
#[test]
fn test_magic_link_high_security_config() {
    let config = MagicLinkConfig::high_security();
    let manager = MagicLinkManager::new(config);

    let data = manager.generate("secure@example.com").unwrap();

    // token 长度更长（base64 编码后）
    assert!(data.token.len() > 50);

    // 验证成功
    assert!(manager.verify(&data.token).is_ok());
}

/// 测试 Magic Link 最大活跃 token 限制
#[test]
fn test_magic_link_max_active_tokens() {
    let config = MagicLinkConfig::default().with_max_active_per_user(2);
    let manager = MagicLinkManager::new(config);

    let t1 = manager.generate("user@example.com").unwrap();
    let t2 = manager.generate("user@example.com").unwrap();
    let t3 = manager.generate("user@example.com").unwrap();

    // t1 应该被删除了（最旧的）
    assert!(manager.verify(&t1.token).is_err());

    // t2 和 t3 仍然有效
    assert!(manager.verify(&t2.token).is_ok());
    assert!(manager.verify(&t3.token).is_ok());
}

/// 测试不同用户的 Magic Link 相互独立
#[test]
fn test_magic_link_user_isolation() {
    let manager = MagicLinkManager::new(MagicLinkConfig::default());

    let alice_token = manager.generate("alice@example.com").unwrap();
    let bob_token = manager.generate("bob@example.com").unwrap();

    // 验证 alice 的 token
    let email1 = manager.verify(&alice_token.token).unwrap();
    assert_eq!(email1, "alice@example.com");

    // bob 的 token 仍然有效
    let email2 = manager.verify(&bob_token.token).unwrap();
    assert_eq!(email2, "bob@example.com");
}

// ============================================================================
// OTP 测试
// ============================================================================

/// 测试基本的 OTP 生成和验证流程
#[test]
fn test_otp_basic_flow() {
    let config = OtpConfig::default().with_min_interval(None);
    let manager = OtpManager::new(config);

    // 生成 OTP
    let otp = manager
        .generate("user@example.com", OtpPurpose::Login)
        .unwrap();

    assert_eq!(otp.code.len(), 6);
    assert_eq!(otp.identifier, "user@example.com");
    assert_eq!(otp.purpose, OtpPurpose::Login);
    assert!(!otp.is_expired());

    // 验证 OTP
    assert!(
        manager
            .verify("user@example.com", &otp.code, OtpPurpose::Login)
            .is_ok()
    );
}

/// 测试 OTP 一次性使用
#[test]
fn test_otp_single_use() {
    let config = OtpConfig::default().with_min_interval(None);
    let manager = OtpManager::new(config);

    let otp = manager
        .generate("user@example.com", OtpPurpose::Login)
        .unwrap();

    // 第一次验证成功
    assert!(
        manager
            .verify("user@example.com", &otp.code, OtpPurpose::Login)
            .is_ok()
    );

    // 第二次验证失败
    assert!(
        manager
            .verify("user@example.com", &otp.code, OtpPurpose::Login)
            .is_err()
    );
}

/// 测试 OTP 错误验证码
#[test]
fn test_otp_wrong_code() {
    let config = OtpConfig::default()
        .with_min_interval(None)
        .with_max_attempts(5);
    let manager = OtpManager::new(config);

    let otp = manager
        .generate("user@example.com", OtpPurpose::Login)
        .unwrap();

    // 错误的验证码
    assert!(
        manager
            .verify("user@example.com", "000000", OtpPurpose::Login)
            .is_err()
    );

    // 正确的验证码仍然有效（还有尝试次数）
    assert!(
        manager
            .verify("user@example.com", &otp.code, OtpPurpose::Login)
            .is_ok()
    );
}

/// 测试 OTP 最大尝试次数
#[test]
fn test_otp_max_attempts() {
    let config = OtpConfig::default()
        .with_min_interval(None)
        .with_max_attempts(2);
    let manager = OtpManager::new(config);

    let otp = manager
        .generate("user@example.com", OtpPurpose::Login)
        .unwrap();

    // 错误尝试 2 次
    let _ = manager.verify("user@example.com", "000000", OtpPurpose::Login);
    let _ = manager.verify("user@example.com", "000001", OtpPurpose::Login);

    // 超过最大尝试次数，正确的验证码也无效
    assert!(
        manager
            .verify("user@example.com", &otp.code, OtpPurpose::Login)
            .is_err()
    );
}

/// 测试不同用途的 OTP 相互独立
#[test]
fn test_otp_purpose_isolation() {
    let config = OtpConfig::default().with_min_interval(None);
    let manager = OtpManager::new(config);

    let login_otp = manager
        .generate("user@example.com", OtpPurpose::Login)
        .unwrap();
    let reset_otp = manager
        .generate("user@example.com", OtpPurpose::PasswordReset)
        .unwrap();

    // 验证码不能跨用途使用
    assert!(
        manager
            .verify(
                "user@example.com",
                &login_otp.code,
                OtpPurpose::PasswordReset
            )
            .is_err()
    );
    assert!(
        manager
            .verify("user@example.com", &reset_otp.code, OtpPurpose::Login)
            .is_err()
    );

    // 正确的用途可以验证
    assert!(
        manager
            .verify("user@example.com", &login_otp.code, OtpPurpose::Login)
            .is_ok()
    );
    assert!(
        manager
            .verify(
                "user@example.com",
                &reset_otp.code,
                OtpPurpose::PasswordReset
            )
            .is_ok()
    );
}

/// 测试 OTP 撤销功能
#[test]
fn test_otp_revoke() {
    let config = OtpConfig::default().with_min_interval(None);
    let manager = OtpManager::new(config);

    let otp = manager
        .generate("user@example.com", OtpPurpose::Login)
        .unwrap();

    // 撤销
    manager
        .revoke("user@example.com", OtpPurpose::Login)
        .unwrap();

    // 验证失败
    assert!(
        manager
            .verify("user@example.com", &otp.code, OtpPurpose::Login)
            .is_err()
    );
}

/// 测试 OTP 高安全配置
#[test]
fn test_otp_high_security_config() {
    let config = OtpConfig::high_security().with_min_interval(None);
    let manager = OtpManager::new(config);

    let otp = manager
        .generate("secure@example.com", OtpPurpose::TwoFactor)
        .unwrap();

    // 8 位验证码
    assert_eq!(otp.code.len(), 8);

    // 验证成功
    assert!(
        manager
            .verify("secure@example.com", &otp.code, OtpPurpose::TwoFactor)
            .is_ok()
    );
}

/// 测试 OTP 自定义验证码长度
#[test]
fn test_otp_custom_code_length() {
    for length in [4, 6, 8, 10] {
        let config = OtpConfig::default()
            .with_code_length(length)
            .with_min_interval(None);
        let manager = OtpManager::new(config);

        let otp = manager
            .generate("user@example.com", OtpPurpose::Login)
            .unwrap();
        assert_eq!(otp.code.len(), length);

        // 验证成功
        assert!(
            manager
                .verify("user@example.com", &otp.code, OtpPurpose::Login)
                .is_ok()
        );
    }
}

/// 测试所有 OTP 用途
#[test]
fn test_all_otp_purposes() {
    let config = OtpConfig::default().with_min_interval(None);
    let manager = OtpManager::new(config);

    let purposes = [
        OtpPurpose::Login,
        OtpPurpose::Registration,
        OtpPurpose::PasswordReset,
        OtpPurpose::EmailVerification,
        OtpPurpose::PhoneVerification,
        OtpPurpose::TransactionConfirmation,
        OtpPurpose::TwoFactor,
        OtpPurpose::Custom(42),
    ];

    for purpose in purposes {
        let otp = manager.generate("user@example.com", purpose).unwrap();
        assert!(
            manager
                .verify("user@example.com", &otp.code, purpose)
                .is_ok(),
            "Failed for purpose: {:?}",
            purpose
        );
    }
}

// ============================================================================
// 实际应用场景测试
// ============================================================================

/// 模拟完整的 Magic Link 登录流程
#[test]
fn test_magic_link_login_scenario() {
    let manager = MagicLinkManager::new(MagicLinkConfig::default());

    // 用户请求 magic link 登录
    let user_email = "alice@example.com";
    let magic_link_data = manager.generate(user_email).unwrap();

    // 构建登录 URL（应用层负责发送邮件）
    let login_url = format!(
        "https://myapp.com/auth/magic?token={}",
        magic_link_data.token
    );
    assert!(login_url.contains(&magic_link_data.token));

    // 用户点击链接后，验证 token
    let verified_email = manager.verify(&magic_link_data.token).unwrap();
    assert_eq!(verified_email, user_email);

    // 此时应用层可以创建 session 并登录用户
}

/// 模拟完整的 OTP 登录流程
#[test]
fn test_otp_login_scenario() {
    let config = OtpConfig::default()
        .with_code_length(6)
        .with_ttl(Duration::from_secs(300))
        .with_max_attempts(3)
        .with_min_interval(None);
    let manager = OtpManager::new(config);

    // 用户请求 OTP 登录
    let user_email = "bob@example.com";
    let otp_data = manager.generate(user_email, OtpPurpose::Login).unwrap();

    // 应用层发送验证码邮件/短信
    let code_to_send = &otp_data.code;
    assert_eq!(code_to_send.len(), 6);

    // 用户输入验证码
    let user_input = code_to_send; // 假设用户正确输入
    assert!(
        manager
            .verify(user_email, user_input, OtpPurpose::Login)
            .is_ok()
    );

    // 此时应用层可以创建 session 并登录用户
}

/// 模拟密码重置流程
#[test]
fn test_password_reset_scenario() {
    let config = OtpConfig::default()
        .with_ttl(Duration::from_secs(600)) // 10 分钟
        .with_max_attempts(5)
        .with_min_interval(None);
    let manager = OtpManager::new(config);

    let user_email = "user@example.com";

    // 用户请求密码重置
    let otp_data = manager
        .generate(user_email, OtpPurpose::PasswordReset)
        .unwrap();

    // 用户第一次输入错误
    let wrong_result = manager.verify(user_email, "000000", OtpPurpose::PasswordReset);
    assert!(wrong_result.is_err());

    // 用户第二次输入正确
    let correct_result = manager.verify(user_email, &otp_data.code, OtpPurpose::PasswordReset);
    assert!(correct_result.is_ok());

    // 应用层现在可以允许用户设置新密码
}

/// 模拟邮箱验证流程
#[test]
fn test_email_verification_scenario() {
    let config = OtpConfig::default()
        .with_code_length(8)
        .with_ttl(Duration::from_secs(3600)) // 1 小时
        .with_min_interval(None);
    let manager = OtpManager::new(config);

    let new_email = "newemail@example.com";

    // 用户注册时生成验证码
    let otp_data = manager
        .generate(new_email, OtpPurpose::EmailVerification)
        .unwrap();

    // 验证码有效期检查
    assert!(otp_data.remaining_seconds() > 3500);

    // 用户验证邮箱
    assert!(
        manager
            .verify(new_email, &otp_data.code, OtpPurpose::EmailVerification)
            .is_ok()
    );
}

/// 测试 Magic Link 和 OTP 可以同时使用
#[test]
fn test_magic_link_and_otp_coexistence() {
    let ml_manager = MagicLinkManager::new(MagicLinkConfig::default());
    let otp_config = OtpConfig::default().with_min_interval(None);
    let otp_manager = OtpManager::new(otp_config);

    let user = "user@example.com";

    // 同时生成 Magic Link 和 OTP
    let magic_link = ml_manager.generate(user).unwrap();
    let otp = otp_manager.generate(user, OtpPurpose::Login).unwrap();

    // 两者都可以独立验证
    assert!(ml_manager.verify(&magic_link.token).is_ok());
    assert!(
        otp_manager
            .verify(user, &otp.code, OtpPurpose::Login)
            .is_ok()
    );
}
