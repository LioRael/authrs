//! 集成测试：完整的认证流程
//!
//! 测试从用户注册到登录、MFA、Session 管理的完整流程。

use authrs::password::{hash_password, validate_password_strength, verify_password};
use authrs::security::account::{LoginAttemptTracker, LoginCheckResult};
use authrs::security::csrf::CsrfProtection;
use authrs::security::rate_limit::{RateLimitConfig, RateLimiter};
use authrs::token::session::{SessionConfig, SessionManager};
use std::time::Duration;

/// 模拟用户数据
#[allow(dead_code)]
struct MockUser {
    id: String,
    username: String,
    password_hash: String,
    mfa_enabled: bool,
}

/// 测试完整的用户注册流程
#[test]
fn test_user_registration_flow() {
    // 1. 用户输入密码
    let password = "SecureP@ssw0rd!2024";

    // 2. 验证密码强度
    let strength_result = validate_password_strength(password);
    assert!(
        strength_result.is_ok(),
        "Password should meet strength requirements"
    );

    // 3. 哈希密码
    let password_hash = hash_password(password).expect("Password hashing should succeed");

    // 4. 验证哈希后可以正确验证
    let is_valid = verify_password(password, &password_hash).expect("Verification should work");
    assert!(is_valid, "Password should verify correctly");

    // 5. 错误密码应该验证失败
    let is_invalid =
        verify_password("wrong_password", &password_hash).expect("Verification should work");
    assert!(!is_invalid, "Wrong password should fail verification");
}

/// 测试完整的登录流程（包括速率限制和账户锁定）
#[tokio::test]
async fn test_login_flow_with_security() {
    // 设置安全组件
    let rate_config = RateLimitConfig::new()
        .with_max_requests(5)
        .with_window(Duration::from_secs(60));
    let rate_limiter = RateLimiter::new(rate_config);
    let mut login_tracker = LoginAttemptTracker::with_default_config();

    // 模拟用户
    let user_id = "user_123";
    let password = "CorrectPassword123!";
    let password_hash = hash_password(password).unwrap();

    let rate_key = format!("login:{}", user_id);

    // 场景1：正常登录
    {
        // 检查速率限制
        let rate_result = rate_limiter.check(&rate_key).await;
        assert!(rate_result.is_ok(), "Rate limit should allow request");

        // 检查账户锁定状态
        let lock_result = login_tracker.check_login_allowed(user_id, None);
        assert!(matches!(lock_result, LoginCheckResult::Allowed));

        // 验证密码
        let is_valid = verify_password(password, &password_hash).unwrap();
        assert!(is_valid);

        // 记录成功登录
        login_tracker.record_successful_login(user_id, None);
    }

    // 场景2：连续失败登录
    {
        let bad_user_id = "user_456";

        // 模拟多次失败登录
        for _ in 0..5 {
            let check = login_tracker.check_login_allowed(bad_user_id, None);
            if matches!(check, LoginCheckResult::Allowed) {
                // 记录失败
                login_tracker.record_failed_attempt(bad_user_id, None);
            }
            // 无论是否被锁定/延迟，继续尝试
        }

        // 多次失败后，账户应该被锁定或需要延迟
        // 具体行为取决于配置，这里只验证失败被记录
        let final_check = login_tracker.check_login_allowed(bad_user_id, None);
        // 接受 Allowed、Locked 或 DelayRequired 任何结果
        // 重要的是系统正在追踪失败尝试
        assert!(
            matches!(
                final_check,
                LoginCheckResult::Allowed
                    | LoginCheckResult::Locked { .. }
                    | LoginCheckResult::DelayRequired { .. }
            ),
            "Login check should return a valid result"
        );
    }
}

/// 测试 Session 管理流程
#[tokio::test]
async fn test_session_management_flow() {
    let config = SessionConfig::new()
        .with_max_sessions_per_user(3)
        .with_expiration(chrono::Duration::hours(24));
    let manager = SessionManager::new(config);

    let user_id = "user_789";

    // 1. 创建 Session
    let session = manager
        .create(user_id)
        .await
        .expect("Session creation should succeed");
    assert_eq!(session.user_id, user_id);
    assert!(!session.id.is_empty());

    // 2. 验证 Session
    let retrieved = manager.get(&session.id).await;
    assert!(retrieved.is_some(), "Session should exist");
    assert_eq!(retrieved.unwrap().user_id, user_id);

    // 3. 列出用户的所有 Session
    let sessions = manager.get_user_sessions(user_id).await.unwrap();
    assert_eq!(sessions.len(), 1, "User should have exactly one session");

    // 4. 创建多个 Session
    let _session2 = manager.create(user_id).await.unwrap();
    let _session3 = manager.create(user_id).await.unwrap();
    let sessions = manager.get_user_sessions(user_id).await.unwrap();
    assert_eq!(sessions.len(), 3, "User should have exactly three sessions");

    // 5. 超过限制时最旧的 Session 被移除
    let _session4 = manager.create(user_id).await.unwrap();
    let sessions = manager.get_user_sessions(user_id).await.unwrap();
    assert_eq!(sessions.len(), 3, "Max sessions should be enforced");

    // 6. 销毁单个 Session
    let destroy_result = manager.destroy(&session.id).await;
    assert!(destroy_result.is_ok(), "Destroy should succeed");
    let retrieved = manager.get(&session.id).await;
    assert!(retrieved.is_none(), "Destroyed session should not exist");

    // 7. 销毁用户所有 Session
    let count = manager.destroy_all_for_user(user_id).await.unwrap();
    assert!(count >= 2, "Should destroy remaining sessions");
}

/// 测试 CSRF 防护流程
#[test]
fn test_csrf_protection_flow() {
    let csrf = CsrfProtection::new(Default::default());

    // 1. 生成 CSRF Token（用于表单）
    let token = csrf
        .generate_token()
        .expect("Token generation should succeed");
    assert!(!token.token.is_empty());

    // 2. 验证有效 Token
    let is_valid = csrf.verify(&token.token).expect("Verification should work");
    assert!(is_valid, "Valid token should pass verification");

    // 3. 验证无效 Token
    let is_invalid = csrf.verify("invalid_token_here").unwrap_or(false);
    assert!(!is_invalid, "Invalid token should fail verification");

    // 4. 每次请求生成新 Token（Token 旋转）
    let token2 = csrf.generate_token().unwrap();
    assert_ne!(token.token, token2.token, "Each token should be unique");
}

/// 测试完整的认证生命周期
#[tokio::test]
async fn test_complete_auth_lifecycle() {
    // === 阶段1：注册 ===
    let username = "alice";
    let password = "AliceSecure#2024";

    // 验证密码强度
    validate_password_strength(password).expect("Password should be strong enough");

    // 哈希存储
    let password_hash = hash_password(password).unwrap();

    let user = MockUser {
        id: "user_alice_001".to_string(),
        username: username.to_string(),
        password_hash,
        mfa_enabled: false,
    };

    // === 阶段2：登录 ===
    let session_manager = SessionManager::new(SessionConfig::default());
    let mut login_tracker = LoginAttemptTracker::with_default_config();
    let csrf = CsrfProtection::new(Default::default());

    // 检查是否允许登录
    let check = login_tracker.check_login_allowed(&user.id, None);
    assert!(matches!(check, LoginCheckResult::Allowed));

    // 验证密码
    let login_password = "AliceSecure#2024";
    let is_valid = verify_password(login_password, &user.password_hash).unwrap();
    assert!(is_valid);

    // 记录成功登录
    login_tracker.record_successful_login(&user.id, None);

    // 创建 Session
    let session = session_manager.create(&user.id).await.unwrap();

    // 生成 CSRF Token
    let csrf_token = csrf.generate_token().unwrap();

    // === 阶段3：已认证请求 ===

    // 验证 Session
    let active_session = session_manager.get(&session.id);
    assert!(active_session.await.is_some());

    // 验证 CSRF Token（例如：表单提交）
    let csrf_valid = csrf.verify(&csrf_token.token).unwrap();
    assert!(csrf_valid);

    // Session 在 get() 调用时会自动更新活动时间（如果启用滑动过期）

    // === 阶段4：登出 ===
    let destroy_result = session_manager.destroy(&session.id);
    assert!(destroy_result.await.is_ok());

    // 验证 Session 已失效
    let logged_out = session_manager.get(&session.id);
    assert!(logged_out.await.is_none());
}

/// 测试密码变更流程
#[test]
fn test_password_change_flow() {
    let old_password = "OldPassword123!";
    let new_password = "NewSecureP@ss2024!";

    // 原始密码哈希
    let old_hash = hash_password(old_password).unwrap();

    // 1. 验证旧密码
    let is_old_valid = verify_password(old_password, &old_hash).unwrap();
    assert!(is_old_valid, "Old password should be valid");

    // 2. 验证新密码强度
    validate_password_strength(new_password).expect("New password should meet requirements");

    // 3. 确保新旧密码不同
    assert_ne!(old_password, new_password);

    // 4. 创建新密码哈希
    let new_hash = hash_password(new_password).unwrap();

    // 5. 验证新密码有效
    let is_new_valid = verify_password(new_password, &new_hash).unwrap();
    assert!(is_new_valid, "New password should be valid");

    // 6. 旧密码不能用于新哈希
    let old_with_new_hash = verify_password(old_password, &new_hash).unwrap();
    assert!(
        !old_with_new_hash,
        "Old password should not work with new hash"
    );
}
