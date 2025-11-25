//! 集成测试：JWT 和 Token 管理
//!
//! 测试 JWT 创建/验证、Refresh Token 轮换等流程。

use authrs::token::jwt::{JwtBuilder, JwtValidator};
use authrs::token::refresh::{RefreshConfig, RefreshTokenManager};
use authrs::token::session::{SessionConfig, SessionManager};

/// 测试 JWT 创建和验证的基本流程
#[test]
fn test_jwt_basic_flow() {
    let secret = b"test-secret-key-must-be-32-bytes!";

    // 1. 创建 JWT
    let token = JwtBuilder::new()
        .subject("user_123")
        .issuer("authrs-test")
        .expires_in_hours(1)
        .claim("role", "admin")
        .build_with_secret(secret)
        .expect("JWT creation should succeed");

    assert!(!token.is_empty(), "Token should not be empty");

    // 2. 验证 JWT
    let validator = JwtValidator::new(secret);
    let claims = validator
        .validate(&token)
        .expect("JWT validation should succeed");

    assert_eq!(claims.sub, Some("user_123".to_string()));
    assert_eq!(claims.iss, Some("authrs-test".to_string()));

    // 3. 验证自定义 claims
    let role = claims.custom.get("role").and_then(|v| v.as_str());
    assert_eq!(role, Some("admin"));
}

/// 测试 JWT 签名验证（错误密钥）
#[test]
fn test_jwt_wrong_secret() {
    let secret1 = b"first-secret-key-32-bytes-long!!";
    let secret2 = b"second-secret-key-32-bytes-long!";

    // 使用第一个密钥创建 JWT
    let token = JwtBuilder::new()
        .subject("user_123")
        .expires_in_hours(1)
        .build_with_secret(secret1)
        .expect("JWT creation should succeed");

    // 使用第二个密钥验证应该失败
    let validator = JwtValidator::new(secret2);
    let result = validator.validate(&token);
    assert!(
        result.is_err(),
        "Token signed with different secret should fail"
    );
}

/// 测试 JWT 创建带有各种 claims
#[test]
fn test_jwt_with_claims() {
    let secret = b"test-secret-key-must-be-32-bytes!";

    // 创建带有多个 claims 的 JWT
    let token = JwtBuilder::new()
        .subject("user_123")
        .issuer("authrs-test")
        .expires_in_hours(1)
        .claim("user_level", 5)
        .claim("verified", true)
        .build_with_secret(secret)
        .expect("JWT creation should succeed");

    let validator = JwtValidator::new(secret);
    let claims = validator.validate(&token).expect("JWT should be valid");

    assert_eq!(claims.sub, Some("user_123".to_string()));
    assert_eq!(
        claims.custom.get("user_level").and_then(|v| v.as_i64()),
        Some(5)
    );
    assert_eq!(
        claims.custom.get("verified").and_then(|v| v.as_bool()),
        Some(true)
    );
}

/// 测试 Refresh Token 管理
#[tokio::test]
async fn test_refresh_token_manager() {
    let config = RefreshConfig::new();

    let manager = RefreshTokenManager::new(config);
    let user_id = "user_123";

    // 1. 生成 Refresh Token
    let token = manager
        .generate(user_id)
        .await
        .expect("Token generation should succeed");
    assert!(!token.token.is_empty());
    assert_eq!(token.user_id, user_id);

    // 2. 使用 Token
    let result = manager
        .use_token(&token.token)
        .await
        .expect("Token use should succeed");

    // TokenUseResult 是一个结构体
    assert_eq!(result.user_id, user_id);
}

/// 测试 Refresh Token 基本功能
#[tokio::test]
async fn test_refresh_token_basic() {
    let config = RefreshConfig::new();
    let manager = RefreshTokenManager::new(config);

    // 生成 Token
    let token = manager.generate("user_123").await.unwrap();
    assert!(!token.token.is_empty());

    // Token 刚生成应该有效
    let result = manager.use_token(&token.token).await;
    assert!(result.is_ok(), "Fresh token should be valid");
}

/// 测试 Session 管理
#[tokio::test]
async fn test_session_management() {
    let session_manager = SessionManager::new(SessionConfig::default());

    let user_id = "user_123";

    // 1. 创建 Session
    let session = session_manager
        .create(user_id)
        .await
        .expect("Session creation should succeed");
    assert!(!session.id.is_empty());
    assert_eq!(session.user_id, user_id);

    // 2. 获取 Session
    let retrieved = session_manager.get(&session.id).await;
    assert!(retrieved.is_some(), "Session should exist");
    assert_eq!(retrieved.unwrap().user_id, user_id);

    // 3. 销毁 Session
    session_manager.destroy(&session.id).await.unwrap();
    let after_destroy = session_manager.get(&session.id).await;
    assert!(after_destroy.is_none(), "Session should be destroyed");
}
