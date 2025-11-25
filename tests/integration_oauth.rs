//! 集成测试：OAuth 2.0
//!
//! 测试 OAuth 客户端管理、PKCE、Token 响应等完整流程。

#![cfg(feature = "oauth")]

use authrs::oauth::{
    ClientType, GrantType, InMemoryClientStore, IntrospectionRequest, IntrospectionResponse,
    OAuthClient, OAuthClientStore, PkceChallenge, PkceMethod, TokenResponse,
};

/// 测试 OAuth 客户端创建和验证
#[test]
fn test_oauth_client_creation() {
    // 创建机密客户端（带密钥）
    let (client, secret) = OAuthClient::builder()
        .name("My Web Application")
        .client_type(ClientType::Confidential)
        .redirect_uri("https://example.com/callback")
        .redirect_uri("https://example.com/callback2")
        .grant_type(GrantType::AuthorizationCode)
        .grant_type(GrantType::RefreshToken)
        .scope("read")
        .scope("write")
        .scope("profile")
        .build()
        .expect("Client creation should succeed");

    // 验证客户端属性
    assert_eq!(client.name, "My Web Application");
    assert_eq!(client.client_type, ClientType::Confidential);
    assert!(
        client
            .redirect_uris
            .contains(&"https://example.com/callback".to_string())
    );
    assert!(client.grant_types.contains(&GrantType::AuthorizationCode));
    assert!(client.scopes.contains(&"read".to_string()));

    // 机密客户端应该有密钥
    assert!(secret.is_some(), "Confidential client should have secret");

    let client_secret = secret.unwrap();
    assert!(!client_secret.is_empty());

    // 验证密钥
    assert!(
        client.verify_secret(&client_secret),
        "Client secret should verify correctly"
    );

    // 错误密钥应该验证失败
    assert!(
        !client.verify_secret("wrong_secret"),
        "Wrong secret should fail verification"
    );
}

/// 测试公开客户端（无密钥）
#[test]
fn test_public_client() {
    let (client, secret) = OAuthClient::builder()
        .name("Mobile App")
        .client_type(ClientType::Public)
        .redirect_uri("myapp://callback")
        .grant_type(GrantType::AuthorizationCode)
        .scope("read")
        .build()
        .expect("Public client creation should succeed");

    assert_eq!(client.client_type, ClientType::Public);
    assert!(secret.is_none(), "Public client should not have secret");
}

/// 测试 PKCE (S256 方法)
#[test]
fn test_pkce_s256() {
    // 生成 PKCE challenge
    let challenge = PkceChallenge::new(PkceMethod::S256).expect("PKCE generation should succeed");

    // 获取授权请求参数
    let (code_challenge, method) = challenge.authorization_params();

    assert!(
        !code_challenge.is_empty(),
        "Code challenge should not be empty"
    );
    assert_eq!(method, "S256");

    // 获取 verifier（用于 token 请求）
    let code_verifier = challenge.verifier();
    assert!(
        !code_verifier.is_empty(),
        "Code verifier should not be empty"
    );

    // 服务端验证
    let is_valid = PkceChallenge::verify(code_verifier, code_challenge, PkceMethod::S256);
    assert!(is_valid, "PKCE verification should succeed");

    // 错误的 verifier 应该验证失败
    let wrong_verifier = "wrong_verifier_value_here_1234567890123456789012345";
    let is_invalid = PkceChallenge::verify(wrong_verifier, code_challenge, PkceMethod::S256);
    assert!(!is_invalid, "Wrong verifier should fail PKCE verification");
}

/// 测试 PKCE (Plain 方法)
#[test]
fn test_pkce_plain() {
    let challenge =
        PkceChallenge::new(PkceMethod::Plain).expect("PKCE Plain generation should succeed");

    let (code_challenge, method) = challenge.authorization_params();
    let code_verifier = challenge.verifier();

    assert_eq!(method, "plain");
    // Plain 方法下 challenge 和 verifier 应该相同
    assert_eq!(code_challenge, code_verifier);

    // 验证
    let is_valid = PkceChallenge::verify(code_verifier, code_challenge, PkceMethod::Plain);
    assert!(is_valid, "Plain PKCE verification should succeed");
}

/// 测试 Token 响应构建
#[test]
fn test_token_response() {
    let response = TokenResponse::new("access_token_here_abc123")
        .with_expires_in(3600)
        .with_refresh_token("refresh_token_here_xyz789")
        .with_scope("read write profile");

    assert_eq!(response.access_token, "access_token_here_abc123");
    assert_eq!(response.expires_in, Some(3600));
    assert_eq!(
        response.refresh_token,
        Some("refresh_token_here_xyz789".to_string())
    );
    assert_eq!(response.scope, Some("read write profile".to_string()));
    assert_eq!(response.token_type.to_string().to_lowercase(), "bearer");
}

/// 测试 Token 内省请求
#[test]
fn test_introspection_request() {
    // 创建内省请求
    let request = IntrospectionRequest::new("token_to_check_123");

    assert_eq!(request.token, "token_to_check_123");
    assert!(request.token_type_hint.is_none());

    // 带类型提示的请求
    let mut request_with_hint = IntrospectionRequest::new("access_token_456");
    request_with_hint.token_type_hint = Some(authrs::oauth::TokenTypeHint::AccessToken);

    assert!(request_with_hint.token_type_hint.is_some());
}

/// 测试 Token 内省响应
#[test]
fn test_introspection_response() {
    // 活跃 token 响应
    let active_response = IntrospectionResponse::active()
        .scope("read write")
        .client_id("client_123")
        .username("alice")
        .sub("user_456")
        .exp(chrono::Utc::now().timestamp() + 3600)
        .build();

    assert!(
        active_response.active,
        "Response should indicate active token"
    );
    assert_eq!(active_response.scope, Some("read write".to_string()));
    assert_eq!(active_response.client_id, Some("client_123".to_string()));
    assert_eq!(active_response.username, Some("alice".to_string()));
    assert_eq!(active_response.sub, Some("user_456".to_string()));

    // 非活跃 token 响应
    let inactive_response = IntrospectionResponse::inactive();
    assert!(
        !inactive_response.active,
        "Response should indicate inactive token"
    );
}

/// 测试 OAuth 客户端存储
#[test]
fn test_client_store() {
    let mut store = InMemoryClientStore::new();

    // 创建并存储客户端
    let (client1, _) = OAuthClient::builder()
        .name("Client 1")
        .client_type(ClientType::Confidential)
        .redirect_uri("https://client1.com/callback")
        .grant_type(GrantType::AuthorizationCode)
        .scope("read")
        .build()
        .unwrap();

    let client1_id = client1.client_id.clone();
    let _ = store.save(&client1);

    let (client2, _) = OAuthClient::builder()
        .name("Client 2")
        .client_type(ClientType::Public)
        .redirect_uri("https://client2.com/callback")
        .grant_type(GrantType::AuthorizationCode)
        .scope("write")
        .build()
        .unwrap();

    let client2_id = client2.client_id.clone();
    let _ = store.save(&client2);

    // 通过 ID 获取
    let retrieved1 = store.find_by_id(&client1_id).unwrap();
    assert!(retrieved1.is_some());
    assert_eq!(retrieved1.unwrap().name, "Client 1");

    let retrieved2 = store.find_by_id(&client2_id).unwrap();
    assert!(retrieved2.is_some());
    assert_eq!(retrieved2.unwrap().name, "Client 2");

    // 不存在的 ID
    let not_found = store.find_by_id("nonexistent_id").unwrap();
    assert!(not_found.is_none());

    // 列出所有客户端
    let all_clients = store.list().unwrap();
    assert_eq!(all_clients.len(), 2);

    // 删除客户端
    let deleted = store.delete(&client1_id);
    assert!(deleted.is_ok());
    assert!(store.find_by_id(&client1_id).unwrap().is_none());
    assert_eq!(store.list().unwrap().len(), 1);
}

/// 测试重定向 URI 验证
#[test]
fn test_redirect_uri_validation() {
    let (client, _) = OAuthClient::builder()
        .name("URI Test Client")
        .client_type(ClientType::Confidential)
        .redirect_uri("https://example.com/callback")
        .redirect_uri("https://example.com/oauth/callback")
        .grant_type(GrantType::AuthorizationCode)
        .scope("read")
        .build()
        .unwrap();

    // 有效的重定向 URI
    assert!(client.allows_redirect_uri("https://example.com/callback"));
    assert!(client.allows_redirect_uri("https://example.com/oauth/callback"));

    // 无效的重定向 URI
    assert!(!client.allows_redirect_uri("https://evil.com/callback"));
    assert!(!client.allows_redirect_uri("https://example.com/other"));
}

/// 测试授权类型验证
#[test]
fn test_grant_type_validation() {
    let (client, _) = OAuthClient::builder()
        .name("Grant Test Client")
        .client_type(ClientType::Confidential)
        .redirect_uri("https://example.com/callback")
        .grant_type(GrantType::AuthorizationCode)
        .grant_type(GrantType::RefreshToken)
        .scope("read")
        .build()
        .unwrap();

    // 允许的授权类型
    assert!(client.allows_grant_type(GrantType::AuthorizationCode));
    assert!(client.allows_grant_type(GrantType::RefreshToken));

    // 不允许的授权类型
    assert!(!client.allows_grant_type(GrantType::ClientCredentials));
}

/// 测试完整的 OAuth 授权码流程（模拟）
#[test]
fn test_authorization_code_flow_simulation() {
    // === 步骤 1：客户端注册 ===
    let mut client_store = InMemoryClientStore::new();

    let (client, client_secret) = OAuthClient::builder()
        .name("Web Application")
        .client_type(ClientType::Confidential)
        .redirect_uri("https://myapp.com/callback")
        .grant_type(GrantType::AuthorizationCode)
        .grant_type(GrantType::RefreshToken)
        .scope("read")
        .scope("write")
        .build()
        .unwrap();

    let client_id = client.client_id.clone();
    let secret = client_secret.unwrap();
    let _ = client_store.save(&client);

    // === 步骤 2：生成 PKCE ===
    let pkce = PkceChallenge::new(PkceMethod::S256).unwrap();
    let (code_challenge, _method) = pkce.authorization_params();
    let code_verifier = pkce.verifier().to_string();

    // === 步骤 3：模拟授权请求验证 ===
    let client = client_store
        .find_by_id(&client_id)
        .unwrap()
        .expect("Client should exist");

    // 验证 redirect_uri
    let redirect_uri = "https://myapp.com/callback";
    assert!(client.allows_redirect_uri(redirect_uri));

    // 验证 grant_type
    assert!(client.allows_grant_type(GrantType::AuthorizationCode));

    // === 步骤 4：用户授权后，模拟生成授权码 ===
    // 在实际实现中，这里会：
    // 1. 显示授权页面给用户
    // 2. 用户同意后生成授权码
    // 3. 将授权码与 code_challenge 关联存储
    let _authorization_code = "auth_code_123456";

    // === 步骤 5：模拟 Token 请求验证 ===
    // 验证客户端凭证 - 需要重新获取 client 因为之前的被借用了
    let client_for_verify = client_store
        .find_by_id(&client_id)
        .unwrap()
        .expect("Client should exist");
    assert!(client_for_verify.verify_secret(&secret));

    // 验证 PKCE
    let is_pkce_valid = PkceChallenge::verify(&code_verifier, code_challenge, PkceMethod::S256);
    assert!(is_pkce_valid, "PKCE verification should pass");

    // === 步骤 6：生成 Token 响应 ===
    let token_response = TokenResponse::new("access_token_abc123")
        .with_expires_in(3600)
        .with_refresh_token("refresh_token_xyz789")
        .with_scope("read write");

    assert!(!token_response.access_token.is_empty());
    assert!(token_response.refresh_token.is_some());

    // === 步骤 7：Token 内省 ===
    let _introspection_request = IntrospectionRequest::new(&token_response.access_token);

    // 模拟内省响应（token 有效）
    let introspection_response = IntrospectionResponse::active()
        .client_id(&client_id)
        .scope("read write")
        .sub("user_123")
        .build();

    assert!(introspection_response.active);
    assert_eq!(introspection_response.client_id, Some(client_id));
}

/// 测试客户端凭证授权流程
#[test]
fn test_client_credentials_flow() {
    let (client, client_secret) = OAuthClient::builder()
        .name("Service Client")
        .client_type(ClientType::Confidential)
        .redirect_uri("https://service.example.com/callback") // Required even for client credentials
        .grant_type(GrantType::ClientCredentials)
        .scope("api:read")
        .scope("api:write")
        .build()
        .unwrap();

    let secret = client_secret.unwrap();

    // 验证允许的授权类型
    assert!(client.allows_grant_type(GrantType::ClientCredentials));
    assert!(!client.allows_grant_type(GrantType::AuthorizationCode));

    // 验证客户端凭证
    assert!(client.verify_secret(&secret));

    // 生成服务间通信的 token
    let token_response = TokenResponse::new("service_access_token")
        .with_expires_in(3600)
        .with_scope("api:read api:write");

    assert_eq!(token_response.scope, Some("api:read api:write".to_string()));
    // Client Credentials 流程通常不提供 refresh token
    assert!(token_response.refresh_token.is_none());
}

/// 测试多个 PKCE challenge 的独立性
#[test]
fn test_pkce_independence() {
    let challenge1 = PkceChallenge::new(PkceMethod::S256).unwrap();
    let challenge2 = PkceChallenge::new(PkceMethod::S256).unwrap();

    let (code_challenge1, _) = challenge1.authorization_params();
    let (code_challenge2, _) = challenge2.authorization_params();

    let verifier1 = challenge1.verifier();
    let verifier2 = challenge2.verifier();

    // 每个 challenge 应该是唯一的
    assert_ne!(code_challenge1, code_challenge2);
    assert_ne!(verifier1, verifier2);

    // 交叉验证应该失败
    assert!(!PkceChallenge::verify(
        verifier1,
        code_challenge2,
        PkceMethod::S256
    ));
    assert!(!PkceChallenge::verify(
        verifier2,
        code_challenge1,
        PkceMethod::S256
    ));

    // 正确配对验证应该成功
    assert!(PkceChallenge::verify(
        verifier1,
        code_challenge1,
        PkceMethod::S256
    ));
    assert!(PkceChallenge::verify(
        verifier2,
        code_challenge2,
        PkceMethod::S256
    ));
}
