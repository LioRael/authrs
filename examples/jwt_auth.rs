//! JWT 认证示例
//!
//! 展示如何使用 AuthRS 实现 JWT 令牌的创建、验证和刷新。
//!
//! 运行: cargo run --example jwt_auth --features jwt

use authrs::token::jwt::{JwtBuilder, JwtValidator};
use authrs::token::refresh::{RefreshConfig, RefreshTokenManager};

/// JWT 密钥（实际应用中应从环境变量或密钥管理服务获取）
const JWT_SECRET: &[u8] = b"your-256-bit-secret-key-here-32b";

/// 模拟的用户服务
struct UserService;

impl UserService {
    fn authenticate(username: &str, password: &str) -> Option<UserInfo> {
        // 实际应用中应查询数据库并验证密码
        if username == "alice" && password == "password123" {
            Some(UserInfo {
                user_id: "user_001".to_string(),
                username: "alice".to_string(),
                roles: vec!["user".to_string(), "editor".to_string()],
            })
        } else {
            None
        }
    }
}

struct UserInfo {
    user_id: String,
    username: String,
    roles: Vec<String>,
}

/// JWT 认证服务
struct JwtAuthService {
    validator: JwtValidator,
    refresh_manager: RefreshTokenManager,
}

impl JwtAuthService {
    fn new() -> Self {
        let refresh_config = RefreshConfig::new();

        Self {
            validator: JwtValidator::new(JWT_SECRET),
            refresh_manager: RefreshTokenManager::new(refresh_config),
        }
    }

    /// 用户登录，返回 JWT 和 Refresh Token
    async fn login(&self, username: &str, password: &str) -> Result<TokenPair, String> {
        // 1. 验证用户凭证
        let user = UserService::authenticate(username, password)
            .ok_or_else(|| "用户名或密码错误".to_string())?;

        // 2. 创建 JWT
        let access_token = JwtBuilder::new()
            .subject(&user.user_id)
            .issuer("authrs-example")
            .audience("authrs-api")
            .expires_in_hours(1) // 1 小时过期
            .claim("username", &user.username)
            .claim("roles", &user.roles)
            .build_with_secret(JWT_SECRET)
            .map_err(|e| format!("JWT 创建失败: {}", e))?;

        // 3. 创建 Refresh Token
        let refresh_token = self
            .refresh_manager
            .generate(&user.user_id)
            .await
            .map_err(|e| format!("Refresh Token 创建失败: {}", e))?;

        println!("✅ 登录成功: {}", user.username);

        Ok(TokenPair {
            access_token,
            refresh_token: refresh_token.token,
            user_id: user.user_id,
        })
    }

    /// 验证 JWT 并返回用户信息
    fn validate_token(&self, token: &str) -> Result<TokenClaims, String> {
        let claims = self
            .validator
            .validate(token)
            .map_err(|e| format!("Token 验证失败: {}", e))?;

        let user_id = claims.sub.ok_or("Token 缺少 subject")?;
        let username = claims
            .custom
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let roles = claims
            .custom
            .get("roles")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        Ok(TokenClaims {
            user_id,
            username,
            roles,
        })
    }

    /// 使用 Refresh Token 获取新的 Access Token
    async fn refresh(&self, refresh_token: &str) -> Result<RefreshResult, String> {
        let result = self
            .refresh_manager
            .use_token(refresh_token)
            .await
            .map_err(|e| format!("Refresh Token 使用失败: {}", e))?;

        // TokenUseResult 是一个结构体
        // 创建新的 Access Token
        let access_token = JwtBuilder::new()
            .subject(&result.user_id)
            .issuer("authrs-example")
            .audience("authrs-api")
            .expires_in_hours(1)
            .build_with_secret(JWT_SECRET)
            .map_err(|e| format!("JWT 创建失败: {}", e))?;

        Ok(RefreshResult {
            access_token,
            new_refresh_token: result.new_token.map(|t| t.token),
            user_id: result.user_id,
        })
    }
}

struct TokenPair {
    access_token: String,
    refresh_token: String,
    user_id: String,
}

struct TokenClaims {
    user_id: String,
    username: String,
    roles: Vec<String>,
}

struct RefreshResult {
    access_token: String,
    new_refresh_token: Option<String>,
    #[allow(dead_code)]
    user_id: String,
}

#[tokio::main]
async fn main() {
    println!("=== AuthRS JWT 认证示例 ===\n");

    let auth_service = JwtAuthService::new();

    // 1. 用户登录
    println!("🔐 用户登录...");
    let tokens = match auth_service.login("alice", "password123").await {
        Ok(t) => {
            println!("   用户 ID: {}", t.user_id);
            println!("   Access Token: {}...", &t.access_token[..50]);
            println!("   Refresh Token: {}...\n", &t.refresh_token[..20]);
            t
        }
        Err(e) => {
            println!("   ❌ 登录失败: {}\n", e);
            return;
        }
    };

    // 2. 验证 Access Token
    println!("🔍 验证 Access Token...");
    match auth_service.validate_token(&tokens.access_token) {
        Ok(claims) => {
            println!("   ✅ Token 有效");
            println!("   用户 ID: {}", claims.user_id);
            println!("   用户名: {}", claims.username);
            println!("   角色: {:?}\n", claims.roles);
        }
        Err(e) => {
            println!("   ❌ {}\n", e);
        }
    }

    // 3. 验证无效 Token
    println!("🔍 验证无效 Token...");
    match auth_service.validate_token("invalid.token.here") {
        Ok(_) => println!("   Token 有效\n"),
        Err(e) => println!("   ❌ {}\n", e),
    }

    // 4. 使用 Refresh Token 获取新的 Access Token
    println!("🔄 刷新 Token...");
    match auth_service.refresh(&tokens.refresh_token).await {
        Ok(result) => {
            println!("   ✅ Token 刷新成功");
            println!("   新 Access Token: {}...", &result.access_token[..50]);
            if let Some(new_rt) = &result.new_refresh_token {
                println!("   新 Refresh Token: {}...", &new_rt[..20]);
            }
            println!();

            // 验证新的 Access Token
            println!("🔍 验证新的 Access Token...");
            match auth_service.validate_token(&result.access_token) {
                Ok(claims) => {
                    println!("   ✅ 新 Token 有效, 用户: {}\n", claims.username);
                }
                Err(e) => {
                    println!("   ❌ {}\n", e);
                }
            }
        }
        Err(e) => {
            println!("   ❌ {}\n", e);
        }
    }

    // 5. 尝试重用旧的 Refresh Token
    println!("🔄 尝试重用旧的 Refresh Token...");
    match auth_service.refresh(&tokens.refresh_token).await {
        Ok(_) => println!("   Token 刷新成功\n"),
        Err(e) => println!("   ❌ {}\n", e),
    }

    // 6. 演示生成新的 JWT
    println!("📦 生成另一个 JWT...");
    let another_token = JwtBuilder::new()
        .subject("user_002")
        .issuer("authrs-example")
        .expires_in_hours(1)
        .build_with_secret(JWT_SECRET);

    match another_token {
        Ok(token) => {
            println!("   ✅ JWT 生成成功");
            println!("   Token 长度: {}", token.len());
        }
        Err(e) => {
            println!("   ❌ 生成失败: {}", e);
        }
    }

    println!("\n=== 示例结束 ===");
}
