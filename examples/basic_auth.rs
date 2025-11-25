//! 基本认证示例
//!
//! 展示如何使用 AuthRS 实现用户注册和登录流程。
//!
//! 运行: cargo run --example basic_auth --features full

use authrs::{
    hash_password,
    password::validate_password_strength,
    security::account::{LoginAttemptTracker, LoginCheckResult},
    token::session::{SessionConfig, SessionManager},
    verify_password,
};
use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

/// 简单的用户存储（实际应用中应使用数据库）
struct UserStore {
    users: HashMap<String, User>,
}

struct User {
    id: String,
    username: String,
    password_hash: String,
}

impl UserStore {
    fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }

    fn register(&mut self, username: &str, password: &str) -> Result<&User, String> {
        // 1. 检查用户名是否已存在
        if self.users.contains_key(username) {
            return Err("用户名已存在".to_string());
        }

        // 2. 验证密码强度
        validate_password_strength(password).map_err(|e| format!("密码强度不足: {}", e))?;

        // 3. 哈希密码
        let password_hash = hash_password(password).map_err(|e| format!("密码哈希失败: {}", e))?;

        // 4. 创建用户
        let user_id = format!("user_{}", self.users.len() + 1);
        let user = User {
            id: user_id.clone(),
            username: username.to_string(),
            password_hash,
        };

        self.users.insert(username.to_string(), user);
        Ok(self.users.get(username).unwrap())
    }

    fn find_by_username(&self, username: &str) -> Option<&User> {
        self.users.get(username)
    }
}

/// 认证服务
struct AuthService {
    user_store: UserStore,
    session_manager: SessionManager,
    login_tracker: LoginAttemptTracker,
}

impl AuthService {
    fn new() -> Self {
        let session_config = SessionConfig::new().with_max_sessions_per_user(3);

        Self {
            user_store: UserStore::new(),
            session_manager: SessionManager::new(session_config),
            login_tracker: LoginAttemptTracker::with_default_config(),
        }
    }

    /// 用户注册
    fn register(&mut self, username: &str, password: &str) -> Result<String, String> {
        let user = self.user_store.register(username, password)?;
        println!("✅ 用户注册成功: {} (ID: {})", user.username, user.id);
        Ok(user.id.clone())
    }

    /// 用户登录
    fn login(
        &mut self,
        username: &str,
        password: &str,
        ip: Option<IpAddr>,
    ) -> Result<String, String> {
        // 1. 检查是否允许登录（防暴力破解）
        match self.login_tracker.check_login_allowed(username, ip) {
            LoginCheckResult::Allowed => {}
            LoginCheckResult::Locked { reason, remaining } => {
                return Err(format!(
                    "账户已锁定: {:?}, 剩余时间: {:?}",
                    reason, remaining
                ));
            }
            LoginCheckResult::DelayRequired { wait_time } => {
                return Err(format!("请等待 {:?} 后重试", wait_time));
            }
            LoginCheckResult::IpBanned { ip } => {
                return Err(format!("IP {} 已被封禁", ip));
            }
        }

        // 2. 查找用户
        let user = match self.user_store.find_by_username(username) {
            Some(u) => u,
            None => {
                self.login_tracker.record_failed_attempt(username, ip);
                return Err("用户名或密码错误".to_string());
            }
        };

        // 3. 验证密码
        let is_valid = verify_password(password, &user.password_hash)
            .map_err(|e| format!("密码验证失败: {}", e))?;

        if !is_valid {
            self.login_tracker.record_failed_attempt(username, ip);
            return Err("用户名或密码错误".to_string());
        }

        // 4. 记录成功登录
        self.login_tracker.record_successful_login(username, ip);

        // 5. 创建 Session
        let session = self
            .session_manager
            .create(&user.id)
            .map_err(|e| format!("Session 创建失败: {}", e))?;

        println!("✅ 登录成功: {} -> Session ID: {}", username, session.id);
        Ok(session.id)
    }

    /// 验证 Session
    fn validate_session(&self, session_id: &str) -> Option<String> {
        self.session_manager
            .get(session_id)
            .map(|s| s.user_id.clone())
    }

    /// 登出
    fn logout(&self, session_id: &str) -> bool {
        let result = self.session_manager.destroy(session_id);
        if result.is_ok() {
            println!("✅ 登出成功: Session {}", session_id);
        }
        result.is_ok()
    }
}

fn main() {
    println!("=== AuthRS 基本认证示例 ===\n");

    let mut auth = AuthService::new();

    // 1. 注册用户
    println!("📝 注册用户...");
    match auth.register("alice", "AliceSecure#2024!") {
        Ok(id) => println!("   用户 ID: {}\n", id),
        Err(e) => println!("   注册失败: {}\n", e),
    }

    // 2. 尝试使用弱密码注册
    println!("📝 尝试使用弱密码注册...");
    match auth.register("bob", "weak") {
        Ok(_) => println!("   注册成功\n"),
        Err(e) => println!("   ❌ {}\n", e),
    }

    // 3. 登录
    println!("🔐 登录...");
    let session_id = match auth.login(
        "alice",
        "AliceSecure#2024!",
        Some(IpAddr::from_str("192.168.1.100").unwrap()),
    ) {
        Ok(sid) => {
            println!("   Session: {}\n", sid);
            sid
        }
        Err(e) => {
            println!("   登录失败: {}\n", e);
            return;
        }
    };

    // 4. 验证 Session
    println!("🔍 验证 Session...");
    match auth.validate_session(&session_id) {
        Some(user_id) => println!("   ✅ Session 有效, 用户: {}\n", user_id),
        None => println!("   ❌ Session 无效\n"),
    }

    // 5. 尝试错误密码登录
    println!("🔐 尝试错误密码登录...");
    for i in 1..=3 {
        match auth.login(
            "alice",
            "wrong_password",
            Some(IpAddr::from_str("192.168.1.200").unwrap()),
        ) {
            Ok(_) => println!("   登录成功"),
            Err(e) => println!("   尝试 {}: {}", i, e),
        }
    }
    println!();

    // 6. 登出
    println!("🚪 登出...");
    auth.logout(&session_id);

    // 7. 登出后验证 Session
    println!("\n🔍 登出后验证 Session...");
    match auth.validate_session(&session_id) {
        Some(_) => println!("   Session 仍然有效"),
        None => println!("   ✅ Session 已失效"),
    }

    println!("\n=== 示例结束 ===");
}
