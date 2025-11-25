//! API Key 管理示例
//!
//! 展示如何使用 AuthRS 实现 API Key 的创建、验证、权限检查和生命周期管理。
//!
//! 运行: cargo run --example api_keys --features full

use authrs::api_key::{ApiKeyConfig, ApiKeyManager};

/// API Key 服务
struct ApiKeyService {
    manager: ApiKeyManager,
}

impl ApiKeyService {
    fn new() -> Self {
        // 使用生产环境配置
        let config = ApiKeyConfig::production();
        Self {
            manager: ApiKeyManager::new(config),
        }
    }

    /// 为服务创建 API Key
    fn create_key(
        &mut self,
        owner: &str,
        scopes: &[&str],
        expires_in_days: Option<i64>,
    ) -> Result<CreatedKey, String> {
        let mut builder = self.manager.create_key(owner).with_prefix("sk_live");

        // 添加权限范围
        for scope in scopes {
            builder = builder.with_scope(*scope);
        }

        // 设置过期时间
        if let Some(days) = expires_in_days {
            builder = builder.with_expires_in_days(days as u32);
        }

        let (key, plain_key) = builder.build().map_err(|e| format!("创建失败: {}", e))?;

        let key_id = key.id.clone();
        let hint = key.key_hint.clone();

        self.manager.add_key(key);

        Ok(CreatedKey {
            key_id,
            plain_key,
            hint,
        })
    }

    /// 验证 API Key
    fn validate(&mut self, key: &str) -> Option<KeyInfo> {
        self.manager.validate(key).map(|k| KeyInfo {
            key_id: k.id.clone(),
            owner: k.owner.clone(),
            scopes: k.scopes.clone(),
            use_count: k.use_count,
        })
    }

    /// 验证 API Key 并检查权限
    fn validate_with_scopes(&mut self, key: &str, required_scopes: &[&str]) -> Option<KeyInfo> {
        self.manager
            .validate_with_scopes(key, required_scopes)
            .map(|k| KeyInfo {
                key_id: k.id.clone(),
                owner: k.owner.clone(),
                scopes: k.scopes.clone(),
                use_count: k.use_count,
            })
    }

    /// 记录 API Key 使用
    fn record_usage(&mut self, key_id: &str) {
        if let Some(key) = self.manager.get_by_id_mut(key_id) {
            key.record_usage();
        }
    }

    /// 撤销 API Key
    fn revoke(&mut self, key_id: &str) -> bool {
        self.manager.revoke(key_id).is_ok()
    }

    /// 轮换 API Key
    fn rotate(&mut self, key_id: &str) -> Result<CreatedKey, String> {
        let (new_key, plain_key) = self
            .manager
            .rotate(key_id)
            .map_err(|e| format!("轮换失败: {}", e))?;

        let new_key_id = new_key.id.clone();
        let hint = new_key.key_hint.clone();

        self.manager.add_key(new_key);

        Ok(CreatedKey {
            key_id: new_key_id,
            plain_key,
            hint,
        })
    }

    /// 获取统计信息
    fn stats(&self) -> Stats {
        let s = self.manager.stats();
        Stats {
            total: s.total,
            active: s.active,
            expired: s.expired,
            revoked: s.revoked,
        }
    }

    /// 列出某个 owner 的所有 key
    fn list_by_owner(&self, owner: &str) -> Vec<KeySummary> {
        self.manager
            .list_by_owner(owner)
            .into_iter()
            .map(|k| KeySummary {
                key_id: k.id.clone(),
                hint: k.display_hint(),
                status: format!("{:?}", k.status),
                use_count: k.use_count,
                scopes: k.scopes.clone(),
            })
            .collect()
    }
}

struct CreatedKey {
    key_id: String,
    plain_key: String,
    hint: String,
}

struct KeyInfo {
    key_id: String,
    owner: String,
    scopes: Vec<String>,
    use_count: u64,
}

struct KeySummary {
    key_id: String,
    hint: String,
    status: String,
    use_count: u64,
    scopes: Vec<String>,
}

struct Stats {
    total: usize,
    active: usize,
    expired: usize,
    revoked: usize,
}

fn main() {
    println!("=== AuthRS API Key 管理示例 ===\n");

    let mut api_service = ApiKeyService::new();

    // ===== 创建 API Key =====
    println!("🔑 创建 API Key...\n");

    // 创建完整权限的 Key
    let admin_key =
        match api_service.create_key("admin-service", &["read", "write", "delete"], Some(90)) {
            Ok(k) => {
                println!("   ✅ 管理员 Key 创建成功");
                println!("   Key ID: {}", k.key_id);
                println!("   完整 Key: {} (请妥善保存)", k.plain_key);
                println!("   提示: ****{}", k.hint);
                println!();
                k
            }
            Err(e) => {
                println!("   ❌ 创建失败: {}\n", e);
                return;
            }
        };

    // 创建只读 Key
    let readonly_key = match api_service.create_key("analytics-service", &["read"], Some(30)) {
        Ok(k) => {
            println!("   ✅ 只读 Key 创建成功");
            println!("   Key ID: {}", k.key_id);
            println!("   完整 Key: {}", k.plain_key);
            println!();
            k
        }
        Err(e) => {
            println!("   ❌ 创建失败: {}\n", e);
            return;
        }
    };

    // 创建写入 Key
    let write_key = match api_service.create_key("ingestion-service", &["write"], Some(60)) {
        Ok(k) => {
            println!("   ✅ 写入 Key 创建成功");
            println!("   Key ID: {}", k.key_id);
            println!("   完整 Key: {}", k.plain_key);
            println!();
            k
        }
        Err(e) => {
            println!("   ❌ 创建失败: {}\n", e);
            return;
        }
    };

    // ===== 验证 API Key =====
    println!("🔍 验证 API Key...\n");

    // 验证有效的 Key
    match api_service.validate(&admin_key.plain_key) {
        Some(info) => {
            println!("   ✅ 管理员 Key 验证成功");
            println!("   Owner: {}", info.owner);
            println!("   Scopes: {:?}", info.scopes);
            println!();
        }
        None => {
            println!("   ❌ Key 无效\n");
        }
    }

    // 验证无效的 Key
    match api_service.validate("sk_live_invalid_key_12345") {
        Some(_) => println!("   Key 有效\n"),
        None => println!("   ❌ 无效 Key 被正确拒绝\n"),
    }

    // ===== 权限检查 =====
    println!("🛡️  权限检查...\n");

    // 只读 Key 尝试写入权限
    println!("   只读 Key 检查 write 权限:");
    match api_service.validate_with_scopes(&readonly_key.plain_key, &["write"]) {
        Some(_) => println!("   ✅ 权限检查通过"),
        None => println!("   ❌ 权限不足（预期行为）"),
    }
    println!();

    // 只读 Key 检查读取权限
    println!("   只读 Key 检查 read 权限:");
    match api_service.validate_with_scopes(&readonly_key.plain_key, &["read"]) {
        Some(_) => println!("   ✅ 权限检查通过"),
        None => println!("   ❌ 权限不足"),
    }
    println!();

    // 管理员 Key 检查多个权限
    println!("   管理员 Key 检查 read + write + delete 权限:");
    match api_service.validate_with_scopes(&admin_key.plain_key, &["read", "write", "delete"]) {
        Some(_) => println!("   ✅ 权限检查通过"),
        None => println!("   ❌ 权限不足"),
    }
    println!();

    // ===== 使用统计 =====
    println!("📊 使用统计...\n");

    // 模拟多次 API 调用
    for _ in 0..10 {
        if let Some(info) = api_service.validate(&admin_key.plain_key) {
            api_service.record_usage(&info.key_id);
        }
    }

    for _ in 0..5 {
        if let Some(info) = api_service.validate(&readonly_key.plain_key) {
            api_service.record_usage(&info.key_id);
        }
    }

    // 查看使用次数
    if let Some(info) = api_service.validate(&admin_key.plain_key) {
        println!("   管理员 Key 使用次数: {}", info.use_count);
    }
    if let Some(info) = api_service.validate(&readonly_key.plain_key) {
        println!("   只读 Key 使用次数: {}", info.use_count);
    }
    println!();

    // ===== Key 轮换 =====
    println!("🔄 Key 轮换...\n");

    println!("   轮换管理员 Key...");
    match api_service.rotate(&admin_key.key_id) {
        Ok(new_key) => {
            println!("   ✅ 轮换成功");
            println!("   新 Key ID: {}", new_key.key_id);
            println!("   新完整 Key: {}", new_key.plain_key);
            println!();

            // 验证旧 Key 失效
            println!("   验证旧 Key:");
            match api_service.validate(&admin_key.plain_key) {
                Some(_) => println!("   旧 Key 仍然有效"),
                None => println!("   ❌ 旧 Key 已失效（预期行为）"),
            }
            println!();

            // 验证新 Key 有效
            println!("   验证新 Key:");
            match api_service.validate(&new_key.plain_key) {
                Some(info) => {
                    println!("   ✅ 新 Key 有效");
                    println!("   Scopes: {:?}", info.scopes);
                }
                None => println!("   ❌ 新 Key 无效"),
            }
            println!();
        }
        Err(e) => {
            println!("   ❌ 轮换失败: {}\n", e);
        }
    }

    // ===== Key 撤销 =====
    println!("🚫 Key 撤销...\n");

    println!("   撤销写入 Key...");
    if api_service.revoke(&write_key.key_id) {
        println!("   ✅ 撤销成功");

        // 验证撤销后的 Key
        match api_service.validate(&write_key.plain_key) {
            Some(_) => println!("   Key 仍然有效"),
            None => println!("   ❌ Key 已被撤销（预期行为）"),
        }
    } else {
        println!("   ❌ 撤销失败");
    }
    println!();

    // ===== 列出 Key =====
    println!("📋 列出 Key...\n");

    // 为同一个 owner 创建多个 Key
    let _ = api_service.create_key("multi-service", &["read"], None);
    let _ = api_service.create_key("multi-service", &["write"], None);
    let _ = api_service.create_key("multi-service", &["read", "write"], None);

    let keys = api_service.list_by_owner("multi-service");
    println!("   multi-service 的 Key 列表:");
    for (i, key) in keys.iter().enumerate() {
        println!(
            "   {}. {} | 状态: {} | 权限: {:?} | 使用: {} 次",
            i + 1,
            key.hint,
            key.status,
            key.scopes,
            key.use_count
        );
    }
    println!();

    // ===== 统计信息 =====
    println!("📈 统计信息...\n");

    let stats = api_service.stats();
    println!("   总计: {} 个 Key", stats.total);
    println!("   活跃: {} 个", stats.active);
    println!("   过期: {} 个", stats.expired);
    println!("   已撤销: {} 个", stats.revoked);

    println!("\n=== 示例结束 ===");
}
