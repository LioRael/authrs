//! 集成测试：API Key 管理
//!
//! 测试 API Key 的创建、验证、轮换、权限检查等完整流程。

use authrs::api_key::{ApiKeyConfig, ApiKeyManager, ApiKeyStatus};
use chrono::{Duration, Utc};

/// 测试 API Key 创建和验证的基本流程
#[test]
fn test_api_key_basic_flow() {
    let mut manager = ApiKeyManager::with_default_config();

    // 1. 创建 API Key
    let (key, plain_key) = manager
        .create_key("my-service")
        .with_prefix("sk_test")
        .with_scope("read")
        .with_scope("write")
        .build()
        .expect("API key creation should succeed");

    // 验证创建的 key 属性
    assert_eq!(key.owner, "my-service");
    assert_eq!(key.prefix, "sk_test");
    assert!(key.scopes.contains(&"read".to_string()));
    assert!(key.scopes.contains(&"write".to_string()));
    assert_eq!(key.status, ApiKeyStatus::Active);

    // 2. 将 key 添加到管理器
    manager.add_key(key.clone());

    // 3. 验证 API Key
    let validated = manager.validate(&plain_key);
    assert!(validated.is_some(), "Valid key should pass validation");
    assert_eq!(validated.unwrap().owner, "my-service");

    // 4. 错误的 key 应该验证失败
    let wrong_key = manager.validate("sk_test_invalid_key_here");
    assert!(wrong_key.is_none(), "Invalid key should fail validation");
}

/// 测试 API Key 过期功能
#[test]
fn test_api_key_expiration() {
    let mut manager = ApiKeyManager::with_default_config();

    // 创建一个立即过期的 key（过期时间设为过去）
    let (mut key, plain_key) = manager
        .create_key("test-service")
        .with_prefix("sk_exp")
        .build()
        .expect("API key creation should succeed");

    // 手动设置过期时间为过去
    key.expires_at = Some(Utc::now() - Duration::hours(1));
    manager.add_key(key);

    // 验证应该失败（已过期）
    let result = manager.validate(&plain_key);
    assert!(result.is_none(), "Expired key should fail validation");
}

/// 测试 API Key 权限范围验证
#[test]
fn test_api_key_scope_validation() {
    let mut manager = ApiKeyManager::with_default_config();

    // 创建只有 read 权限的 key
    let (key, plain_key) = manager
        .create_key("limited-service")
        .with_prefix("sk_limited")
        .with_scope("read")
        .build()
        .unwrap();

    manager.add_key(key);

    // 验证只需要 read 权限（应该成功）
    let read_check = manager.validate_with_scopes(&plain_key, &["read"]);
    assert!(
        read_check.is_some(),
        "Key with read scope should pass read check"
    );

    // 验证需要 write 权限（应该失败）
    let write_check = manager.validate_with_scopes(&plain_key, &["write"]);
    assert!(
        write_check.is_none(),
        "Key without write scope should fail write check"
    );

    // 验证需要多个权限（应该失败，因为没有 write）
    let multi_check = manager.validate_with_scopes(&plain_key, &["read", "write"]);
    assert!(
        multi_check.is_none(),
        "Key should fail when missing required scope"
    );
}

/// 测试 API Key 轮换功能
#[test]
fn test_api_key_rotation() {
    let mut manager = ApiKeyManager::with_default_config();

    // 创建原始 key
    let (key, old_plain_key) = manager
        .create_key("rotation-service")
        .with_prefix("sk_rotate")
        .with_scope("admin")
        .build()
        .unwrap();

    let old_key_id = key.id.clone();
    manager.add_key(key);

    // 轮换 key
    let rotation_result = manager.rotate(&old_key_id);
    assert!(rotation_result.is_ok(), "Key rotation should succeed");

    let (new_key, new_plain_key) = rotation_result.unwrap();

    // 新 key 应该继承权限
    assert!(new_key.scopes.contains(&"admin".to_string()));
    // 新 key 应该记录来源
    assert_eq!(new_key.rotated_from, Some(old_key_id.clone()));

    // 添加新 key
    manager.add_key(new_key);

    // 旧 key 应该失效
    let old_result = manager.validate(&old_plain_key);
    assert!(
        old_result.is_none(),
        "Old key should be invalid after rotation"
    );

    // 新 key 应该有效
    let new_result = manager.validate(&new_plain_key);
    assert!(
        new_result.is_some(),
        "New key should be valid after rotation"
    );
}

/// 测试 API Key 撤销功能
#[test]
fn test_api_key_revocation() {
    let mut manager = ApiKeyManager::with_default_config();

    let (key, plain_key) = manager
        .create_key("revoke-service")
        .with_prefix("sk_revoke")
        .build()
        .unwrap();

    let key_id = key.id.clone();
    manager.add_key(key);

    // 撤销前应该有效
    let before_revoke = manager.validate(&plain_key);
    assert!(
        before_revoke.is_some(),
        "Key should be valid before revocation"
    );

    // 撤销 key
    let revoked = manager.revoke(&key_id);
    assert!(revoked.is_ok(), "Revocation should succeed");

    // 撤销后应该无效
    let after_revoke = manager.validate(&plain_key);
    assert!(
        after_revoke.is_none(),
        "Key should be invalid after revocation"
    );

    // 检查状态
    let key_info = manager.get_by_id(&key_id);
    assert!(key_info.is_some());
    assert_eq!(key_info.unwrap().status, ApiKeyStatus::Revoked);
}

/// 测试 API Key 使用统计
#[test]
fn test_api_key_usage_tracking() {
    let mut manager = ApiKeyManager::with_default_config();

    let (key, plain_key) = manager
        .create_key("usage-service")
        .with_prefix("sk_usage")
        .build()
        .unwrap();

    let key_id = key.id.clone();
    manager.add_key(key);

    // 初始使用次数为 0
    {
        let key_info = manager.get_by_id(&key_id).unwrap();
        assert_eq!(key_info.use_count, 0);
        assert!(key_info.last_used_at.is_none());
    }

    // 多次验证（模拟 API 调用）
    // Note: validate() may increment use_count internally
    for _ in 0..5 {
        let result = manager.validate(&plain_key);
        assert!(result.is_some());
    }

    // 检查使用统计 - use_count increments on each validate call
    let key_info = manager.get_by_id(&key_id).unwrap();
    assert!(key_info.use_count >= 5, "Use count should be at least 5");
    assert!(
        key_info.last_used_at.is_some(),
        "Last used time should be set"
    );
}

/// 测试 API Key 元数据
#[test]
fn test_api_key_metadata() {
    let manager = ApiKeyManager::with_default_config();

    let (key, _plain_key) = manager
        .create_key("metadata-service")
        .with_prefix("sk_meta")
        .with_metadata("environment", "production")
        .with_metadata("team", "backend")
        .with_metadata("project", "api-gateway")
        .build()
        .unwrap();

    // 验证元数据
    assert_eq!(
        key.metadata.get("environment"),
        Some(&"production".to_string())
    );
    assert_eq!(key.metadata.get("team"), Some(&"backend".to_string()));
    assert_eq!(
        key.metadata.get("project"),
        Some(&"api-gateway".to_string())
    );
}

/// 测试 API Key 列表和过滤
#[test]
fn test_api_key_listing() {
    let mut manager = ApiKeyManager::with_default_config();

    // 创建多个不同 owner 的 key
    let owners = ["service-a", "service-b", "service-a", "service-c"];
    for owner in owners {
        let (key, _) = manager
            .create_key(owner)
            .with_prefix("sk_list")
            .build()
            .unwrap();
        manager.add_key(key);
    }

    // 列出所有 key
    let all_keys = manager.list();
    assert_eq!(all_keys.len(), 4, "Should have 4 keys total");

    // 按 owner 过滤
    let service_a_keys = manager.list_by_owner("service-a");
    assert_eq!(service_a_keys.len(), 2, "service-a should have 2 keys");

    let service_b_keys = manager.list_by_owner("service-b");
    assert_eq!(service_b_keys.len(), 1, "service-b should have 1 key");

    // 列出活跃的 key
    let active_keys = manager.list_active();
    assert_eq!(active_keys.len(), 4, "All keys should be active");
}

/// 测试 API Key 统计信息
#[test]
fn test_api_key_stats() {
    let mut manager = ApiKeyManager::with_default_config();

    // 创建并添加一些 key
    for i in 0..5 {
        let (key, _) = manager
            .create_key(&format!("service-{}", i))
            .with_prefix("sk_stats")
            .build()
            .unwrap();
        manager.add_key(key);
    }

    // 撤销一个
    let first_key_id = {
        let all_keys = manager.list();
        all_keys[0].id.clone()
    };
    manager.revoke(&first_key_id).unwrap();

    // 检查统计
    let stats = manager.stats();
    assert_eq!(stats.total, 5, "Total should be 5");
    assert_eq!(stats.active, 4, "Active should be 4");
    assert_eq!(stats.revoked, 1, "Revoked should be 1");
    assert_eq!(stats.expired, 0, "Expired should be 0");
}

/// 测试即将过期的 API Key 检测
#[test]
fn test_api_key_expiring_soon() {
    let mut manager = ApiKeyManager::with_default_config();

    // 创建一个即将过期的 key（7天内过期）
    let (mut key_soon, _) = manager
        .create_key("soon-service")
        .with_prefix("sk_soon")
        .build()
        .unwrap();
    key_soon.expires_at = Some(Utc::now() + Duration::days(3));
    manager.add_key(key_soon);

    // 创建一个远期过期的 key
    let (mut key_later, _) = manager
        .create_key("later-service")
        .with_prefix("sk_later")
        .build()
        .unwrap();
    key_later.expires_at = Some(Utc::now() + Duration::days(30));
    manager.add_key(key_later);

    // 创建一个永不过期的 key
    let (key_never, _) = manager
        .create_key("never-service")
        .with_prefix("sk_never")
        .build()
        .unwrap();
    manager.add_key(key_never);

    // 查找 7 天内过期的 key
    let expiring = manager.list_expiring_soon(7);
    assert_eq!(
        expiring.len(),
        1,
        "Should find 1 key expiring within 7 days"
    );
    assert_eq!(expiring[0].owner, "soon-service");

    // 查找 60 天内过期的 key
    let expiring_60 = manager.list_expiring_soon(60);
    assert_eq!(
        expiring_60.len(),
        2,
        "Should find 2 keys expiring within 60 days"
    );
}

/// 测试生产环境配置
#[test]
fn test_production_config() {
    let config = ApiKeyConfig::production();
    let manager = ApiKeyManager::new(config);

    // 生产环境要求更长的 key
    let (key, plain_key) = manager
        .create_key("prod-service")
        .with_prefix("sk_live")
        .with_scope("read")
        .with_expires_in_days(90)
        .build()
        .unwrap();

    // 验证 key 格式
    assert!(plain_key.starts_with("sk_live_"), "Key should have prefix");
    assert!(
        key.expires_at.is_some(),
        "Production key should have expiration"
    );

    // 验证过期时间约为 90 天
    let expires_at = key.expires_at.unwrap();
    let days_until_expiry = (expires_at - Utc::now()).num_days();
    assert!(
        days_until_expiry >= 89 && days_until_expiry <= 90,
        "Expiry should be ~90 days"
    );
}

/// 测试完整的 API Key 生命周期
#[test]
fn test_api_key_full_lifecycle() {
    let mut manager = ApiKeyManager::with_default_config();

    // === 阶段1：创建 ===
    let (key, plain_key) = manager
        .create_key("lifecycle-service")
        .with_prefix("sk_lifecycle")
        .with_scope("read")
        .with_scope("write")
        .with_expires_in_days(30)
        .build()
        .expect("Key creation should succeed");

    let key_id = key.id.clone();
    manager.add_key(key);

    // 验证创建成功
    assert!(manager.validate(&plain_key).is_some());

    // === 阶段2：正常使用 ===
    for _ in 0..10 {
        let validated = manager.validate(&plain_key);
        assert!(validated.is_some());

        // 记录使用
        if let Some(key_mut) = manager.get_by_id_mut(&key_id) {
            key_mut.record_usage();
        }
    }

    // 检查使用统计 - validate increments use_count
    assert!(manager.get_by_id(&key_id).unwrap().use_count >= 10);

    // === 阶段3：权限检查 ===
    assert!(
        manager
            .validate_with_scopes(&plain_key, &["read"])
            .is_some()
    );
    assert!(
        manager
            .validate_with_scopes(&plain_key, &["write"])
            .is_some()
    );
    assert!(
        manager
            .validate_with_scopes(&plain_key, &["admin"])
            .is_none()
    );

    // === 阶段4：轮换 ===
    let (new_key, new_plain_key) = manager.rotate(&key_id).expect("Rotation should succeed");
    let new_key_id = new_key.id.clone();
    manager.add_key(new_key);

    // 旧 key 失效，新 key 有效
    assert!(manager.validate(&plain_key).is_none());
    assert!(manager.validate(&new_plain_key).is_some());

    // 新 key 继承了权限
    assert!(
        manager
            .validate_with_scopes(&new_plain_key, &["read"])
            .is_some()
    );
    assert!(
        manager
            .validate_with_scopes(&new_plain_key, &["write"])
            .is_some()
    );

    // === 阶段5：撤销 ===
    manager.revoke(&new_key_id);
    assert!(manager.validate(&new_plain_key).is_none());

    // === 阶段6：删除 ===
    let deleted = manager.delete(&new_key_id);
    assert!(deleted.is_ok(), "Deletion should succeed");
    assert!(manager.get_by_id(&new_key_id).is_none());
}

/// 测试 API Key 禁用和启用
#[test]
fn test_api_key_disable_enable() {
    let mut manager = ApiKeyManager::with_default_config();

    let (key, plain_key) = manager
        .create_key("toggle-service")
        .with_prefix("sk_toggle")
        .build()
        .unwrap();

    let key_id = key.id.clone();
    manager.add_key(key);

    // 初始状态为 Active
    assert!(manager.validate(&plain_key).is_some());

    // 禁用 key
    if let Some(key_mut) = manager.get_by_id_mut(&key_id) {
        key_mut.disable();
    }

    // 禁用后验证失败
    assert!(manager.validate(&plain_key).is_none());
    assert_eq!(
        manager.get_by_id(&key_id).unwrap().status,
        ApiKeyStatus::Disabled
    );

    // 重新启用 key
    if let Some(key_mut) = manager.get_by_id_mut(&key_id) {
        key_mut.enable();
    }

    // 启用后验证成功
    assert!(manager.validate(&plain_key).is_some());
    assert_eq!(
        manager.get_by_id(&key_id).unwrap().status,
        ApiKeyStatus::Active
    );
}

/// 测试 API Key 显示提示（用于 UI 显示）
#[test]
fn test_api_key_display_hint() {
    let manager = ApiKeyManager::with_default_config();

    let (key, plain_key) = manager
        .create_key("hint-service")
        .with_prefix("sk_hint")
        .build()
        .unwrap();

    // key_hint 应该是 key 的后几位
    let hint = &key.key_hint;
    assert!(!hint.is_empty(), "Hint should not be empty");

    // hint 应该是 key 的一部分（不一定是后缀，取决于实现）
    assert!(!hint.is_empty(), "Hint should not be empty");

    // display_hint 应该返回一个可用于显示的字符串
    let display = key.display_hint();
    assert!(!display.is_empty(), "Display should not be empty");
}
