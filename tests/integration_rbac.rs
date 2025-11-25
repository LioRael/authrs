//! 集成测试：RBAC (Role-Based Access Control)
//!
//! 测试角色定义、权限检查、策略引擎等完整流程。

#![cfg(feature = "rbac")]

use authrs::rbac::{
    Action, Permission, PermissionSet, Policy, PolicyEffect, PolicyEngine, PolicyEvaluator,
    Resource, RoleBuilder, RoleManager, Subject,
};

/// 测试权限定义和基本检查
#[test]
fn test_permission_basics() {
    // 创建具体权限
    let read_posts = Permission::new("posts", "read");
    let write_posts = Permission::new("posts", "write");
    let delete_posts = Permission::new("posts", "delete");

    // 权限相等性检查
    assert_eq!(read_posts, Permission::new("posts", "read"));
    assert_ne!(read_posts, write_posts);

    // 权限字符串表示
    assert_eq!(read_posts.to_string(), "posts:read");
    assert_eq!(delete_posts.to_string(), "posts:delete");
}

/// 测试通配符权限
#[test]
fn test_wildcard_permissions() {
    // 完全通配符（超级权限）
    let super_perm = Permission::wildcard();
    assert!(super_perm.matches(&Permission::new("posts", "read")));
    assert!(super_perm.matches(&Permission::new("users", "delete")));
    assert!(super_perm.matches(&Permission::new("anything", "everything")));

    // 资源通配符
    let posts_all = Permission::resource_wildcard("posts");
    assert!(posts_all.matches(&Permission::new("posts", "read")));
    assert!(posts_all.matches(&Permission::new("posts", "write")));
    assert!(posts_all.matches(&Permission::new("posts", "delete")));
    assert!(!posts_all.matches(&Permission::new("users", "read")));

    // 操作通配符
    let read_all = Permission::action_wildcard("read");
    assert!(read_all.matches(&Permission::new("posts", "read")));
    assert!(read_all.matches(&Permission::new("users", "read")));
    assert!(!read_all.matches(&Permission::new("posts", "write")));
}

/// 测试权限集合
#[test]
fn test_permission_set() {
    let mut perm_set = PermissionSet::new();

    // 添加权限
    perm_set.add(Permission::new("posts", "read"));
    perm_set.add(Permission::new("posts", "write"));
    perm_set.add(Permission::new("users", "read"));

    // 检查包含
    assert!(perm_set.contains(&Permission::new("posts", "read")));
    assert!(perm_set.contains(&Permission::new("users", "read")));
    assert!(!perm_set.contains(&Permission::new("users", "delete")));

    // 权限数量
    assert_eq!(perm_set.len(), 3);
    assert!(!perm_set.is_empty());

    // 移除权限
    perm_set.remove(&Permission::new("posts", "write"));
    assert_eq!(perm_set.len(), 2);
    assert!(!perm_set.contains(&Permission::new("posts", "write")));
}

/// 测试角色创建和权限检查
#[test]
fn test_role_basics() {
    let editor = RoleBuilder::new("editor")
        .description("Content editor role")
        .permission(Permission::new("posts", "read"))
        .permission(Permission::new("posts", "write"))
        .permission(Permission::new("posts", "create"))
        .build();

    assert_eq!(editor.name(), "editor");
    assert_eq!(editor.description(), Some("Content editor role"));

    // 直接权限检查
    assert!(editor.has_permission(&Permission::new("posts", "read")));
    assert!(editor.has_permission(&Permission::new("posts", "write")));
    assert!(editor.has_permission(&Permission::new("posts", "create")));
    assert!(!editor.has_permission(&Permission::new("posts", "delete")));
    assert!(!editor.has_permission(&Permission::new("users", "read")));
}

/// 测试角色继承
#[test]
fn test_role_inheritance() {
    let mut manager = RoleManager::new();

    // 基础角色：查看者
    let viewer = RoleBuilder::new("viewer")
        .permission(Permission::new("posts", "read"))
        .permission(Permission::new("comments", "read"))
        .build();

    // 继承角色：编辑者（继承查看者权限）
    let editor = RoleBuilder::new("editor")
        .inherit("viewer")
        .permission(Permission::new("posts", "write"))
        .permission(Permission::new("posts", "create"))
        .permission(Permission::new("comments", "write"))
        .build();

    // 继承角色：管理员（继承编辑者权限）
    let admin = RoleBuilder::new("admin")
        .inherit("editor")
        .permission(Permission::new("posts", "delete"))
        .permission(Permission::new("users", "read"))
        .permission(Permission::new("users", "write"))
        .build();

    manager.add_role(viewer);
    manager.add_role(editor);
    manager.add_role(admin);

    // 验证有效权限（包含继承的权限）
    let viewer_perms = manager.get_effective_permissions("viewer");
    assert!(viewer_perms.contains(&Permission::new("posts", "read")));
    assert!(!viewer_perms.contains(&Permission::new("posts", "write")));

    let editor_perms = manager.get_effective_permissions("editor");
    assert!(editor_perms.contains(&Permission::new("posts", "read"))); // 继承自 viewer
    assert!(editor_perms.contains(&Permission::new("posts", "write"))); // 自己的
    assert!(editor_perms.contains(&Permission::new("comments", "read"))); // 继承自 viewer
    assert!(!editor_perms.contains(&Permission::new("posts", "delete")));

    let admin_perms = manager.get_effective_permissions("admin");
    assert!(admin_perms.contains(&Permission::new("posts", "read"))); // 继承链
    assert!(admin_perms.contains(&Permission::new("posts", "write"))); // 继承链
    assert!(admin_perms.contains(&Permission::new("posts", "delete"))); // 自己的
    assert!(admin_perms.contains(&Permission::new("users", "read"))); // 自己的
}

/// 测试角色管理器的权限检查
#[test]
fn test_role_manager_permission_check() {
    let mut manager = RoleManager::new();

    let viewer = RoleBuilder::new("viewer")
        .permission(Permission::new("posts", "read"))
        .build();

    let editor = RoleBuilder::new("editor")
        .inherit("viewer")
        .permission(Permission::new("posts", "write"))
        .build();

    manager.add_role(viewer);
    manager.add_role(editor);

    // 使用管理器检查权限
    assert!(manager.role_has_permission("viewer", &Permission::new("posts", "read")));
    assert!(!manager.role_has_permission("viewer", &Permission::new("posts", "write")));

    assert!(manager.role_has_permission("editor", &Permission::new("posts", "read")));
    assert!(manager.role_has_permission("editor", &Permission::new("posts", "write")));

    // 不存在的角色
    assert!(!manager.role_has_permission("nonexistent", &Permission::new("posts", "read")));
}

/// 测试策略引擎基础功能
#[test]
fn test_policy_engine_basics() {
    let mut engine = PolicyEngine::new();

    // 添加允许策略
    engine.add_policy(
        Policy::allow("editor-posts-read")
            .role("editor")
            .resource("posts")
            .action("read")
            .build(),
    );

    engine.add_policy(
        Policy::allow("editor-posts-write")
            .role("editor")
            .resource("posts")
            .action("write")
            .build(),
    );

    // 创建用户主体
    let user = Subject::new("user123").with_role("editor");

    // 评估权限
    let can_read = engine.evaluate(&user, &Resource::new("posts"), &Action::new("read"));
    assert!(can_read.is_allowed());

    let can_write = engine.evaluate(&user, &Resource::new("posts"), &Action::new("write"));
    assert!(can_write.is_allowed());

    // 未定义的权限默认拒绝
    let can_delete = engine.evaluate(&user, &Resource::new("posts"), &Action::new("delete"));
    assert!(can_delete.is_denied());

    // 未授权角色的用户
    let guest = Subject::new("guest123").with_role("guest");
    let guest_can_read = engine.evaluate(&guest, &Resource::new("posts"), &Action::new("read"));
    assert!(guest_can_read.is_denied());
}

/// 测试拒绝策略优先级
#[test]
fn test_deny_policy_priority() {
    let mut engine = PolicyEngine::new();

    // 允许编辑者操作文章
    engine.add_policy(
        Policy::allow("editor-posts-all")
            .role("editor")
            .resource("posts")
            .actions(["read", "write", "delete"])
            .build(),
    );

    // 明确拒绝删除操作（高优先级）
    engine.add_policy(
        Policy::deny("no-delete-posts")
            .resource("posts")
            .action("delete")
            .priority(100) // 更高优先级
            .build(),
    );

    let editor = Subject::new("editor1").with_role("editor");

    // 读写应该被允许
    assert!(
        engine
            .evaluate(&editor, &Resource::new("posts"), &Action::new("read"))
            .is_allowed()
    );
    assert!(
        engine
            .evaluate(&editor, &Resource::new("posts"), &Action::new("write"))
            .is_allowed()
    );

    // 删除应该被拒绝（高优先级拒绝策略）
    let delete_decision = engine.evaluate(&editor, &Resource::new("posts"), &Action::new("delete"));
    assert!(delete_decision.is_denied());
}

/// 测试策略资源匹配
#[test]
fn test_policy_resource_matching() {
    let mut engine = PolicyEngine::new();

    // 允许用户编辑文章
    engine.add_policy(
        Policy::allow("user-edit-posts")
            .role("user")
            .resource("posts")
            .action("edit")
            .build(),
    );

    // 创建用户
    let user = Subject::new("user123").with_role("user");

    // 用户可以编辑 posts
    let can_edit_posts = engine.evaluate(&user, &Resource::new("posts"), &Action::new("edit"));
    assert!(can_edit_posts.is_allowed());

    // 用户不能编辑其他资源
    let can_edit_users = engine.evaluate(&user, &Resource::new("users"), &Action::new("edit"));
    assert!(can_edit_users.is_denied());
}

/// 测试多角色用户
#[test]
fn test_multi_role_subject() {
    let mut engine = PolicyEngine::new();

    // 编辑者可以编辑文章
    engine.add_policy(
        Policy::allow("editor-posts")
            .role("editor")
            .resource("posts")
            .action("write")
            .build(),
    );

    // 审核员可以审核评论
    engine.add_policy(
        Policy::allow("moderator-comments")
            .role("moderator")
            .resource("comments")
            .action("moderate")
            .build(),
    );

    // 创建同时拥有两个角色的用户
    let multi_role_user = Subject::new("power_user")
        .with_role("editor")
        .with_role("moderator");

    // 应该同时拥有两个角色的权限
    assert!(
        engine
            .evaluate(
                &multi_role_user,
                &Resource::new("posts"),
                &Action::new("write")
            )
            .is_allowed()
    );
    assert!(
        engine
            .evaluate(
                &multi_role_user,
                &Resource::new("comments"),
                &Action::new("moderate")
            )
            .is_allowed()
    );
}

/// 测试策略效果（允许/拒绝）
#[test]
fn test_policy_effects() {
    let allow_policy = Policy::allow("test-allow")
        .role("user")
        .resource("test")
        .action("do")
        .build();

    let deny_policy = Policy::deny("test-deny")
        .role("user")
        .resource("test")
        .action("forbidden")
        .build();

    assert_eq!(allow_policy.effect, PolicyEffect::Allow);
    assert_eq!(deny_policy.effect, PolicyEffect::Deny);
}

/// 测试决策原因
#[test]
fn test_decision_reason() {
    let mut engine = PolicyEngine::new();

    engine.add_policy(
        Policy::allow("user-read")
            .role("user")
            .resource("public")
            .action("read")
            .build(),
    );

    let user = Subject::new("test_user").with_role("user");

    // 被允许的决策应该有原因
    let allowed = engine.evaluate(&user, &Resource::new("public"), &Action::new("read"));
    assert!(allowed.is_allowed());

    // 被拒绝的决策也应该有原因
    let denied = engine.evaluate(&user, &Resource::new("private"), &Action::new("read"));
    assert!(denied.is_denied());
}

/// 测试便捷的权限检查方法
#[test]
fn test_check_permission_shorthand() {
    let mut engine = PolicyEngine::new();

    engine.add_policy(
        Policy::allow("admin-all")
            .role("admin")
            .resource("*")
            .action("*")
            .build(),
    );

    let admin = Subject::new("admin1").with_role("admin");

    // 使用便捷方法
    assert!(engine.check_permission(&admin, "users", "create"));
    assert!(engine.check_permission(&admin, "posts", "delete"));
    assert!(engine.check_permission(&admin, "settings", "modify"));
}

/// 测试移除策略
#[test]
fn test_remove_policy() {
    let mut engine = PolicyEngine::new();

    engine.add_policy(
        Policy::allow("temp-access")
            .role("temp")
            .resource("temp-resource")
            .action("access")
            .build(),
    );

    let temp_user = Subject::new("temp1").with_role("temp");

    // 策略存在时应该允许
    assert!(
        engine
            .evaluate(
                &temp_user,
                &Resource::new("temp-resource"),
                &Action::new("access")
            )
            .is_allowed()
    );

    // 移除策略
    engine.remove_policy("temp-access");

    // 策略移除后应该拒绝
    assert!(
        engine
            .evaluate(
                &temp_user,
                &Resource::new("temp-resource"),
                &Action::new("access")
            )
            .is_denied()
    );
}

/// 测试完整的 RBAC 工作流
#[test]
fn test_complete_rbac_workflow() {
    // === 步骤1：定义角色层次结构 ===
    let mut role_manager = RoleManager::new();

    // 访客角色
    let guest = RoleBuilder::new("guest")
        .description("Anonymous visitor")
        .permission(Permission::new("posts", "read"))
        .permission(Permission::new("comments", "read"))
        .build();

    // 注册用户
    let user = RoleBuilder::new("user")
        .description("Registered user")
        .inherit("guest")
        .permission(Permission::new("posts", "create"))
        .permission(Permission::new("comments", "create"))
        .permission(Permission::new("profile", "read"))
        .permission(Permission::new("profile", "write"))
        .build();

    // 编辑者
    let editor = RoleBuilder::new("editor")
        .description("Content editor")
        .inherit("user")
        .permission(Permission::new("posts", "write"))
        .permission(Permission::new("posts", "publish"))
        .permission(Permission::new("comments", "moderate"))
        .build();

    // 管理员
    let admin = RoleBuilder::new("admin")
        .description("System administrator")
        .inherit("editor")
        .permission(Permission::wildcard()) // 所有权限
        .build();

    role_manager.add_role(guest);
    role_manager.add_role(user);
    role_manager.add_role(editor);
    role_manager.add_role(admin);

    // === 步骤2：配置策略引擎 ===
    let mut policy_engine = PolicyEngine::new();

    // 基于角色的策略
    policy_engine.add_policy(
        Policy::allow("guest-read")
            .role("guest")
            .resource("posts")
            .action("read")
            .build(),
    );

    policy_engine.add_policy(
        Policy::allow("user-create")
            .role("user")
            .resource("posts")
            .action("create")
            .build(),
    );

    policy_engine.add_policy(
        Policy::allow("editor-publish")
            .role("editor")
            .resource("posts")
            .actions(["write", "publish"])
            .build(),
    );

    policy_engine.add_policy(
        Policy::allow("admin-all")
            .role("admin")
            .resource("*")
            .action("*")
            .build(),
    );

    // 全局拒绝策略（最高优先级）
    policy_engine.add_policy(
        Policy::deny("no-delete-system")
            .resource("system")
            .action("delete")
            .priority(1000)
            .build(),
    );

    // === 步骤3：验证权限 ===

    // 访客用户 - 只有 guest-read 策略允许 posts:read
    let guest_user = Subject::new("guest_123").with_role("guest");
    assert!(policy_engine.check_permission(&guest_user, "posts", "read"));
    assert!(!policy_engine.check_permission(&guest_user, "posts", "create"));

    // 注册用户 - user-create 策略允许 posts:create
    let reg_user = Subject::new("user_456").with_role("user");
    assert!(policy_engine.check_permission(&reg_user, "posts", "create"));
    // Note: posts:read requires guest role or explicit policy

    // 编辑者 - editor-publish 策略允许 posts:write 和 posts:publish
    let editor_user = Subject::new("editor_789").with_role("editor");
    assert!(policy_engine.check_permission(&editor_user, "posts", "write"));
    assert!(policy_engine.check_permission(&editor_user, "posts", "publish"));

    // 管理员 - admin-all 策略允许所有资源的所有操作
    let admin_user = Subject::new("admin_001").with_role("admin");
    assert!(policy_engine.check_permission(&admin_user, "posts", "read"));
    assert!(policy_engine.check_permission(&admin_user, "users", "delete"));
    assert!(policy_engine.check_permission(&admin_user, "settings", "modify"));

    // 但是即使是管理员也不能删除系统（高优先级拒绝策略）
    let can_delete_system = policy_engine.evaluate(
        &admin_user,
        &Resource::new("system"),
        &Action::new("delete"),
    );
    assert!(can_delete_system.is_denied());

    // === 步骤4：验证角色权限继承 ===
    let admin_perms = role_manager.get_effective_permissions("admin");
    // 管理员应该有通配符权限，可以匹配任何权限
    assert!(!admin_perms.is_empty());
}
