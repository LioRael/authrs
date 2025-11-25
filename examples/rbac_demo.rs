//! RBAC (角色权限管理) 示例
//!
//! 展示如何使用 AuthRS 实现角色定义、权限检查和策略引擎。
//!
//! 运行: cargo run --example rbac_demo --features rbac

use authrs::rbac::{
    Action, Permission, Policy, PolicyEngine, PolicyEvaluator, Resource, RoleBuilder, RoleManager,
    Subject,
};

/// 演示基本的角色和权限
fn demo_basic_roles() {
    println!("📚 基本角色和权限演示\n");

    // 创建权限
    let read_posts = Permission::new("posts", "read");
    let write_posts = Permission::new("posts", "write");
    let delete_posts = Permission::new("posts", "delete");
    let read_users = Permission::new("users", "read");
    let write_users = Permission::new("users", "write");

    // 创建角色
    let viewer = RoleBuilder::new("viewer")
        .description("只能查看内容的用户")
        .permission(read_posts.clone())
        .build();

    let editor = RoleBuilder::new("editor")
        .description("可以编辑内容的用户")
        .permission(read_posts.clone())
        .permission(write_posts.clone())
        .build();

    let admin = RoleBuilder::new("admin")
        .description("管理员，拥有所有权限")
        .permission(read_posts.clone())
        .permission(write_posts.clone())
        .permission(delete_posts.clone())
        .permission(read_users.clone())
        .permission(write_users.clone())
        .build();

    // 检查权限
    println!("   角色: viewer");
    println!(
        "   - 读取文章: {}",
        bool_emoji(viewer.has_permission(&read_posts))
    );
    println!(
        "   - 编辑文章: {}",
        bool_emoji(viewer.has_permission(&write_posts))
    );
    println!(
        "   - 删除文章: {}",
        bool_emoji(viewer.has_permission(&delete_posts))
    );
    println!();

    println!("   角色: editor");
    println!(
        "   - 读取文章: {}",
        bool_emoji(editor.has_permission(&read_posts))
    );
    println!(
        "   - 编辑文章: {}",
        bool_emoji(editor.has_permission(&write_posts))
    );
    println!(
        "   - 删除文章: {}",
        bool_emoji(editor.has_permission(&delete_posts))
    );
    println!();

    println!("   角色: admin");
    println!(
        "   - 读取文章: {}",
        bool_emoji(admin.has_permission(&read_posts))
    );
    println!(
        "   - 编辑文章: {}",
        bool_emoji(admin.has_permission(&write_posts))
    );
    println!(
        "   - 删除文章: {}",
        bool_emoji(admin.has_permission(&delete_posts))
    );
    println!(
        "   - 读取用户: {}",
        bool_emoji(admin.has_permission(&read_users))
    );
    println!(
        "   - 编辑用户: {}",
        bool_emoji(admin.has_permission(&write_users))
    );
    println!();
}

/// 演示角色继承
fn demo_role_inheritance() {
    println!("🔗 角色继承演示\n");

    let mut manager = RoleManager::new();

    // 创建角色层次结构
    // guest -> user -> moderator -> admin

    let guest = RoleBuilder::new("guest")
        .description("访客")
        .permission(Permission::new("public", "read"))
        .build();

    let user = RoleBuilder::new("user")
        .description("注册用户")
        .inherit("guest") // 继承 guest
        .permission(Permission::new("posts", "create"))
        .permission(Permission::new("comments", "create"))
        .permission(Permission::new("profile", "read"))
        .permission(Permission::new("profile", "write"))
        .build();

    let moderator = RoleBuilder::new("moderator")
        .description("版主")
        .inherit("user") // 继承 user
        .permission(Permission::new("posts", "moderate"))
        .permission(Permission::new("comments", "moderate"))
        .permission(Permission::new("users", "warn"))
        .build();

    let admin = RoleBuilder::new("admin")
        .description("管理员")
        .inherit("moderator") // 继承 moderator
        .permission(Permission::new("users", "ban"))
        .permission(Permission::new("settings", "manage"))
        .build();

    manager.add_role(guest);
    manager.add_role(user);
    manager.add_role(moderator);
    manager.add_role(admin);

    // 显示各角色的有效权限
    for role_name in &["guest", "user", "moderator", "admin"] {
        let perms = manager.get_effective_permissions(role_name);
        println!("   角色: {} (共 {} 个权限)", role_name, perms.len());
        for perm in &perms {
            println!("      - {}", perm);
        }
        println!();
    }

    // 检查继承的权限
    println!("   权限检查:");
    println!(
        "   - admin 是否有 public:read (继承自 guest): {}",
        bool_emoji(manager.role_has_permission("admin", &Permission::new("public", "read")))
    );
    println!(
        "   - admin 是否有 posts:create (继承自 user): {}",
        bool_emoji(manager.role_has_permission("admin", &Permission::new("posts", "create")))
    );
    println!(
        "   - user 是否有 settings:manage (admin 专属): {}",
        bool_emoji(manager.role_has_permission("user", &Permission::new("settings", "manage")))
    );
    println!();
}

/// 演示通配符权限
fn demo_wildcard_permissions() {
    println!("✨ 通配符权限演示\n");

    // 超级管理员：拥有所有权限
    let super_admin = RoleBuilder::new("super_admin")
        .permission(Permission::wildcard()) // *:*
        .build();

    // 文章管理员：拥有文章的所有操作权限
    let posts_admin = RoleBuilder::new("posts_admin")
        .permission(Permission::resource_wildcard("posts")) // posts:*
        .build();

    // 只读角色：拥有所有资源的读取权限
    let readonly = RoleBuilder::new("readonly")
        .permission(Permission::action_wildcard("read")) // *:read
        .build();

    // 测试权限
    let test_permissions = vec![
        Permission::new("posts", "read"),
        Permission::new("posts", "write"),
        Permission::new("posts", "delete"),
        Permission::new("users", "read"),
        Permission::new("users", "delete"),
        Permission::new("settings", "modify"),
    ];

    println!("   角色: super_admin (*:*)");
    for perm in &test_permissions {
        println!(
            "   - {}: {}",
            perm,
            bool_emoji(super_admin.has_permission(perm))
        );
    }
    println!();

    println!("   角色: posts_admin (posts:*)");
    for perm in &test_permissions {
        println!(
            "   - {}: {}",
            perm,
            bool_emoji(posts_admin.has_permission(perm))
        );
    }
    println!();

    println!("   角色: readonly (*:read)");
    for perm in &test_permissions {
        println!(
            "   - {}: {}",
            perm,
            bool_emoji(readonly.has_permission(perm))
        );
    }
    println!();
}

/// 演示策略引擎
fn demo_policy_engine() {
    println!("⚙️  策略引擎演示\n");

    let mut engine = PolicyEngine::new();

    // 添加允许策略
    engine.add_policy(
        Policy::allow("viewer-read")
            .role("viewer")
            .resource("posts")
            .action("read")
            .build(),
    );

    engine.add_policy(
        Policy::allow("editor-posts")
            .role("editor")
            .resource("posts")
            .actions(["read", "write", "publish"])
            .build(),
    );

    engine.add_policy(
        Policy::allow("admin-all")
            .role("admin")
            .resource("*")
            .action("*")
            .build(),
    );

    // 添加拒绝策略（高优先级）
    engine.add_policy(
        Policy::deny("no-delete-published")
            .resource("published_posts")
            .action("delete")
            .priority(100) // 高优先级
            .build(),
    );

    // 创建用户
    let viewer = Subject::new("user_001").with_role("viewer");
    let editor = Subject::new("user_002").with_role("editor");
    let admin = Subject::new("user_003").with_role("admin");

    // 测试策略评估
    println!("   策略评估测试:\n");

    // Viewer 测试
    println!("   用户: viewer");
    test_policy(&engine, &viewer, "posts", "read");
    test_policy(&engine, &viewer, "posts", "write");
    println!();

    // Editor 测试
    println!("   用户: editor");
    test_policy(&engine, &editor, "posts", "read");
    test_policy(&engine, &editor, "posts", "write");
    test_policy(&engine, &editor, "posts", "publish");
    test_policy(&engine, &editor, "posts", "delete");
    println!();

    // Admin 测试
    println!("   用户: admin");
    test_policy(&engine, &admin, "posts", "read");
    test_policy(&engine, &admin, "posts", "delete");
    test_policy(&engine, &admin, "users", "manage");
    // 测试高优先级拒绝策略
    test_policy(&engine, &admin, "published_posts", "delete");
    println!();
}

/// 演示多角色用户
fn demo_multi_role_user() {
    println!("👥 多角色用户演示\n");

    let mut engine = PolicyEngine::new();

    // 配置策略
    engine.add_policy(
        Policy::allow("editor-posts")
            .role("editor")
            .resource("posts")
            .actions(["read", "write"])
            .build(),
    );

    engine.add_policy(
        Policy::allow("reviewer-review")
            .role("reviewer")
            .resource("posts")
            .action("review")
            .build(),
    );

    engine.add_policy(
        Policy::allow("publisher-publish")
            .role("publisher")
            .resource("posts")
            .action("publish")
            .build(),
    );

    // 创建拥有多个角色的用户
    let multi_role_user = Subject::new("power_user")
        .with_role("editor")
        .with_role("reviewer")
        .with_role("publisher");

    println!("   用户: power_user (角色: editor, reviewer, publisher)\n");

    test_policy(&engine, &multi_role_user, "posts", "read");
    test_policy(&engine, &multi_role_user, "posts", "write");
    test_policy(&engine, &multi_role_user, "posts", "review");
    test_policy(&engine, &multi_role_user, "posts", "publish");
    test_policy(&engine, &multi_role_user, "posts", "delete");
    println!();
}

/// 演示实际应用场景
fn demo_real_world_scenario() {
    println!("🌐 实际应用场景演示\n");
    println!("   场景: 博客系统权限管理\n");

    let mut role_manager = RoleManager::new();
    let mut policy_engine = PolicyEngine::new();

    // 定义角色
    let guest = RoleBuilder::new("guest")
        .description("游客")
        .permission(Permission::new("posts", "read"))
        .permission(Permission::new("comments", "read"))
        .build();

    let member = RoleBuilder::new("member")
        .description("会员")
        .inherit("guest")
        .permission(Permission::new("posts", "create"))
        .permission(Permission::new("comments", "create"))
        .permission(Permission::new("profile", "read"))
        .permission(Permission::new("profile", "update"))
        .build();

    let author = RoleBuilder::new("author")
        .description("作者")
        .inherit("member")
        .permission(Permission::new("posts", "update"))
        .permission(Permission::new("posts", "delete"))
        .permission(Permission::new("posts", "publish"))
        .build();

    let moderator = RoleBuilder::new("moderator")
        .description("版主")
        .inherit("member")
        .permission(Permission::new("comments", "delete"))
        .permission(Permission::new("comments", "hide"))
        .permission(Permission::new("users", "warn"))
        .build();

    let admin = RoleBuilder::new("admin")
        .description("管理员")
        .inherit("author")
        .inherit("moderator")
        .permission(Permission::new("users", "ban"))
        .permission(Permission::new("settings", "manage"))
        .build();

    role_manager.add_role(guest);
    role_manager.add_role(member);
    role_manager.add_role(author);
    role_manager.add_role(moderator);
    role_manager.add_role(admin);

    // 配置策略引擎
    for role_name in ["guest", "member", "author", "moderator", "admin"] {
        let permissions = role_manager.get_effective_permissions(role_name);
        for perm in permissions {
            policy_engine.add_policy(
                Policy::allow(format!(
                    "{}-{}-{}",
                    role_name,
                    perm.resource(),
                    perm.action()
                ))
                .role(role_name)
                .resource(perm.resource())
                .action(perm.action())
                .build(),
            );
        }
    }

    // 特殊规则：禁止任何人删除已发布超过 30 天的文章
    policy_engine.add_policy(
        Policy::deny("no-delete-old-posts")
            .resource("archived_posts")
            .action("delete")
            .priority(1000)
            .build(),
    );

    // 模拟用户操作
    println!("   模拟用户操作:\n");

    let guest_user = Subject::new("visitor_123").with_role("guest");
    let member_user = Subject::new("member_456").with_role("member");
    let author_user = Subject::new("author_789").with_role("author");
    let admin_user = Subject::new("admin_001").with_role("admin");

    println!("   游客尝试操作:");
    println!(
        "   - 阅读文章: {}",
        bool_emoji(policy_engine.check_permission(&guest_user, "posts", "read"))
    );
    println!(
        "   - 发表评论: {}",
        bool_emoji(policy_engine.check_permission(&guest_user, "comments", "create"))
    );
    println!();

    println!("   会员尝试操作:");
    println!(
        "   - 阅读文章: {}",
        bool_emoji(policy_engine.check_permission(&member_user, "posts", "read"))
    );
    println!(
        "   - 发表评论: {}",
        bool_emoji(policy_engine.check_permission(&member_user, "comments", "create"))
    );
    println!(
        "   - 发布文章: {}",
        bool_emoji(policy_engine.check_permission(&member_user, "posts", "publish"))
    );
    println!();

    println!("   作者尝试操作:");
    println!(
        "   - 发布文章: {}",
        bool_emoji(policy_engine.check_permission(&author_user, "posts", "publish"))
    );
    println!(
        "   - 删除文章: {}",
        bool_emoji(policy_engine.check_permission(&author_user, "posts", "delete"))
    );
    println!(
        "   - 删除归档文章: {}",
        bool_emoji(policy_engine.check_permission(&author_user, "archived_posts", "delete"))
    );
    println!();

    println!("   管理员尝试操作:");
    println!(
        "   - 封禁用户: {}",
        bool_emoji(policy_engine.check_permission(&admin_user, "users", "ban"))
    );
    println!(
        "   - 管理设置: {}",
        bool_emoji(policy_engine.check_permission(&admin_user, "settings", "manage"))
    );
    println!(
        "   - 删除归档文章: {}",
        bool_emoji(policy_engine.check_permission(&admin_user, "archived_posts", "delete"))
    );
    println!();
}

fn test_policy(engine: &PolicyEngine, subject: &Subject, resource: &str, action: &str) {
    let decision = engine.evaluate(subject, &Resource::new(resource), &Action::new(action));
    let status = if decision.is_allowed() {
        "✅ 允许"
    } else {
        "❌ 拒绝"
    };
    println!("   - {}:{} -> {}", resource, action, status);
}

fn bool_emoji(value: bool) -> &'static str {
    if value { "✅" } else { "❌" }
}

fn main() {
    println!("=== AuthRS RBAC 示例 ===\n");

    demo_basic_roles();
    println!("{}\n", "=".repeat(50));

    demo_role_inheritance();
    println!("{}\n", "=".repeat(50));

    demo_wildcard_permissions();
    println!("{}\n", "=".repeat(50));

    demo_policy_engine();
    println!("{}\n", "=".repeat(50));

    demo_multi_role_user();
    println!("{}\n", "=".repeat(50));

    demo_real_world_scenario();

    println!("=== 示例结束 ===");
}
