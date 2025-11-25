//! # RBAC (Role-Based Access Control) 模块
//!
//! 提供基础的角色权限管理功能，包括：
//!
//! - **角色定义**: 创建和管理角色
//! - **权限检查**: 定义和验证权限
//! - **策略引擎**: 基于策略的访问控制决策
//!
//! ## 基本概念
//!
//! - **Permission（权限）**: 表示对特定资源的特定操作能力
//! - **Role（角色）**: 一组权限的集合
//! - **Policy（策略）**: 定义访问控制规则，可以是允许或拒绝
//!
//! ## 使用示例
//!
//! ### 基本权限检查
//!
//! ```rust
//! use authrs::rbac::{Permission, Role, RoleBuilder};
//!
//! // 创建权限
//! let read_posts = Permission::new("posts", "read");
//! let write_posts = Permission::new("posts", "write");
//! let delete_posts = Permission::new("posts", "delete");
//!
//! // 创建角色
//! let editor = RoleBuilder::new("editor")
//!     .description("Content editor")
//!     .permission(read_posts.clone())
//!     .permission(write_posts.clone())
//!     .build();
//!
//! // 检查权限
//! assert!(editor.has_permission(&read_posts));
//! assert!(editor.has_permission(&write_posts));
//! assert!(!editor.has_permission(&delete_posts));
//! ```
//!
//! ### 使用通配符权限
//!
//! ```rust
//! use authrs::rbac::{Permission, Role, RoleBuilder};
//!
//! // 创建管理员角色，拥有所有权限
//! let admin = RoleBuilder::new("admin")
//!     .permission(Permission::wildcard()) // 所有资源的所有操作
//!     .build();
//!
//! // 创建文章管理员，拥有文章的所有操作权限
//! let posts_admin = RoleBuilder::new("posts_admin")
//!     .permission(Permission::resource_wildcard("posts")) // posts:*
//!     .build();
//!
//! let read_posts = Permission::new("posts", "read");
//! let read_users = Permission::new("users", "read");
//!
//! assert!(admin.has_permission(&read_posts));
//! assert!(admin.has_permission(&read_users));
//! assert!(posts_admin.has_permission(&read_posts));
//! assert!(!posts_admin.has_permission(&read_users));
//! ```
//!
//! ### 使用策略引擎
//!
//! ```rust
//! use authrs::rbac::{
//!     Permission, Role, RoleBuilder, PolicyEngine, Policy,
//!     PolicyEffect, PolicyEvaluator, Subject, Resource, Action,
//! };
//!
//! // 创建策略引擎
//! let mut engine = PolicyEngine::new();
//!
//! // 添加策略：允许 editor 角色读写文章
//! engine.add_policy(
//!     Policy::allow("editor-posts-policy")
//!         .role("editor")
//!         .resource("posts")
//!         .actions(["read", "write"])
//!         .build()
//! );
//!
//! // 添加策略：拒绝所有用户删除文章（优先级更高）
//! engine.add_policy(
//!     Policy::deny("no-delete-posts")
//!         .resource("posts")
//!         .action("delete")
//!         .priority(100) // 更高优先级
//!         .build()
//! );
//!
//! // 创建主体（用户）
//! let user = Subject::new("user123").with_role("editor");
//!
//! // 评估访问请求
//! let can_read = engine.evaluate(&user, &Resource::new("posts"), &Action::new("read"));
//! let can_delete = engine.evaluate(&user, &Resource::new("posts"), &Action::new("delete"));
//!
//! assert!(can_read.is_allowed());
//! assert!(can_delete.is_denied());
//! ```
//!
//! ### 角色继承
//!
//! ```rust
//! use authrs::rbac::{Permission, Role, RoleBuilder, RoleManager};
//!
//! let mut manager = RoleManager::new();
//!
//! // 创建基础角色
//! let viewer = RoleBuilder::new("viewer")
//!     .permission(Permission::new("posts", "read"))
//!     .build();
//!
//! // 创建继承角色
//! let editor = RoleBuilder::new("editor")
//!     .inherit("viewer") // 继承 viewer 的权限
//!     .permission(Permission::new("posts", "write"))
//!     .build();
//!
//! manager.add_role(viewer);
//! manager.add_role(editor);
//!
//! // editor 拥有继承的 read 权限和自己的 write 权限
//! let effective = manager.get_effective_permissions("editor");
//! assert!(effective.contains(&Permission::new("posts", "read")));
//! assert!(effective.contains(&Permission::new("posts", "write")));
//! ```

mod permission;
mod policy;
mod role;

pub use permission::{Action, Permission, PermissionSet, Resource};
pub use policy::{
    Decision, DecisionReason, Policy, PolicyBuilder, PolicyEffect, PolicyEngine, PolicyEvaluator,
    Subject,
};
pub use role::{InMemoryRoleStore, Role, RoleBuilder, RoleManager, RoleStore};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_rbac_workflow() {
        // 创建权限
        let read_posts = Permission::new("posts", "read");
        let write_posts = Permission::new("posts", "write");
        let delete_posts = Permission::new("posts", "delete");

        // 创建角色
        let editor = RoleBuilder::new("editor")
            .description("Content editor")
            .permission(read_posts.clone())
            .permission(write_posts.clone())
            .build();

        // 验证权限
        assert!(editor.has_permission(&read_posts));
        assert!(editor.has_permission(&write_posts));
        assert!(!editor.has_permission(&delete_posts));
    }

    #[test]
    fn test_policy_engine_workflow() {
        let mut engine = PolicyEngine::new();

        // 添加允许策略
        engine.add_policy(
            Policy::allow("editor-posts-read")
                .role("editor")
                .resource("posts")
                .action("read")
                .build(),
        );

        // 添加拒绝策略（高优先级）
        engine.add_policy(
            Policy::deny("no-delete")
                .resource("posts")
                .action("delete")
                .priority(100)
                .build(),
        );

        let user = Subject::new("user1").with_role("editor");

        // 测试允许的操作
        let decision = engine.evaluate(&user, &Resource::new("posts"), &Action::new("read"));
        assert!(decision.is_allowed());

        // 测试拒绝的操作
        let decision = engine.evaluate(&user, &Resource::new("posts"), &Action::new("delete"));
        assert!(decision.is_denied());

        // 测试未定义的操作（默认拒绝）
        let decision = engine.evaluate(&user, &Resource::new("users"), &Action::new("read"));
        assert!(decision.is_denied());
    }

    #[test]
    fn test_role_inheritance() {
        let mut manager = RoleManager::new();

        // 基础角色
        let viewer = RoleBuilder::new("viewer")
            .permission(Permission::new("posts", "read"))
            .build();

        // 继承角色
        let editor = RoleBuilder::new("editor")
            .inherit("viewer")
            .permission(Permission::new("posts", "write"))
            .build();

        manager.add_role(viewer);
        manager.add_role(editor);

        // 验证继承的权限
        let effective = manager.get_effective_permissions("editor");
        assert!(effective.contains(&Permission::new("posts", "read")));
        assert!(effective.contains(&Permission::new("posts", "write")));
    }

    #[test]
    fn test_wildcard_permissions() {
        // 超级管理员
        let super_admin = RoleBuilder::new("super_admin")
            .permission(Permission::wildcard())
            .build();

        // 资源管理员
        let posts_admin = RoleBuilder::new("posts_admin")
            .permission(Permission::resource_wildcard("posts"))
            .build();

        let read_posts = Permission::new("posts", "read");
        let delete_posts = Permission::new("posts", "delete");
        let read_users = Permission::new("users", "read");

        // 超级管理员拥有所有权限
        assert!(super_admin.has_permission(&read_posts));
        assert!(super_admin.has_permission(&delete_posts));
        assert!(super_admin.has_permission(&read_users));

        // posts_admin 只有 posts 资源的权限
        assert!(posts_admin.has_permission(&read_posts));
        assert!(posts_admin.has_permission(&delete_posts));
        assert!(!posts_admin.has_permission(&read_users));
    }
}
