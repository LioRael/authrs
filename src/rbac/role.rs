//! 角色定义模块
//!
//! 提供角色的创建、管理和继承功能。

use super::permission::{Permission, PermissionSet};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

/// 角色定义
///
/// 角色是一组权限的集合，支持继承其他角色的权限
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    /// 角色唯一标识符
    pub id: String,
    /// 角色名称
    pub name: String,
    /// 角色描述
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// 直接分配给此角色的权限
    permissions: PermissionSet,
    /// 继承的角色 ID 列表
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    inherits: HashSet<String>,
    /// 角色是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 更新时间
    pub updated_at: DateTime<Utc>,
    /// 元数据
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

fn default_enabled() -> bool {
    true
}

impl Role {
    /// 创建新角色
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: id.into(),
            name: name.into(),
            description: None,
            permissions: PermissionSet::new(),
            inherits: HashSet::new(),
            enabled: true,
            created_at: now,
            updated_at: now,
            metadata: HashMap::new(),
        }
    }

    /// 获取角色 ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// 获取角色名称
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 获取描述
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// 设置描述
    pub fn set_description(&mut self, description: impl Into<String>) {
        self.description = Some(description.into());
        self.updated_at = Utc::now();
    }

    /// 添加权限
    pub fn add_permission(&mut self, permission: Permission) {
        self.permissions.add(permission);
        self.updated_at = Utc::now();
    }

    /// 移除权限
    pub fn remove_permission(&mut self, permission: &Permission) -> bool {
        let removed = self.permissions.remove(permission);
        if removed {
            self.updated_at = Utc::now();
        }
        removed
    }

    /// 检查是否有特定权限（仅检查直接权限，不考虑继承）
    pub fn has_permission(&self, permission: &Permission) -> bool {
        self.permissions.contains(permission)
    }

    /// 获取直接权限集合
    pub fn permissions(&self) -> &PermissionSet {
        &self.permissions
    }

    /// 添加继承角色
    pub fn inherit(&mut self, role_id: impl Into<String>) {
        self.inherits.insert(role_id.into());
        self.updated_at = Utc::now();
    }

    /// 移除继承角色
    pub fn uninherit(&mut self, role_id: &str) -> bool {
        let removed = self.inherits.remove(role_id);
        if removed {
            self.updated_at = Utc::now();
        }
        removed
    }

    /// 获取继承的角色列表
    pub fn inherits(&self) -> &HashSet<String> {
        &self.inherits
    }

    /// 检查是否继承自指定角色
    pub fn inherits_from(&self, role_id: &str) -> bool {
        self.inherits.contains(role_id)
    }

    /// 启用角色
    pub fn enable(&mut self) {
        self.enabled = true;
        self.updated_at = Utc::now();
    }

    /// 禁用角色
    pub fn disable(&mut self) {
        self.enabled = false;
        self.updated_at = Utc::now();
    }

    /// 检查角色是否启用
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// 添加元数据
    pub fn set_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
        self.updated_at = Utc::now();
    }

    /// 获取元数据
    pub fn get_metadata(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).map(|s| s.as_str())
    }
}

impl PartialEq for Role {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Role {}

impl std::hash::Hash for Role {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

// ============================================================================
// RoleBuilder
// ============================================================================

/// 角色构建器
///
/// 提供流式 API 来创建角色
///
/// # 示例
///
/// ```rust
/// use authrs::rbac::{RoleBuilder, Permission};
///
/// let role = RoleBuilder::new("editor")
///     .description("Content editor")
///     .permission(Permission::new("posts", "read"))
///     .permission(Permission::new("posts", "write"))
///     .inherit("viewer")
///     .metadata("department", "content")
///     .build();
/// ```
pub struct RoleBuilder {
    id: String,
    name: Option<String>,
    description: Option<String>,
    permissions: Vec<Permission>,
    inherits: Vec<String>,
    enabled: bool,
    metadata: HashMap<String, String>,
}

impl RoleBuilder {
    /// 创建新的角色构建器
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: None,
            description: None,
            permissions: Vec::new(),
            inherits: Vec::new(),
            enabled: true,
            metadata: HashMap::new(),
        }
    }

    /// 设置角色名称（默认与 ID 相同）
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// 设置描述
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// 添加权限
    pub fn permission(mut self, permission: Permission) -> Self {
        self.permissions.push(permission);
        self
    }

    /// 添加多个权限
    pub fn permissions(mut self, permissions: impl IntoIterator<Item = Permission>) -> Self {
        self.permissions.extend(permissions);
        self
    }

    /// 添加继承角色
    pub fn inherit(mut self, role_id: impl Into<String>) -> Self {
        self.inherits.push(role_id.into());
        self
    }

    /// 添加多个继承角色
    pub fn inherits<I, S>(mut self, role_ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.inherits.extend(role_ids.into_iter().map(Into::into));
        self
    }

    /// 设置是否启用
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// 添加元数据
    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// 构建角色
    pub fn build(self) -> Role {
        let now = Utc::now();
        let name = self.name.unwrap_or_else(|| self.id.clone());

        Role {
            id: self.id,
            name,
            description: self.description,
            permissions: self.permissions.into_iter().collect(),
            inherits: self.inherits.into_iter().collect(),
            enabled: self.enabled,
            created_at: now,
            updated_at: now,
            metadata: self.metadata,
        }
    }
}

// ============================================================================
// RoleStore Trait
// ============================================================================

/// 角色存储 trait
///
/// 定义角色持久化存储的接口
#[async_trait]
pub trait RoleStore: Send + Sync {
    /// 保存角色
    async fn save(&self, role: Role) -> Result<(), ()>;

    /// 根据 ID 获取角色
    async fn get(&self, id: &str) -> Option<Role>;

    /// 更新/替换角色
    async fn update(&self, role: Role) -> Result<(), ()>;

    /// 删除角色，返回被删除的角色
    async fn delete(&self, id: &str) -> Option<Role>;

    /// 列出所有角色
    async fn list(&self) -> Vec<Role>;

    /// 检查角色是否存在
    async fn exists(&self, id: &str) -> bool {
        self.get(id).await.is_some()
    }
}

// ============================================================================
// InMemoryRoleStore
// ============================================================================

/// 内存角色存储
///
/// 用于测试和开发环境
#[derive(Debug, Default)]
pub struct InMemoryRoleStore {
    roles: RwLock<HashMap<String, Role>>,
}

impl InMemoryRoleStore {
    /// 创建新的内存存储
    pub fn new() -> Self {
        Self::default()
    }

    /// 获取角色数量
    pub fn len(&self) -> usize {
        self.roles.read().map(|m| m.len()).unwrap_or(0)
    }

    /// 检查是否为空
    pub fn is_empty(&self) -> bool {
        self.roles.read().map(|m| m.is_empty()).unwrap_or(true)
    }

    /// 清空所有角色
    pub fn clear(&mut self) {
        if let Ok(mut roles) = self.roles.write() {
            roles.clear();
        }
    }
}

#[async_trait]
impl RoleStore for InMemoryRoleStore {
    async fn save(&self, role: Role) -> Result<(), ()> {
        if let Ok(mut roles) = self.roles.write() {
            roles.insert(role.id.clone(), role);
        }
        Ok(())
    }

    async fn get(&self, id: &str) -> Option<Role> {
        self.roles.read().ok().and_then(|m| m.get(id).cloned())
    }

    async fn update(&self, role: Role) -> Result<(), ()> {
        if let Ok(mut roles) = self.roles.write() {
            roles.insert(role.id.clone(), role);
        }
        Ok(())
    }

    async fn delete(&self, id: &str) -> Option<Role> {
        self.roles.write().ok().and_then(|mut m| m.remove(id))
    }

    async fn list(&self) -> Vec<Role> {
        self.roles
            .read()
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default()
    }
}

// ============================================================================
// RoleManager
// ============================================================================

/// 角色管理器
///
/// 管理角色的创建、分配和权限解析（包括继承）
///
/// # 示例
///
/// ```rust
/// use authrs::rbac::{RoleManager, RoleBuilder, Permission};
///
/// let mut manager = RoleManager::new();
///
/// // 创建基础角色
/// let viewer = RoleBuilder::new("viewer")
///     .permission(Permission::new("posts", "read"))
///     .build();
///
/// // 创建继承角色
/// let editor = RoleBuilder::new("editor")
///     .inherit("viewer")
///     .permission(Permission::new("posts", "write"))
///     .build();
///
/// manager.add_role(viewer);
/// manager.add_role(editor);
///
/// // 获取有效权限（包括继承的）
/// let permissions = manager.get_effective_permissions("editor");
/// ```
pub struct RoleManager {
    store: Arc<dyn RoleStore>,
}

impl Default for RoleManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RoleManager {
    /// 创建新的角色管理器
    pub fn new() -> Self {
        Self {
            store: Arc::new(InMemoryRoleStore::new()),
        }
    }

    /// 使用自定义存储创建管理器
    pub fn with_store<S: RoleStore + 'static>(store: S) -> Self {
        Self {
            store: Arc::new(store),
        }
    }

    /// 添加角色
    pub async fn add_role(&self, role: Role) {
        let _ = self.store.save(role).await;
    }

    /// 获取角色
    pub async fn get_role(&self, id: &str) -> Option<Role> {
        self.store.get(id).await
    }

    /// 删除角色
    pub async fn remove_role(&self, id: &str) -> Option<Role> {
        self.store.delete(id).await
    }

    /// 列出所有角色
    pub async fn list_roles(&self) -> Vec<Role> {
        self.store.list().await
    }

    /// 检查角色是否存在
    pub async fn role_exists(&self, id: &str) -> bool {
        self.store.exists(id).await
    }

    /// 获取角色数量
    pub async fn role_count(&self) -> usize {
        self.store.list().await.len()
    }

    /// 获取角色的有效权限（包括继承的权限）
    ///
    /// 递归解析所有继承链上的权限
    pub async fn get_effective_permissions(&self, role_id: &str) -> PermissionSet {
        let mut permissions = PermissionSet::new();
        let mut visited = HashSet::new();
        let mut stack = vec![role_id.to_string()];

        while let Some(current) = stack.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }

            if let Some(role) = self.store.get(&current).await {
                if role.enabled {
                    permissions.merge(role.permissions());
                    for parent_id in role.inherits() {
                        stack.push(parent_id.clone());
                    }
                }
            }
        }

        permissions
    }

    /// 检查角色是否有特定权限（包括继承）
    pub async fn role_has_permission(&self, role_id: &str, permission: &Permission) -> bool {
        let effective = self.get_effective_permissions(role_id).await;
        effective.contains(permission)
    }

    /// 获取用户的所有有效权限
    ///
    /// 用户可以拥有多个角色
    pub async fn get_user_permissions(&self, role_ids: &[&str]) -> PermissionSet {
        let mut permissions = PermissionSet::new();
        for role_id in role_ids {
            let role_permissions = self.get_effective_permissions(role_id).await;
            permissions.merge(&role_permissions);
        }
        permissions
    }

    /// 检查用户是否有特定权限
    pub async fn user_has_permission(&self, role_ids: &[&str], permission: &Permission) -> bool {
        for role_id in role_ids {
            if self.role_has_permission(role_id, permission).await {
                return true;
            }
        }
        false
    }

    /// 检查用户是否有所有指定权限
    pub async fn user_has_all_permissions(
        &self,
        role_ids: &[&str],
        permissions: &[Permission],
    ) -> bool {
        let user_perms = self.get_user_permissions(role_ids).await;
        user_perms.contains_all(permissions)
    }

    /// 检查用户是否有任意一个指定权限
    pub async fn user_has_any_permission(
        &self,
        role_ids: &[&str],
        permissions: &[Permission],
    ) -> bool {
        let user_perms = self.get_user_permissions(role_ids).await;
        user_perms.contains_any(permissions)
    }

    /// 获取角色的继承链
    ///
    /// 返回所有直接和间接继承的角色 ID
    pub async fn get_inheritance_chain(&self, role_id: &str) -> Vec<String> {
        let mut chain = Vec::new();
        let mut visited = HashSet::new();
        let mut stack = vec![role_id.to_string()];

        while let Some(current) = stack.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }

            if let Some(role) = self.store.get(&current).await {
                for parent_id in role.inherits() {
                    chain.push(parent_id.clone());
                    stack.push(parent_id.clone());
                }
            }
        }

        chain
    }

    /// 检查继承关系是否会导致循环
    pub async fn would_create_cycle(&self, role_id: &str, parent_id: &str) -> bool {
        // 如果要继承自己，直接返回 true
        if role_id == parent_id {
            return true;
        }

        // 检查 parent_id 的继承链中是否包含 role_id
        let chain = self.get_inheritance_chain(parent_id).await;
        chain.contains(&role_id.to_string())
    }

    /// 安全地添加继承关系
    ///
    /// 如果会导致循环继承则返回错误
    pub async fn add_inheritance(&self, role_id: &str, parent_id: &str) -> Result<(), String> {
        if self.would_create_cycle(role_id, parent_id).await {
            return Err(format!(
                "Adding inheritance from '{}' to '{}' would create a cycle",
                parent_id, role_id
            ));
        }

        if !self.store.exists(parent_id).await {
            return Err(format!("Parent role '{}' does not exist", parent_id));
        }

        if let Some(mut role) = self.store.get(role_id).await {
            role.inherit(parent_id);
            let _ = self.store.save(role).await;
            Ok(())
        } else {
            Err(format!("Role '{}' does not exist", role_id))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_new() {
        let role = Role::new("admin", "Administrator");
        assert_eq!(role.id(), "admin");
        assert_eq!(role.name(), "Administrator");
        assert!(role.is_enabled());
        assert!(role.permissions().is_empty());
    }

    #[test]
    fn test_role_permissions() {
        let mut role = Role::new("editor", "Editor");
        let read = Permission::new("posts", "read");
        let write = Permission::new("posts", "write");

        role.add_permission(read.clone());
        role.add_permission(write.clone());

        assert!(role.has_permission(&read));
        assert!(role.has_permission(&write));
        assert!(!role.has_permission(&Permission::new("posts", "delete")));

        role.remove_permission(&write);
        assert!(!role.has_permission(&write));
    }

    #[tokio::test]
    async fn test_role_builder() {
        let role = RoleBuilder::new("editor")
            .name("Content Editor")
            .description("Can edit content")
            .permission(Permission::new("posts", "read"))
            .permission(Permission::new("posts", "write"))
            .inherit("viewer")
            .metadata("department", "content")
            .build();

        assert_eq!(role.id(), "editor");
        assert_eq!(role.name(), "Content Editor");
        assert_eq!(role.description(), Some("Can edit content"));
        assert!(role.has_permission(&Permission::new("posts", "read")));
        assert!(role.inherits_from("viewer"));
        assert_eq!(role.get_metadata("department"), Some("content"));
    }

    #[tokio::test]
    async fn test_role_inheritance() {
        let mut role = Role::new("admin", "Admin");
        role.inherit("editor");
        role.inherit("viewer");

        assert!(role.inherits_from("editor"));
        assert!(role.inherits_from("viewer"));
        assert!(!role.inherits_from("guest"));

        role.uninherit("editor");
        assert!(!role.inherits_from("editor"));
    }

    #[tokio::test]
    async fn test_role_enable_disable() {
        let mut role = Role::new("test", "Test");
        assert!(role.is_enabled());

        role.disable();
        assert!(!role.is_enabled());

        role.enable();
        assert!(role.is_enabled());
    }

    #[tokio::test]
    async fn test_in_memory_store() {
        let store = InMemoryRoleStore::new();
        assert!(store.is_empty());

        let role = Role::new("admin", "Admin");
        store.save(role).await.unwrap();

        assert_eq!(store.len(), 1);
        assert!(store.exists("admin").await);
        assert!(!store.exists("unknown").await);

        let role = store.get("admin").await.unwrap();
        assert_eq!(role.id(), "admin");

        let deleted = store.delete("admin").await;
        assert!(deleted.is_some());
        assert!(store.is_empty());
    }

    #[tokio::test]
    async fn test_role_manager_basic() {
        let manager = RoleManager::new();

        let viewer = RoleBuilder::new("viewer")
            .permission(Permission::new("posts", "read"))
            .build();

        let editor = RoleBuilder::new("editor")
            .permission(Permission::new("posts", "write"))
            .build();

        manager.add_role(viewer).await;
        manager.add_role(editor).await;

        assert_eq!(manager.role_count().await, 2);
        assert!(manager.role_exists("viewer").await);
        assert!(manager.role_exists("editor").await);
    }

    #[tokio::test]
    async fn test_role_manager_inheritance() {
        let manager = RoleManager::new();

        // 创建角色层级：viewer -> editor -> admin
        let viewer = RoleBuilder::new("viewer")
            .permission(Permission::new("posts", "read"))
            .build();

        let editor = RoleBuilder::new("editor")
            .inherit("viewer")
            .permission(Permission::new("posts", "write"))
            .build();

        let admin = RoleBuilder::new("admin")
            .inherit("editor")
            .permission(Permission::new("posts", "delete"))
            .build();

        manager.add_role(viewer).await;
        manager.add_role(editor).await;
        manager.add_role(admin).await;

        // viewer 只有 read 权限
        let viewer_perms = manager.get_effective_permissions("viewer").await;
        assert!(viewer_perms.contains(&Permission::new("posts", "read")));
        assert!(!viewer_perms.contains(&Permission::new("posts", "write")));

        // editor 有 read + write 权限
        let editor_perms = manager.get_effective_permissions("editor").await;
        assert!(editor_perms.contains(&Permission::new("posts", "read")));
        assert!(editor_perms.contains(&Permission::new("posts", "write")));
        assert!(!editor_perms.contains(&Permission::new("posts", "delete")));

        // admin 有所有权限
        let admin_perms = manager.get_effective_permissions("admin").await;
        assert!(admin_perms.contains(&Permission::new("posts", "read")));
        assert!(admin_perms.contains(&Permission::new("posts", "write")));
        assert!(admin_perms.contains(&Permission::new("posts", "delete")));
    }

    #[tokio::test]
    async fn test_role_manager_disabled_role() {
        let manager = RoleManager::new();

        let mut viewer = RoleBuilder::new("viewer")
            .permission(Permission::new("posts", "read"))
            .build();
        viewer.disable();

        let editor = RoleBuilder::new("editor")
            .inherit("viewer")
            .permission(Permission::new("posts", "write"))
            .build();

        manager.add_role(viewer).await;
        manager.add_role(editor).await;

        // 禁用的角色权限不应该被继承
        let editor_perms = manager.get_effective_permissions("editor").await;
        assert!(editor_perms.contains(&Permission::new("posts", "write")));
        assert!(!editor_perms.contains(&Permission::new("posts", "read")));
    }

    #[tokio::test]
    async fn test_user_permissions() {
        let manager = RoleManager::new();

        let viewer = RoleBuilder::new("viewer")
            .permission(Permission::new("posts", "read"))
            .build();

        let commenter = RoleBuilder::new("commenter")
            .permission(Permission::new("comments", "write"))
            .build();

        manager.add_role(viewer).await;
        manager.add_role(commenter).await;

        // 用户同时拥有两个角色
        let roles = ["viewer", "commenter"];
        let user_perms = manager.get_user_permissions(&roles).await;

        assert!(user_perms.contains(&Permission::new("posts", "read")));
        assert!(user_perms.contains(&Permission::new("comments", "write")));
    }

    #[tokio::test]
    async fn test_cycle_detection() {
        let manager = RoleManager::new();

        let a = RoleBuilder::new("a").build();
        let b = RoleBuilder::new("b").inherit("a").build();
        let c = RoleBuilder::new("c").inherit("b").build();

        manager.add_role(a).await;
        manager.add_role(b).await;
        manager.add_role(c).await;

        // 不应该允许 a 继承 c（会创建循环）
        assert!(manager.would_create_cycle("a", "c").await);
        assert!(manager.would_create_cycle("a", "b").await);

        // 这些不会创建循环
        assert!(!manager.would_create_cycle("c", "a").await); // c 已经间接继承 a

        // 尝试添加会导致循环的继承
        let result = manager.add_inheritance("a", "c").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_inheritance_chain() {
        let manager = RoleManager::new();

        let viewer = RoleBuilder::new("viewer").build();
        let editor = RoleBuilder::new("editor").inherit("viewer").build();
        let admin = RoleBuilder::new("admin").inherit("editor").build();

        manager.add_role(viewer).await;
        manager.add_role(editor).await;
        manager.add_role(admin).await;

        let chain = manager.get_inheritance_chain("admin").await;
        assert!(chain.contains(&"editor".to_string()));
        assert!(chain.contains(&"viewer".to_string()));
    }
}
