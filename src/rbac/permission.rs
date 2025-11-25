//! 权限定义模块
//!
//! 提供权限、操作和资源的定义与管理。

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::hash::{Hash, Hasher};

/// 通配符常量，表示匹配所有
pub const WILDCARD: &str = "*";

/// 权限定义
///
/// 权限由资源和操作组成，格式为 `resource:action`
///
/// ## 特殊权限
///
/// - `*:*` - 匹配所有资源的所有操作（超级权限）
/// - `resource:*` - 匹配特定资源的所有操作
/// - `*:action` - 匹配所有资源的特定操作
///
/// ## 示例
///
/// ```rust
/// use authrs::rbac::Permission;
///
/// // 普通权限
/// let read_posts = Permission::new("posts", "read");
///
/// // 通配符权限
/// let all_posts = Permission::resource_wildcard("posts"); // posts:*
/// let super_admin = Permission::wildcard(); // *:*
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    /// 资源标识符
    resource: String,
    /// 操作标识符
    action: String,
    /// 可选的描述
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

impl Permission {
    /// 创建新的权限
    ///
    /// # 参数
    ///
    /// - `resource`: 资源标识符
    /// - `action`: 操作标识符
    ///
    /// # 示例
    ///
    /// ```rust
    /// use authrs::rbac::Permission;
    ///
    /// let perm = Permission::new("posts", "read");
    /// assert_eq!(perm.resource(), "posts");
    /// assert_eq!(perm.action(), "read");
    /// ```
    pub fn new(resource: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            resource: resource.into(),
            action: action.into(),
            description: None,
        }
    }

    /// 创建带描述的权限
    pub fn with_description(
        resource: impl Into<String>,
        action: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            resource: resource.into(),
            action: action.into(),
            description: Some(description.into()),
        }
    }

    /// 创建通配符权限（匹配所有资源的所有操作）
    ///
    /// # 示例
    ///
    /// ```rust
    /// use authrs::rbac::Permission;
    ///
    /// let super_perm = Permission::wildcard();
    /// assert!(super_perm.is_wildcard());
    /// ```
    pub fn wildcard() -> Self {
        Self {
            resource: WILDCARD.to_string(),
            action: WILDCARD.to_string(),
            description: Some("Full access to all resources".to_string()),
        }
    }

    /// 创建资源通配符权限（匹配特定资源的所有操作）
    ///
    /// # 示例
    ///
    /// ```rust
    /// use authrs::rbac::Permission;
    ///
    /// let posts_all = Permission::resource_wildcard("posts");
    /// assert!(posts_all.is_resource_wildcard());
    /// ```
    pub fn resource_wildcard(resource: impl Into<String>) -> Self {
        Self {
            resource: resource.into(),
            action: WILDCARD.to_string(),
            description: None,
        }
    }

    /// 创建操作通配符权限（匹配所有资源的特定操作）
    ///
    /// # 示例
    ///
    /// ```rust
    /// use authrs::rbac::Permission;
    ///
    /// let read_all = Permission::action_wildcard("read");
    /// assert!(read_all.is_action_wildcard());
    /// ```
    pub fn action_wildcard(action: impl Into<String>) -> Self {
        Self {
            resource: WILDCARD.to_string(),
            action: action.into(),
            description: None,
        }
    }

    /// 从字符串解析权限
    ///
    /// 格式：`resource:action`
    ///
    /// # 示例
    ///
    /// ```rust
    /// use authrs::rbac::Permission;
    ///
    /// let perm = Permission::parse("posts:read").unwrap();
    /// assert_eq!(perm.resource(), "posts");
    /// assert_eq!(perm.action(), "read");
    /// ```
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() == 2 {
            Some(Self::new(parts[0], parts[1]))
        } else {
            None
        }
    }

    /// 获取资源标识符
    pub fn resource(&self) -> &str {
        &self.resource
    }

    /// 获取操作标识符
    pub fn action(&self) -> &str {
        &self.action
    }

    /// 获取描述
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// 设置描述
    pub fn set_description(&mut self, description: impl Into<String>) {
        self.description = Some(description.into());
    }

    /// 检查是否是完全通配符权限
    pub fn is_wildcard(&self) -> bool {
        self.resource == WILDCARD && self.action == WILDCARD
    }

    /// 检查是否是资源通配符权限
    pub fn is_resource_wildcard(&self) -> bool {
        self.action == WILDCARD && self.resource != WILDCARD
    }

    /// 检查是否是操作通配符权限
    pub fn is_action_wildcard(&self) -> bool {
        self.resource == WILDCARD && self.action != WILDCARD
    }

    /// 检查是否包含通配符
    pub fn has_wildcard(&self) -> bool {
        self.resource == WILDCARD || self.action == WILDCARD
    }

    /// 检查此权限是否匹配另一个权限
    ///
    /// 通配符权限可以匹配更具体的权限
    ///
    /// # 示例
    ///
    /// ```rust
    /// use authrs::rbac::Permission;
    ///
    /// let all = Permission::wildcard();
    /// let posts_all = Permission::resource_wildcard("posts");
    /// let read_posts = Permission::new("posts", "read");
    ///
    /// assert!(all.matches(&read_posts));
    /// assert!(posts_all.matches(&read_posts));
    /// assert!(read_posts.matches(&read_posts));
    /// assert!(!read_posts.matches(&posts_all));
    /// ```
    pub fn matches(&self, other: &Permission) -> bool {
        let resource_matches = self.resource == WILDCARD || self.resource == other.resource;
        let action_matches = self.action == WILDCARD || self.action == other.action;
        resource_matches && action_matches
    }

    /// 转换为字符串格式
    pub fn to_string_format(&self) -> String {
        format!("{}:{}", self.resource, self.action)
    }
}

impl PartialEq for Permission {
    fn eq(&self, other: &Self) -> bool {
        self.resource == other.resource && self.action == other.action
    }
}

impl Eq for Permission {}

impl Hash for Permission {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.resource.hash(state);
        self.action.hash(state);
    }
}

impl fmt::Display for Permission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.resource, self.action)
    }
}

// ============================================================================
// Resource 类型
// ============================================================================

/// 资源定义
///
/// 表示系统中的一个可访问资源
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resource {
    /// 资源类型/标识符
    pub name: String,
    /// 可选的资源 ID（用于实例级权限控制）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// 可选的属性
    #[serde(default, skip_serializing_if = "std::collections::HashMap::is_empty")]
    pub attributes: std::collections::HashMap<String, String>,
}

impl Resource {
    /// 创建新的资源
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            id: None,
            attributes: std::collections::HashMap::new(),
        }
    }

    /// 创建带 ID 的资源（实例级）
    pub fn with_id(name: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            id: Some(id.into()),
            attributes: std::collections::HashMap::new(),
        }
    }

    /// 添加属性
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// 获取资源名称
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 获取资源 ID
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// 获取属性值
    pub fn get_attribute(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(|s| s.as_str())
    }

    /// 检查是否匹配资源名称
    pub fn matches_name(&self, name: &str) -> bool {
        self.name == name || name == WILDCARD
    }
}

impl fmt::Display for Resource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.id {
            Some(id) => write!(f, "{}:{}", self.name, id),
            None => write!(f, "{}", self.name),
        }
    }
}

// ============================================================================
// Action 类型
// ============================================================================

/// 操作定义
///
/// 表示对资源的操作
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Action {
    /// 操作名称
    pub name: String,
}

impl Action {
    /// 创建新的操作
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// 获取操作名称
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 检查是否匹配操作名称
    pub fn matches(&self, name: &str) -> bool {
        self.name == name || name == WILDCARD || self.name == WILDCARD
    }

    // 常用操作常量
    /// 读取操作
    pub fn read() -> Self {
        Self::new("read")
    }

    /// 写入/创建操作
    pub fn write() -> Self {
        Self::new("write")
    }

    /// 更新操作
    pub fn update() -> Self {
        Self::new("update")
    }

    /// 删除操作
    pub fn delete() -> Self {
        Self::new("delete")
    }

    /// 列表操作
    pub fn list() -> Self {
        Self::new("list")
    }

    /// 管理操作
    pub fn manage() -> Self {
        Self::new("manage")
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

// ============================================================================
// PermissionSet 类型
// ============================================================================

/// 权限集合
///
/// 用于管理一组权限，支持通配符匹配
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PermissionSet {
    permissions: HashSet<Permission>,
}

impl PermissionSet {
    /// 创建空的权限集合
    pub fn new() -> Self {
        Self {
            permissions: HashSet::new(),
        }
    }

    /// 从权限列表创建
    pub fn from_permissions(permissions: impl IntoIterator<Item = Permission>) -> Self {
        Self {
            permissions: permissions.into_iter().collect(),
        }
    }

    /// 添加权限
    pub fn add(&mut self, permission: Permission) -> bool {
        self.permissions.insert(permission)
    }

    /// 移除权限
    pub fn remove(&mut self, permission: &Permission) -> bool {
        self.permissions.remove(permission)
    }

    /// 检查是否包含特定权限
    ///
    /// 考虑通配符匹配
    pub fn contains(&self, permission: &Permission) -> bool {
        // 精确匹配
        if self.permissions.contains(permission) {
            return true;
        }

        // 通配符匹配
        for p in &self.permissions {
            if p.matches(permission) {
                return true;
            }
        }

        false
    }

    /// 检查是否包含所有指定权限
    pub fn contains_all(&self, permissions: &[Permission]) -> bool {
        permissions.iter().all(|p| self.contains(p))
    }

    /// 检查是否包含任意一个指定权限
    pub fn contains_any(&self, permissions: &[Permission]) -> bool {
        permissions.iter().any(|p| self.contains(p))
    }

    /// 获取权限数量
    pub fn len(&self) -> usize {
        self.permissions.len()
    }

    /// 检查是否为空
    pub fn is_empty(&self) -> bool {
        self.permissions.is_empty()
    }

    /// 获取所有权限的迭代器
    pub fn iter(&self) -> impl Iterator<Item = &Permission> {
        self.permissions.iter()
    }

    /// 合并另一个权限集合
    pub fn merge(&mut self, other: &PermissionSet) {
        for p in &other.permissions {
            self.permissions.insert(p.clone());
        }
    }

    /// 获取权限的字符串列表
    pub fn to_string_list(&self) -> Vec<String> {
        self.permissions.iter().map(|p| p.to_string()).collect()
    }

    /// 清空所有权限
    pub fn clear(&mut self) {
        self.permissions.clear();
    }
}

impl IntoIterator for PermissionSet {
    type Item = Permission;
    type IntoIter = std::collections::hash_set::IntoIter<Permission>;

    fn into_iter(self) -> Self::IntoIter {
        self.permissions.into_iter()
    }
}

impl<'a> IntoIterator for &'a PermissionSet {
    type Item = &'a Permission;
    type IntoIter = std::collections::hash_set::Iter<'a, Permission>;

    fn into_iter(self) -> Self::IntoIter {
        self.permissions.iter()
    }
}

impl FromIterator<Permission> for PermissionSet {
    fn from_iter<T: IntoIterator<Item = Permission>>(iter: T) -> Self {
        Self {
            permissions: iter.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_new() {
        let perm = Permission::new("posts", "read");
        assert_eq!(perm.resource(), "posts");
        assert_eq!(perm.action(), "read");
        assert!(!perm.has_wildcard());
    }

    #[test]
    fn test_permission_parse() {
        let perm = Permission::parse("users:delete").unwrap();
        assert_eq!(perm.resource(), "users");
        assert_eq!(perm.action(), "delete");

        assert!(Permission::parse("invalid").is_none());
    }

    #[test]
    fn test_permission_wildcard() {
        let wildcard = Permission::wildcard();
        assert!(wildcard.is_wildcard());
        assert!(wildcard.has_wildcard());

        let resource_wild = Permission::resource_wildcard("posts");
        assert!(resource_wild.is_resource_wildcard());
        assert!(!resource_wild.is_wildcard());

        let action_wild = Permission::action_wildcard("read");
        assert!(action_wild.is_action_wildcard());
        assert!(!action_wild.is_wildcard());
    }

    #[test]
    fn test_permission_matches() {
        let all = Permission::wildcard();
        let posts_all = Permission::resource_wildcard("posts");
        let read_posts = Permission::new("posts", "read");
        let delete_posts = Permission::new("posts", "delete");
        let read_users = Permission::new("users", "read");

        // 通配符匹配所有
        assert!(all.matches(&read_posts));
        assert!(all.matches(&delete_posts));
        assert!(all.matches(&read_users));

        // 资源通配符匹配特定资源的所有操作
        assert!(posts_all.matches(&read_posts));
        assert!(posts_all.matches(&delete_posts));
        assert!(!posts_all.matches(&read_users));

        // 精确匹配
        assert!(read_posts.matches(&read_posts));
        assert!(!read_posts.matches(&delete_posts));
    }

    #[test]
    fn test_permission_equality() {
        let p1 = Permission::new("posts", "read");
        let p2 = Permission::new("posts", "read");
        let p3 = Permission::new("posts", "write");

        assert_eq!(p1, p2);
        assert_ne!(p1, p3);
    }

    #[test]
    fn test_permission_display() {
        let perm = Permission::new("posts", "read");
        assert_eq!(format!("{}", perm), "posts:read");
    }

    #[test]
    fn test_resource() {
        let resource = Resource::new("posts");
        assert_eq!(resource.name(), "posts");
        assert!(resource.id().is_none());

        let resource_with_id = Resource::with_id("posts", "123");
        assert_eq!(resource_with_id.name(), "posts");
        assert_eq!(resource_with_id.id(), Some("123"));

        let resource_with_attr = Resource::new("posts").with_attribute("owner", "user1");
        assert_eq!(resource_with_attr.get_attribute("owner"), Some("user1"));
    }

    #[test]
    fn test_action() {
        let action = Action::new("read");
        assert_eq!(action.name(), "read");

        assert!(action.matches("read"));
        assert!(action.matches("*"));
        assert!(!action.matches("write"));

        // 预定义操作
        assert_eq!(Action::read().name(), "read");
        assert_eq!(Action::write().name(), "write");
        assert_eq!(Action::delete().name(), "delete");
    }

    #[test]
    fn test_permission_set() {
        let mut set = PermissionSet::new();

        let read_posts = Permission::new("posts", "read");
        let write_posts = Permission::new("posts", "write");
        let delete_posts = Permission::new("posts", "delete");

        set.add(read_posts.clone());
        set.add(write_posts.clone());

        assert!(set.contains(&read_posts));
        assert!(set.contains(&write_posts));
        assert!(!set.contains(&delete_posts));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_permission_set_wildcard() {
        let mut set = PermissionSet::new();
        set.add(Permission::resource_wildcard("posts"));

        // 通配符应该匹配所有 posts 操作
        assert!(set.contains(&Permission::new("posts", "read")));
        assert!(set.contains(&Permission::new("posts", "write")));
        assert!(set.contains(&Permission::new("posts", "delete")));

        // 不应该匹配其他资源
        assert!(!set.contains(&Permission::new("users", "read")));
    }

    #[test]
    fn test_permission_set_contains_all_any() {
        let mut set = PermissionSet::new();
        set.add(Permission::new("posts", "read"));
        set.add(Permission::new("posts", "write"));

        let check = vec![
            Permission::new("posts", "read"),
            Permission::new("posts", "write"),
        ];
        assert!(set.contains_all(&check));

        let check_fail = vec![
            Permission::new("posts", "read"),
            Permission::new("posts", "delete"),
        ];
        assert!(!set.contains_all(&check_fail));
        assert!(set.contains_any(&check_fail));
    }

    #[test]
    fn test_permission_set_merge() {
        let mut set1 = PermissionSet::new();
        set1.add(Permission::new("posts", "read"));

        let mut set2 = PermissionSet::new();
        set2.add(Permission::new("posts", "write"));
        set2.add(Permission::new("users", "read"));

        set1.merge(&set2);
        assert_eq!(set1.len(), 3);
        assert!(set1.contains(&Permission::new("posts", "read")));
        assert!(set1.contains(&Permission::new("posts", "write")));
        assert!(set1.contains(&Permission::new("users", "read")));
    }
}
