//! 策略引擎模块
//!
//! 提供基于策略的访问控制决策功能。

use super::permission::{Action, Resource, WILDCARD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// 策略效果
///
/// 定义策略的决策结果
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum PolicyEffect {
    /// 允许访问
    Allow,
    /// 拒绝访问
    #[default]
    Deny,
}

/// 访问主体
///
/// 表示发起访问请求的实体（通常是用户）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    /// 主体 ID
    pub id: String,
    /// 主体拥有的角色
    pub roles: HashSet<String>,
    /// 主体属性
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub attributes: HashMap<String, String>,
}

impl Subject {
    /// 创建新的主体
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            roles: HashSet::new(),
            attributes: HashMap::new(),
        }
    }

    /// 添加角色
    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.roles.insert(role.into());
        self
    }

    /// 添加多个角色
    pub fn with_roles<I, S>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.roles.extend(roles.into_iter().map(Into::into));
        self
    }

    /// 添加属性
    pub fn with_attribute(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// 获取主体 ID
    pub fn id(&self) -> &str {
        &self.id
    }

    /// 检查是否拥有某个角色
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(role)
    }

    /// 检查是否拥有任意一个角色
    pub fn has_any_role(&self, roles: &[&str]) -> bool {
        roles.iter().any(|r| self.roles.contains(*r))
    }

    /// 获取属性值
    pub fn get_attribute(&self, key: &str) -> Option<&str> {
        self.attributes.get(key).map(|s| s.as_str())
    }
}

/// 策略定义
///
/// 定义访问控制规则
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// 策略 ID
    pub id: String,
    /// 策略名称
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// 策略描述
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// 策略效果
    pub effect: PolicyEffect,
    /// 优先级（数值越大优先级越高）
    #[serde(default)]
    pub priority: i32,
    /// 目标角色（空表示匹配所有角色）
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub roles: HashSet<String>,
    /// 目标资源（空表示匹配所有资源）
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub resources: HashSet<String>,
    /// 目标操作（空表示匹配所有操作）
    #[serde(default, skip_serializing_if = "HashSet::is_empty")]
    pub actions: HashSet<String>,
    /// 条件表达式
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<PolicyCondition>,
    /// 策略是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 更新时间
    pub updated_at: DateTime<Utc>,
}

fn default_enabled() -> bool {
    true
}

impl Policy {
    /// 创建允许策略
    pub fn allow(id: impl Into<String>) -> PolicyBuilder {
        PolicyBuilder::new(id, PolicyEffect::Allow)
    }

    /// 创建拒绝策略
    pub fn deny(id: impl Into<String>) -> PolicyBuilder {
        PolicyBuilder::new(id, PolicyEffect::Deny)
    }

    /// 检查策略是否匹配请求
    pub fn matches(&self, subject: &Subject, resource: &Resource, action: &Action) -> bool {
        if !self.enabled {
            return false;
        }

        // 检查角色匹配
        if !self.roles.is_empty() {
            let role_matched = self
                .roles
                .iter()
                .any(|r| r == WILDCARD || subject.has_role(r));
            if !role_matched {
                return false;
            }
        }

        // 检查资源匹配
        if !self.resources.is_empty() {
            let resource_matched = self
                .resources
                .iter()
                .any(|r| r == WILDCARD || resource.matches_name(r));
            if !resource_matched {
                return false;
            }
        }

        // 检查操作匹配
        if !self.actions.is_empty() {
            let action_matched = self
                .actions
                .iter()
                .any(|a| a == WILDCARD || action.matches(a));
            if !action_matched {
                return false;
            }
        }

        // 检查条件
        if !self.conditions.is_empty() {
            return self
                .conditions
                .iter()
                .all(|c| c.evaluate(subject, resource, action));
        }

        true
    }
}

/// 策略条件
///
/// 用于定义更细粒度的访问控制条件
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    /// 条件类型
    pub condition_type: ConditionType,
    /// 条件键
    pub key: String,
    /// 条件值
    pub values: Vec<String>,
}

/// 条件类型
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConditionType {
    /// 字符串相等
    StringEquals,
    /// 字符串不相等
    StringNotEquals,
    /// 字符串以指定值开头
    StringLike,
    /// IP 地址匹配
    IpAddress,
    /// IP 地址不匹配
    NotIpAddress,
    /// 布尔条件
    Bool,
    /// 日期早于
    DateLessThan,
    /// 日期晚于
    DateGreaterThan,
}

impl PolicyCondition {
    /// 创建字符串相等条件
    pub fn string_equals(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            condition_type: ConditionType::StringEquals,
            key: key.into(),
            values: vec![value.into()],
        }
    }

    /// 创建字符串不相等条件
    pub fn string_not_equals(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            condition_type: ConditionType::StringNotEquals,
            key: key.into(),
            values: vec![value.into()],
        }
    }

    /// 评估条件
    pub fn evaluate(&self, subject: &Subject, resource: &Resource, _action: &Action) -> bool {
        let actual_value = match self.key.as_str() {
            // 主体属性
            key if key.starts_with("subject.") => {
                let attr_key = &key[8..];
                if attr_key == "id" {
                    Some(subject.id.as_str())
                } else {
                    subject.get_attribute(attr_key)
                }
            }
            // 资源属性
            key if key.starts_with("resource.") => {
                let attr_key = &key[9..];
                if attr_key == "name" {
                    Some(resource.name.as_str())
                } else if attr_key == "id" {
                    resource.id()
                } else {
                    resource.get_attribute(attr_key)
                }
            }
            _ => None,
        };

        match &self.condition_type {
            ConditionType::StringEquals => {
                actual_value.is_some_and(|v| self.values.contains(&v.to_string()))
            }
            ConditionType::StringNotEquals => {
                actual_value.is_none_or(|v| !self.values.contains(&v.to_string()))
            }
            ConditionType::StringLike => actual_value.is_some_and(|v| {
                self.values.iter().any(|pattern| {
                    if pattern.contains('*') {
                        let parts: Vec<&str> = pattern.split('*').collect();
                        if parts.len() == 2 {
                            v.starts_with(parts[0]) && v.ends_with(parts[1])
                        } else {
                            v.contains(pattern.trim_matches('*'))
                        }
                    } else {
                        v == pattern
                    }
                })
            }),
            _ => true, // 其他条件类型暂时返回 true
        }
    }
}

/// 策略构建器
pub struct PolicyBuilder {
    id: String,
    name: Option<String>,
    description: Option<String>,
    effect: PolicyEffect,
    priority: i32,
    roles: HashSet<String>,
    resources: HashSet<String>,
    actions: HashSet<String>,
    conditions: Vec<PolicyCondition>,
    enabled: bool,
}

impl PolicyBuilder {
    /// 创建新的策略构建器
    pub fn new(id: impl Into<String>, effect: PolicyEffect) -> Self {
        Self {
            id: id.into(),
            name: None,
            description: None,
            effect,
            priority: 0,
            roles: HashSet::new(),
            resources: HashSet::new(),
            actions: HashSet::new(),
            conditions: Vec::new(),
            enabled: true,
        }
    }

    /// 设置名称
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// 设置描述
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// 设置优先级
    pub fn priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// 添加目标角色
    pub fn role(mut self, role: impl Into<String>) -> Self {
        self.roles.insert(role.into());
        self
    }

    /// 添加多个目标角色
    pub fn roles<I, S>(mut self, roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.roles.extend(roles.into_iter().map(Into::into));
        self
    }

    /// 添加目标资源
    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.resources.insert(resource.into());
        self
    }

    /// 添加多个目标资源
    pub fn resources<I, S>(mut self, resources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.resources.extend(resources.into_iter().map(Into::into));
        self
    }

    /// 添加目标操作
    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.actions.insert(action.into());
        self
    }

    /// 添加多个目标操作
    pub fn actions<I, S>(mut self, actions: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.actions.extend(actions.into_iter().map(Into::into));
        self
    }

    /// 添加条件
    pub fn condition(mut self, condition: PolicyCondition) -> Self {
        self.conditions.push(condition);
        self
    }

    /// 设置是否启用
    pub fn enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// 构建策略
    pub fn build(self) -> Policy {
        let now = Utc::now();
        Policy {
            id: self.id,
            name: self.name,
            description: self.description,
            effect: self.effect,
            priority: self.priority,
            roles: self.roles,
            resources: self.resources,
            actions: self.actions,
            conditions: self.conditions,
            enabled: self.enabled,
            created_at: now,
            updated_at: now,
        }
    }
}

/// 决策结果
#[derive(Debug, Clone)]
pub struct Decision {
    /// 决策效果
    pub effect: PolicyEffect,
    /// 决策原因
    pub reason: DecisionReason,
    /// 匹配的策略 ID
    pub matched_policy: Option<String>,
}

impl Decision {
    /// 创建允许决策
    pub fn allow(policy_id: impl Into<String>) -> Self {
        Self {
            effect: PolicyEffect::Allow,
            reason: DecisionReason::PolicyMatched,
            matched_policy: Some(policy_id.into()),
        }
    }

    /// 创建拒绝决策
    pub fn deny(policy_id: impl Into<String>) -> Self {
        Self {
            effect: PolicyEffect::Deny,
            reason: DecisionReason::PolicyMatched,
            matched_policy: Some(policy_id.into()),
        }
    }

    /// 创建默认拒绝决策
    pub fn default_deny() -> Self {
        Self {
            effect: PolicyEffect::Deny,
            reason: DecisionReason::NoMatchingPolicy,
            matched_policy: None,
        }
    }

    /// 检查是否允许
    pub fn is_allowed(&self) -> bool {
        self.effect == PolicyEffect::Allow
    }

    /// 检查是否拒绝
    pub fn is_denied(&self) -> bool {
        self.effect == PolicyEffect::Deny
    }
}

/// 决策原因
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionReason {
    /// 策略匹配
    PolicyMatched,
    /// 无匹配策略（默认拒绝）
    NoMatchingPolicy,
    /// 显式拒绝
    ExplicitDeny,
}

/// 策略评估器 trait
///
/// 定义策略评估的接口
pub trait PolicyEvaluator {
    /// 评估访问请求
    fn evaluate(&self, subject: &Subject, resource: &Resource, action: &Action) -> Decision;
}

/// 策略引擎
///
/// 管理策略并进行访问控制决策
///
/// ## 决策逻辑
///
/// 1. 收集所有匹配的策略
/// 2. 按优先级排序（高优先级优先）
/// 3. 如果有任何拒绝策略匹配，则拒绝（Deny 优先）
/// 4. 如果有任何允许策略匹配，则允许
/// 5. 如果没有匹配策略，默认拒绝
#[derive(Debug, Default)]
pub struct PolicyEngine {
    policies: HashMap<String, Policy>,
}

impl PolicyEngine {
    /// 创建新的策略引擎
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
        }
    }

    /// 添加策略
    pub fn add_policy(&mut self, policy: Policy) {
        self.policies.insert(policy.id.clone(), policy);
    }

    /// 移除策略
    pub fn remove_policy(&mut self, id: &str) -> Option<Policy> {
        self.policies.remove(id)
    }

    /// 获取策略
    pub fn get_policy(&self, id: &str) -> Option<&Policy> {
        self.policies.get(id)
    }

    /// 获取可变策略引用
    pub fn get_policy_mut(&mut self, id: &str) -> Option<&mut Policy> {
        self.policies.get_mut(id)
    }

    /// 列出所有策略
    pub fn list_policies(&self) -> Vec<&Policy> {
        self.policies.values().collect()
    }

    /// 获取策略数量
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    /// 清空所有策略
    pub fn clear(&mut self) {
        self.policies.clear();
    }

    /// 获取匹配的策略列表（按优先级排序）
    fn get_matching_policies(
        &self,
        subject: &Subject,
        resource: &Resource,
        action: &Action,
    ) -> Vec<&Policy> {
        let mut matching: Vec<_> = self
            .policies
            .values()
            .filter(|p| p.matches(subject, resource, action))
            .collect();

        // 按优先级降序排序
        matching.sort_by(|a, b| b.priority.cmp(&a.priority));
        matching
    }

    /// 检查权限（简化接口）
    pub fn check_permission(&self, subject: &Subject, resource: &str, action: &str) -> bool {
        self.evaluate(subject, &Resource::new(resource), &Action::new(action))
            .is_allowed()
    }

    /// 批量检查权限
    pub fn check_permissions(
        &self,
        subject: &Subject,
        permissions: &[(String, String)],
    ) -> HashMap<(String, String), bool> {
        permissions
            .iter()
            .map(|(resource, action)| {
                let allowed = self.check_permission(subject, resource, action);
                ((resource.clone(), action.clone()), allowed)
            })
            .collect()
    }
}

impl PolicyEvaluator for PolicyEngine {
    fn evaluate(&self, subject: &Subject, resource: &Resource, action: &Action) -> Decision {
        let matching = self.get_matching_policies(subject, resource, action);

        if matching.is_empty() {
            return Decision::default_deny();
        }

        // 检查是否有拒绝策略（Deny 优先）
        for policy in &matching {
            if policy.effect == PolicyEffect::Deny {
                return Decision::deny(&policy.id);
            }
        }

        // 检查是否有允许策略
        for policy in &matching {
            if policy.effect == PolicyEffect::Allow {
                return Decision::allow(&policy.id);
            }
        }

        Decision::default_deny()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subject() {
        let subject = Subject::new("user1")
            .with_role("editor")
            .with_role("viewer")
            .with_attribute("department", "engineering");

        assert_eq!(subject.id(), "user1");
        assert!(subject.has_role("editor"));
        assert!(subject.has_role("viewer"));
        assert!(!subject.has_role("admin"));
        assert_eq!(subject.get_attribute("department"), Some("engineering"));
    }

    #[test]
    fn test_policy_builder() {
        let policy = Policy::allow("test-policy")
            .name("Test Policy")
            .description("A test policy")
            .priority(10)
            .role("editor")
            .resource("posts")
            .action("read")
            .build();

        assert_eq!(policy.id, "test-policy");
        assert_eq!(policy.name, Some("Test Policy".to_string()));
        assert_eq!(policy.effect, PolicyEffect::Allow);
        assert_eq!(policy.priority, 10);
        assert!(policy.roles.contains("editor"));
        assert!(policy.resources.contains("posts"));
        assert!(policy.actions.contains("read"));
    }

    #[test]
    fn test_policy_matching() {
        let policy = Policy::allow("editor-posts")
            .role("editor")
            .resource("posts")
            .action("read")
            .build();

        let editor = Subject::new("user1").with_role("editor");
        let viewer = Subject::new("user2").with_role("viewer");

        let posts = Resource::new("posts");
        let users = Resource::new("users");

        let read = Action::new("read");
        let write = Action::new("write");

        // 应该匹配
        assert!(policy.matches(&editor, &posts, &read));

        // 不应该匹配 - 角色不对
        assert!(!policy.matches(&viewer, &posts, &read));

        // 不应该匹配 - 资源不对
        assert!(!policy.matches(&editor, &users, &read));

        // 不应该匹配 - 操作不对
        assert!(!policy.matches(&editor, &posts, &write));
    }

    #[test]
    fn test_policy_wildcard_matching() {
        let policy = Policy::allow("admin-all")
            .role("admin")
            .resource("*")
            .action("*")
            .build();

        let admin = Subject::new("admin1").with_role("admin");
        let posts = Resource::new("posts");
        let users = Resource::new("users");
        let read = Action::new("read");
        let delete = Action::new("delete");

        // 应该匹配所有资源和操作
        assert!(policy.matches(&admin, &posts, &read));
        assert!(policy.matches(&admin, &users, &delete));
    }

    #[test]
    fn test_policy_engine_basic() {
        let mut engine = PolicyEngine::new();

        engine.add_policy(
            Policy::allow("editor-posts-read")
                .role("editor")
                .resource("posts")
                .action("read")
                .build(),
        );

        let editor = Subject::new("user1").with_role("editor");
        let viewer = Subject::new("user2").with_role("viewer");

        // editor 可以读取 posts
        let decision = engine.evaluate(&editor, &Resource::new("posts"), &Action::new("read"));
        assert!(decision.is_allowed());

        // viewer 不能读取 posts
        let decision = engine.evaluate(&viewer, &Resource::new("posts"), &Action::new("read"));
        assert!(decision.is_denied());
    }

    #[test]
    fn test_policy_engine_deny_priority() {
        let mut engine = PolicyEngine::new();

        // 允许策略
        engine.add_policy(
            Policy::allow("editor-posts-all")
                .role("editor")
                .resource("posts")
                .action("*")
                .build(),
        );

        // 拒绝策略（更高优先级）
        engine.add_policy(
            Policy::deny("no-delete")
                .resource("posts")
                .action("delete")
                .priority(100)
                .build(),
        );

        let editor = Subject::new("user1").with_role("editor");

        // 可以读取
        let decision = engine.evaluate(&editor, &Resource::new("posts"), &Action::new("read"));
        assert!(decision.is_allowed());

        // 不能删除（被高优先级拒绝策略阻止）
        let decision = engine.evaluate(&editor, &Resource::new("posts"), &Action::new("delete"));
        assert!(decision.is_denied());
    }

    #[test]
    fn test_policy_engine_multiple_roles() {
        let mut engine = PolicyEngine::new();

        engine.add_policy(
            Policy::allow("viewer-read")
                .role("viewer")
                .resource("posts")
                .action("read")
                .build(),
        );

        engine.add_policy(
            Policy::allow("editor-write")
                .role("editor")
                .resource("posts")
                .action("write")
                .build(),
        );

        // 用户同时拥有两个角色
        let user = Subject::new("user1")
            .with_role("viewer")
            .with_role("editor");

        // 可以读取（来自 viewer 角色）
        assert!(engine.check_permission(&user, "posts", "read"));

        // 可以写入（来自 editor 角色）
        assert!(engine.check_permission(&user, "posts", "write"));

        // 不能删除（没有对应策略）
        assert!(!engine.check_permission(&user, "posts", "delete"));
    }

    #[test]
    fn test_policy_condition() {
        let condition = PolicyCondition::string_equals("subject.department", "engineering");

        let user_eng = Subject::new("user1").with_attribute("department", "engineering");
        let user_sales = Subject::new("user2").with_attribute("department", "sales");

        let resource = Resource::new("code");
        let action = Action::new("read");

        assert!(condition.evaluate(&user_eng, &resource, &action));
        assert!(!condition.evaluate(&user_sales, &resource, &action));
    }

    #[test]
    fn test_policy_with_condition() {
        let mut engine = PolicyEngine::new();

        engine.add_policy(
            Policy::allow("eng-code-access")
                .resource("code")
                .action("read")
                .condition(PolicyCondition::string_equals(
                    "subject.department",
                    "engineering",
                ))
                .build(),
        );

        let user_eng = Subject::new("user1").with_attribute("department", "engineering");
        let user_sales = Subject::new("user2").with_attribute("department", "sales");

        // 工程部门可以访问
        assert!(engine.check_permission(&user_eng, "code", "read"));

        // 销售部门不能访问
        assert!(!engine.check_permission(&user_sales, "code", "read"));
    }

    #[test]
    fn test_disabled_policy() {
        let mut engine = PolicyEngine::new();

        engine.add_policy(
            Policy::allow("disabled-policy")
                .role("editor")
                .resource("posts")
                .action("read")
                .enabled(false)
                .build(),
        );

        let editor = Subject::new("user1").with_role("editor");

        // 禁用的策略不应该匹配
        let decision = engine.evaluate(&editor, &Resource::new("posts"), &Action::new("read"));
        assert!(decision.is_denied());
        assert_eq!(decision.reason, DecisionReason::NoMatchingPolicy);
    }

    #[test]
    fn test_decision() {
        let allow = Decision::allow("test-policy");
        assert!(allow.is_allowed());
        assert!(!allow.is_denied());

        let deny = Decision::deny("test-policy");
        assert!(deny.is_denied());
        assert!(!deny.is_allowed());

        let default_deny = Decision::default_deny();
        assert!(default_deny.is_denied());
        assert_eq!(default_deny.reason, DecisionReason::NoMatchingPolicy);
    }

    #[test]
    fn test_batch_check_permissions() {
        let mut engine = PolicyEngine::new();

        engine.add_policy(
            Policy::allow("editor-posts")
                .role("editor")
                .resource("posts")
                .actions(["read", "write"])
                .build(),
        );

        let editor = Subject::new("user1").with_role("editor");

        let permissions = vec![
            ("posts".to_string(), "read".to_string()),
            ("posts".to_string(), "write".to_string()),
            ("posts".to_string(), "delete".to_string()),
            ("users".to_string(), "read".to_string()),
        ];

        let results = engine.check_permissions(&editor, &permissions);

        assert_eq!(results[&("posts".to_string(), "read".to_string())], true);
        assert_eq!(results[&("posts".to_string(), "write".to_string())], true);
        assert_eq!(results[&("posts".to_string(), "delete".to_string())], false);
        assert_eq!(results[&("users".to_string(), "read".to_string())], false);
    }
}
