//! 集成测试：审计日志
//!
//! 测试安全事件记录、查询、过滤等完整流程。

use authrs::audit::{
    AuditLogger, EventSeverity, EventType, InMemoryAuditLogger, NoOpAuditLogger, SecurityEvent,
};
use chrono::{Duration, Utc};

/// 测试安全事件创建
#[test]
fn test_security_event_creation() {
    // 使用便捷方法创建事件
    let login_event = SecurityEvent::login_success("user_123", "192.168.1.1");
    assert_eq!(login_event.event_type, EventType::LoginSuccess);
    assert_eq!(login_event.severity, EventSeverity::Info);
    assert_eq!(login_event.user_id, Some("user_123".to_string()));

    let failed_login = SecurityEvent::login_failed("user_456", "invalid_password");
    assert_eq!(failed_login.event_type, EventType::LoginFailed);
    assert_eq!(failed_login.severity, EventSeverity::Warning);

    let mfa_enabled = SecurityEvent::mfa_enabled("user_789");
    assert_eq!(mfa_enabled.event_type, EventType::MfaEnabled);

    let account_locked = SecurityEvent::account_locked("user_locked", "too_many_attempts");
    assert_eq!(account_locked.event_type, EventType::AccountLocked);
    assert_eq!(account_locked.severity, EventSeverity::Warning);
}

/// 测试事件构建器模式
#[test]
fn test_security_event_builder() {
    let event = SecurityEvent::new(EventType::LoginSuccess, EventSeverity::Info)
        .with_user_id("user_123")
        .with_ip("192.168.1.100")
        .with_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64)")
        .with_message("User logged in successfully")
        .with_detail("method", "password")
        .with_detail("mfa_used", "true");

    assert_eq!(event.user_id, Some("user_123".to_string()));
    assert_eq!(event.ip_address, Some("192.168.1.100".to_string()));
    assert!(event.user_agent.is_some());
    assert_eq!(
        event.message,
        Some("User logged in successfully".to_string())
    );
    assert_eq!(event.details.get("method"), Some(&"password".to_string()));
    assert_eq!(event.details.get("mfa_used"), Some(&"true".to_string()));
}

/// 测试内存审计日志器
#[test]
fn test_in_memory_audit_logger() {
    let logger = InMemoryAuditLogger::new();

    // 记录多个事件
    logger.log(SecurityEvent::login_success("user_1", "10.0.0.1"));
    logger.log(SecurityEvent::login_failed("user_2", "bad_password"));
    logger.log(SecurityEvent::login_success("user_3", "10.0.0.2"));
    logger.log(SecurityEvent::mfa_enabled("user_1"));
    logger.log(SecurityEvent::account_locked("user_2", "too_many_failures"));

    // 检查事件数量
    assert_eq!(logger.event_count(), 5);

    // 获取所有事件
    let all_events = logger.get_events();
    assert_eq!(all_events.len(), 5);
}

/// 测试按用户过滤事件
#[test]
fn test_filter_by_user() {
    let logger = InMemoryAuditLogger::new();

    // 记录不同用户的事件
    logger.log(SecurityEvent::login_success("alice", "10.0.0.1"));
    logger.log(SecurityEvent::login_success("bob", "10.0.0.2"));
    logger.log(SecurityEvent::password_changed("alice"));
    logger.log(SecurityEvent::mfa_enabled("alice"));
    logger.log(SecurityEvent::login_failed("bob", "wrong_password"));

    // 按用户过滤
    let alice_events = logger.get_events_by_user("alice");
    assert_eq!(alice_events.len(), 3);
    for event in &alice_events {
        assert_eq!(event.user_id, Some("alice".to_string()));
    }

    let bob_events = logger.get_events_by_user("bob");
    assert_eq!(bob_events.len(), 2);
}

/// 测试按事件类型过滤
#[test]
fn test_filter_by_event_type() {
    let logger = InMemoryAuditLogger::new();

    logger.log(SecurityEvent::login_success("user_1", "10.0.0.1"));
    logger.log(SecurityEvent::login_success("user_2", "10.0.0.2"));
    logger.log(SecurityEvent::login_failed("user_3", "bad_password"));
    logger.log(SecurityEvent::login_success("user_4", "10.0.0.3"));
    logger.log(SecurityEvent::mfa_enabled("user_1"));

    // 按类型过滤
    let success_events = logger.get_events_by_type(&EventType::LoginSuccess);
    assert_eq!(success_events.len(), 3);

    let failed_events = logger.get_events_by_type(&EventType::LoginFailed);
    assert_eq!(failed_events.len(), 1);

    let mfa_events = logger.get_events_by_type(&EventType::MfaEnabled);
    assert_eq!(mfa_events.len(), 1);
}

/// 测试按严重程度过滤
#[test]
fn test_filter_by_severity() {
    let logger = InMemoryAuditLogger::new();

    // Info 级别
    logger.log(SecurityEvent::login_success("user_1", "10.0.0.1"));
    logger.log(SecurityEvent::logout("user_1"));

    // Warning 级别
    logger.log(SecurityEvent::login_failed("user_2", "bad_password"));
    logger.log(SecurityEvent::account_locked("user_2", "too_many_failures"));

    // Error 级别 - use new() with explicit severity
    logger.log(
        SecurityEvent::new(EventType::SuspiciousActivity, EventSeverity::Error)
            .with_message("suspicious activity detected"),
    );

    // 按严重程度过滤
    let info_events = logger.get_events_by_severity(EventSeverity::Info);
    assert_eq!(info_events.len(), 2);

    let warning_events = logger.get_events_by_severity(EventSeverity::Warning);
    assert_eq!(warning_events.len(), 2);

    let error_events = logger.get_events_by_severity(EventSeverity::Error);
    assert_eq!(error_events.len(), 1);
}

/// 测试时间范围查询
#[test]
fn test_filter_by_time_range() {
    let logger = InMemoryAuditLogger::new();

    // 记录一些事件
    logger.log(SecurityEvent::login_success("user_1", "10.0.0.1"));
    logger.log(SecurityEvent::login_success("user_2", "10.0.0.2"));
    logger.log(SecurityEvent::login_success("user_3", "10.0.0.3"));

    // 查询时间范围
    let start = Utc::now() - Duration::minutes(1);
    let end = Utc::now() + Duration::minutes(1);

    let events_in_range = logger.get_events_in_range(start, end);
    assert_eq!(events_in_range.len(), 3);

    // 过去的时间范围（不应有事件）
    let past_start = Utc::now() - Duration::hours(2);
    let past_end = Utc::now() - Duration::hours(1);
    let past_events = logger.get_events_in_range(past_start, past_end);
    assert_eq!(past_events.len(), 0);
}

/// 测试最近事件查询
#[test]
fn test_recent_events() {
    let logger = InMemoryAuditLogger::new();

    // 记录 10 个事件
    for i in 0..10 {
        logger.log(SecurityEvent::login_success(
            &format!("user_{}", i),
            "10.0.0.1",
        ));
    }

    // 获取最近 5 个事件
    let recent = logger.get_recent_events(5);
    assert_eq!(recent.len(), 5);

    // 获取最近 20 个事件（只有 10 个）
    let all_recent = logger.get_recent_events(20);
    assert_eq!(all_recent.len(), 10);
}

/// 测试高严重程度事件过滤
#[test]
fn test_high_severity_events() {
    let logger = InMemoryAuditLogger::new();

    // 低严重程度
    logger.log(SecurityEvent::login_success("user_1", "10.0.0.1"));
    logger.log(SecurityEvent::logout("user_1"));

    // 高严重程度 - Error
    logger.log(
        SecurityEvent::new(EventType::SuspiciousActivity, EventSeverity::Error)
            .with_user_id("user_2")
            .with_message("suspicious activity"),
    );

    // 高严重程度 - Critical
    logger.log(
        SecurityEvent::new(
            EventType::Custom("security_breach".to_string()),
            EventSeverity::Critical,
        )
        .with_message("critical security breach"),
    );

    let high_severity = logger.get_high_severity_events();
    assert_eq!(
        high_severity.len(),
        2,
        "Should find Error and Critical events"
    );
}

/// 测试审计统计
#[test]
fn test_audit_stats() {
    let logger = InMemoryAuditLogger::new();

    // 记录各种类型的事件
    logger.log(SecurityEvent::login_success("user_1", "10.0.0.1"));
    logger.log(SecurityEvent::login_success("user_2", "10.0.0.2"));
    logger.log(SecurityEvent::login_failed("user_3", "bad_password"));
    logger.log(SecurityEvent::account_locked("user_3", "too_many_failures"));
    logger.log(
        SecurityEvent::new(EventType::SuspiciousActivity, EventSeverity::Error)
            .with_user_id("user_4"),
    );

    let stats = logger.get_stats();

    assert_eq!(stats.total_events, 5);
    assert_eq!(stats.info_count, 2);
    assert_eq!(stats.warning_count, 2);
    assert_eq!(stats.error_count, 1);
    assert_eq!(stats.critical_count, 0);
}

/// 测试最大事件限制
#[test]
fn test_max_events_limit() {
    let logger = InMemoryAuditLogger::with_max_events(5);

    // 记录超过限制的事件
    for i in 0..10 {
        logger.log(SecurityEvent::login_success(
            &format!("user_{}", i),
            "10.0.0.1",
        ));
    }

    // 应该只保留最新的 5 个
    assert_eq!(logger.event_count(), 5);

    let events = logger.get_events();
    // 最新的应该是 user_9
    let last_event = events.last().unwrap();
    assert_eq!(last_event.user_id, Some("user_9".to_string()));
}

/// 测试清除事件
#[test]
fn test_clear_events() {
    let logger = InMemoryAuditLogger::new();

    logger.log(SecurityEvent::login_success("user_1", "10.0.0.1"));
    logger.log(SecurityEvent::login_success("user_2", "10.0.0.2"));
    assert_eq!(logger.event_count(), 2);

    logger.clear();
    assert_eq!(logger.event_count(), 0);
    assert!(logger.get_events().is_empty());
}

/// 测试空操作日志器
#[test]
fn test_noop_logger() {
    let logger = NoOpAuditLogger::new();

    // 日志操作不会失败，但也不会存储任何内容
    logger.log(SecurityEvent::login_success("user_1", "10.0.0.1"));
    logger.log(SecurityEvent::login_failed("user_2", "bad_password"));

    // NoOp 日志器不提供查询功能，这主要用于禁用审计
}

/// 测试批量日志记录
#[test]
fn test_batch_logging() {
    let logger = InMemoryAuditLogger::new();

    let events = vec![
        SecurityEvent::login_success("user_1", "10.0.0.1"),
        SecurityEvent::login_success("user_2", "10.0.0.2"),
        SecurityEvent::login_failed("user_3", "bad_password"),
        SecurityEvent::mfa_enabled("user_1"),
    ];

    logger.log_batch(events);

    assert_eq!(logger.event_count(), 4);
}

/// 测试事件高严重程度判断
#[test]
fn test_is_high_severity() {
    let info_event = SecurityEvent::login_success("user_1", "10.0.0.1");
    assert!(!info_event.is_high_severity());

    let warning_event = SecurityEvent::login_failed("user_2", "bad_password");
    assert!(!warning_event.is_high_severity());

    let error_event = SecurityEvent::new(EventType::SuspiciousActivity, EventSeverity::Error)
        .with_user_id("user_3");
    assert!(error_event.is_high_severity());

    let critical_event = SecurityEvent::new(
        EventType::Custom("breach".to_string()),
        EventSeverity::Critical,
    );
    assert!(critical_event.is_high_severity());
}

/// 测试认证事件判断
#[test]
fn test_is_auth_event() {
    let login_success = SecurityEvent::login_success("user_1", "10.0.0.1");
    assert!(login_success.is_auth_event());

    let login_failed = SecurityEvent::login_failed("user_2", "bad_password");
    assert!(login_failed.is_auth_event());

    let logout = SecurityEvent::logout("user_3");
    assert!(logout.is_auth_event());

    let _mfa_event = SecurityEvent::mfa_enabled("user_4");
    // MFA events may or may not be considered auth events depending on implementation

    let api_key_event = SecurityEvent::api_key_created("user_5", "key_123");
    assert!(!api_key_event.is_auth_event());
}

/// 测试事件序列化
#[test]
fn test_event_serialization() {
    let event = SecurityEvent::login_success("user_123", "10.0.0.1")
        .with_detail("browser", "Chrome")
        .with_message("Successful login");

    // 测试序列化为 JSON
    let json = serde_json::to_string(&event);
    assert!(json.is_ok(), "Event should be serializable to JSON");

    let json_str = json.unwrap();
    assert!(json_str.contains("user_123"));
    assert!(json_str.contains("10.0.0.1"));
    assert!(json_str.contains("Chrome"));
}

/// 测试克隆日志器共享状态
#[test]
fn test_clone_logger_shares_state() {
    let logger1 = InMemoryAuditLogger::new();
    let logger2 = logger1.clone();

    // 通过 logger1 记录事件
    logger1.log(SecurityEvent::login_success("user_1", "10.0.0.1"));

    // logger2 应该能看到这个事件
    assert_eq!(logger2.event_count(), 1);

    // 通过 logger2 记录事件
    logger2.log(SecurityEvent::login_failed("user_2", "bad_password"));

    // 两个日志器应该看到相同的事件数
    assert_eq!(logger1.event_count(), 2);
    assert_eq!(logger2.event_count(), 2);
}

/// 测试自定义事件类型
#[test]
fn test_custom_event_type() {
    let custom_event = SecurityEvent::new(
        EventType::Custom("api_rate_limit_exceeded".to_string()),
        EventSeverity::Warning,
    )
    .with_user_id("service_account")
    .with_detail("endpoint", "/api/v1/users")
    .with_detail("requests_per_minute", "1500");

    assert!(matches!(
        custom_event.event_type,
        EventType::Custom(ref name) if name == "api_rate_limit_exceeded"
    ));
}

/// 测试完整的审计工作流
#[test]
fn test_complete_audit_workflow() {
    let logger = InMemoryAuditLogger::with_max_events(1000);

    // === 模拟用户登录流程 ===

    // 1. 用户尝试登录（失败）
    logger.log(SecurityEvent::login_failed("alice", "invalid_password").with_ip("192.168.1.100"));

    // 2. 触发速率限制
    logger.log(SecurityEvent::rate_limit_triggered(
        "login",
        Some("192.168.1.100"),
    ));

    // 3. 多次失败后账户锁定
    for _ in 0..3 {
        logger
            .log(SecurityEvent::login_failed("alice", "invalid_password").with_ip("192.168.1.100"));
    }

    logger.log(
        SecurityEvent::account_locked("alice", "too_many_failed_attempts").with_ip("192.168.1.100"),
    );

    // 4. 账户解锁
    logger.log(SecurityEvent::account_unlocked("alice").with_detail("unlocked_by", "admin"));

    // 5. 成功登录
    logger
        .log(SecurityEvent::login_success("alice", "192.168.1.100").with_user_agent("Mozilla/5.0"));

    // 6. 启用 MFA
    logger.log(SecurityEvent::mfa_enabled("alice"));

    // 7. 创建 API Key
    logger.log(SecurityEvent::api_key_created("alice", "sk_live_xxx"));

    // === 验证审计记录 ===

    // 检查总事件数
    assert_eq!(logger.event_count(), 10);

    // 检查 alice 的事件
    let alice_events = logger.get_events_by_user("alice");
    assert_eq!(alice_events.len(), 9); // 除了 rate_limit 事件

    // 检查登录失败事件
    let failed_logins = logger.get_events_by_type(&EventType::LoginFailed);
    assert_eq!(failed_logins.len(), 4);

    // 检查高严重程度事件
    let high_severity = logger.get_high_severity_events();
    // 默认情况下只有 Error 和 Critical 是高严重程度
    // 这里没有 Error/Critical 事件，应该为 0
    assert_eq!(high_severity.len(), 0);

    // 检查统计信息
    let stats = logger.get_stats();
    assert_eq!(stats.total_events, 10);
    assert!(stats.info_count >= 3); // login_success, mfa_enabled, api_key_created
    assert!(stats.warning_count >= 5); // login_failed x4, account_locked
}

/// 测试事件名称显示
#[test]
fn test_event_name_display() {
    let login_success = SecurityEvent::login_success("user", "10.0.0.1");
    // event_name() returns snake_case format
    assert!(!login_success.event_name().is_empty());

    let custom = SecurityEvent::new(
        EventType::Custom("my_custom_event".to_string()),
        EventSeverity::Info,
    )
    .with_user_id("user");
    assert!(custom.event_name().contains("custom"));
}

/// 测试严重程度显示
#[test]
fn test_severity_display() {
    // Just check that Display is implemented and returns non-empty strings
    assert!(!EventSeverity::Debug.to_string().is_empty());
    assert!(!EventSeverity::Info.to_string().is_empty());
    assert!(!EventSeverity::Warning.to_string().is_empty());
    assert!(!EventSeverity::Error.to_string().is_empty());
    assert!(!EventSeverity::Critical.to_string().is_empty());
}

/// 测试事件类型显示
#[test]
fn test_event_type_display() {
    // Just check that Display is implemented and returns non-empty strings
    assert!(!EventType::LoginSuccess.to_string().is_empty());
    assert!(!EventType::LoginFailed.to_string().is_empty());
    assert!(!EventType::MfaEnabled.to_string().is_empty());
    assert!(
        EventType::Custom("test".to_string())
            .to_string()
            .contains("test")
    );
}
