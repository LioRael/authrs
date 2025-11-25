# AuthRS 功能路线图

本文档记录 AuthRS 库的功能规划和未来发展方向。

## ✅ 当前已有功能

| 模块 | 功能 | 状态 |
|------|------|------|
| **password/** | Argon2/bcrypt 哈希、密码强度验证 | ✅ 完成 |
| **token/** | JWT (多算法)、Refresh Token、Session 管理 | ✅ 完成 |
| **mfa/** | TOTP/HOTP、恢复码 | ✅ 完成 |
| **security/** | CSRF 防护、速率限制 (滑动窗口/固定窗口/令牌桶) | ✅ 完成 |
| **security/account** | 账户锁定、登录追踪、递增延迟、IP 封禁 | ✅ 完成 |
| **oauth/** | OAuth 客户端管理、PKCE (S256/plain)、Token 内省 | ✅ 完成 |
| **api_key/** | API Key 管理（哈希存储、权限范围、过期、轮换） | ✅ 完成 |
| **webauthn/** | WebAuthn / Passkeys（注册、认证、凭证管理） | ✅ 完成 |
| **random.rs** | 安全随机数、常量时间比较 | ✅ 完成 |
| **error.rs** | 统一错误类型 | ✅ 完成 |

---

## 🚀 计划增加的功能/模块

### 🔴 高优先级

#### 1. ~~OAuth 2.0 / OpenID Connect 模块~~ ✅ 已完成

现代应用经常需要 OAuth 支持，包括第三方登录。

```
src/oauth/
├── mod.rs           ✅
├── client.rs        ✅ OAuth 客户端凭证
├── pkce.rs          ✅ PKCE 支持 (S256/plain)
├── token.rs         ✅ OAuth token 结构
└── introspection.rs ✅ Token 内省
```

**功能点：**
- [x] Client Credentials Grant
- [x] PKCE (Proof Key for Code Exchange)
- [x] Token Introspection
- [ ] Authorization Code Flow (完整实现需要 HTTP 框架集成)
- [ ] Refresh Token 流程 (完整实现需要 HTTP 框架集成)

#### 2. ~~WebAuthn / Passkeys 模块~~ ✅ 已完成

无密码认证是趋势，Apple/Google 都在推广。

```
src/webauthn/
├── mod.rs           ✅ 模块入口、WebAuthnService 封装
├── registration.rs  ✅ 注册流程、配置、状态管理
├── authentication.rs ✅ 认证流程、配置、状态管理
└── credential.rs    ✅ 凭证管理、存储接口
```

**功能点：**
- [x] 注册 (Registration) 流程
- [x] 认证 (Authentication) 流程
- [x] 凭证存储接口 (CredentialStore trait)
- [x] 支持 Passkeys (基于 webauthn-rs)
- [x] 内存存储实现（用于测试/开发）
- [x] 用户验证策略配置
- [x] 会话状态管理

---

### 🟡 中优先级

#### 3. ~~账户安全模块~~ ✅ 已完成

扩展现有 `security/` 模块，增加账户级别的安全防护。

```rust
// security/account.rs ✅

pub struct AccountLockoutConfig { ... }  // ✅ 账户锁定配置
pub struct LoginAttemptTracker { ... }   // ✅ 登录尝试追踪
pub struct AccountLockStatus { ... }     // ✅ 账户锁定状态
pub enum LoginCheckResult { ... }        // ✅ 登录检查结果
pub enum LockReason { ... }              // ✅ 锁定原因
```

**功能点：**
- [x] 账户锁定机制
- [x] 登录尝试追踪
- [x] 递增延迟策略（指数退避）
- [x] 与现有 `rate_limit` 模块集成
- [x] IP 地址追踪和封禁
- [x] 手动锁定/解锁

#### 4. ~~API Key 管理模块 (增强版)~~ ✅ 已完成

扩展现有的 `generate_api_key` 功能。

```rust
// src/api_key/ ✅

pub struct ApiKey { ... }           // ✅ API Key 结构
pub struct ApiKeyManager { ... }    // ✅ API Key 管理器
pub struct ApiKeyConfig { ... }     // ✅ 配置
pub trait ApiKeyStore { ... }       // ✅ 存储 trait
```

**功能点：**
- [x] API Key 创建与验证
- [x] Key 哈希存储（不存明文）
- [x] 权限范围 (Scopes)
- [x] 过期时间支持
- [x] Key 轮换
- [x] 使用统计

#### 5. 权限/RBAC 模块

基础的角色权限管理。

```
src/rbac/
├── mod.rs
├── role.rs        # 角色定义
├── permission.rs  # 权限检查
└── policy.rs      # 策略引擎
```

**功能点：**
- [ ] 角色定义
- [ ] 权限定义与检查
- [ ] 角色-权限映射
- [ ] 简单策略引擎

---

### 🟢 低优先级

#### 6. Passwordless 认证模块

```
src/passwordless/
├── mod.rs
├── magic_link.rs   # 魔法链接
├── email_otp.rs    # 邮件一次性密码
└── sms_otp.rs      # 短信一次性密码
```

**功能点：**
- [ ] Magic Link 生成与验证
- [ ] Email OTP
- [ ] SMS OTP

#### 7. 安全 Cookie 助手

```rust
// security/cookie.rs

pub struct SecureCookie {
    pub name: String,
    pub value: String,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: SameSite,
    pub max_age: Option<Duration>,
}

pub fn sign_cookie(value: &str, secret: &[u8]) -> String;
pub fn verify_cookie(signed: &str, secret: &[u8]) -> Result<String>;
```

**功能点：**
- [ ] Cookie 签名
- [ ] Cookie 验证
- [ ] 安全属性封装

#### 8. 密钥派生函数

```rust
// src/crypto/kdf.rs

// HKDF 用于从主密钥派生子密钥
pub fn hkdf_sha256(
    secret: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>>;
```

**功能点：**
- [ ] HKDF-SHA256
- [ ] HKDF-SHA512

#### 9. 审计日志 Trait

```rust
// src/audit.rs

pub enum SecurityEvent {
    LoginSuccess { user_id: String, ip: String },
    LoginFailed { user_id: String, reason: String },
    PasswordChanged { user_id: String },
    MfaEnabled { user_id: String },
    SuspiciousActivity { details: String },
}

pub trait AuditLogger {
    fn log(&self, event: SecurityEvent);
}
```

**功能点：**
- [ ] 安全事件枚举
- [ ] 日志 Trait 定义
- [ ] 简单内存实现（用于测试）

#### 10. scrypt 密码哈希

在 `password/hasher.rs` 中增加 scrypt 支持作为另一个算法选项。

**功能点：**
- [ ] scrypt 哈希
- [ ] scrypt 验证
- [ ] 可配置参数

---

## 🔧 改进计划

### 项目结构

- [ ] 增加 `tests/` 集成测试目录
- [ ] 增加 `examples/` 目录，提供完整用例演示
- [ ] 增加 `benches/` 基准测试目录

### 功能增强

- [ ] 考虑异步支持 - 某些 Store trait 可能需要 `async` 版本
- [ ] 增加 `serde` feature - 让序列化可选
- [ ] 更完善的文档和 API 示例

### Feature Flags 规划

```toml
[features]
# 现有
default = ["argon2", "jwt", "mfa"]
argon2 = ["dep:argon2"]
bcrypt = ["dep:bcrypt"]
jwt = ["dep:jsonwebtoken"]
mfa = ["dep:sha1"]
full = ["argon2", "bcrypt", "jwt", "mfa"]

# 计划新增
scrypt = ["dep:scrypt"]
oauth = ["dep:oauth2"]
webauthn = ["dep:url", "dep:webauthn-rs"]
rbac = []
passwordless = []
```

---

## 📅 版本规划

### v0.2.0 ✅ 进行中
- [x] OAuth 2.0 基础支持 (PKCE, 客户端管理, Token 内省)
- [x] 账户锁定机制
- [x] API Key 管理增强
- [x] WebAuthn/Passkeys 支持
- [ ] 集成测试

### v0.3.0
- 示例目录
- 异步 Store 支持
- 更完善的文档

### v0.4.0
- RBAC 模块
- Passwordless 认证

### v1.0.0
- 完整文档
- 稳定 API
- 生产就绪

---

## 参与贡献

欢迎贡献！如果你想帮助实现上述任何功能，请：

1. 在 Issues 中讨论实现方案
2. 遵循 `AGENTS.md` 中的编码规范
3. 确保通过所有测试 (`cargo test --features full`)
4. 运行 `cargo fmt` 和 `cargo clippy`
