# AuthRS 功能路线图

本文档记录 AuthRS 库的功能规划和未来发展方向。

## ✅ 当前已有功能

| 模块 | 功能 | 状态 |
|------|------|------|
| **password/** | Argon2/bcrypt 哈希、密码强度验证 | ✅ 完成 |
| **token/** | JWT (多算法)、Refresh Token、Session 管理 | ✅ 完成 |
| **mfa/** | TOTP/HOTP、恢复码 | ✅ 完成 |
| **security/** | CSRF 防护、速率限制 (滑动窗口/固定窗口/令牌桶)、安全 Cookie | ✅ 完成 |
| **security/account** | 账户锁定、登录追踪、递增延迟、IP 封禁 | ✅ 完成 |
| **oauth/** | OAuth 客户端管理、PKCE (S256/plain)、Token 内省 | ✅ 完成 |
| **api_key/** | API Key 管理（哈希存储、权限范围、过期、轮换） | ✅ 完成 |
| **webauthn/** | WebAuthn / Passkeys（注册、认证、凭证管理） | ✅ 完成 |
| **rbac/** | 角色权限管理、策略引擎 | ✅ 完成 |
| **passwordless/** | Magic Link、OTP (Email/SMS) 无密码认证 | ✅ 完成 |
| **crypto/** | HKDF 密钥派生函数 (SHA256/SHA512) | ✅ 完成 |
| **random.rs** | 安全随机数、常量时间比较 | ✅ 完成 |
| **error.rs** | 统一错误类型 | ✅ 完成 |
| **audit.rs** | 审计日志、安全事件记录 | ✅ 完成 |

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

#### 5. ~~权限/RBAC 模块~~ ✅ 已完成

基础的角色权限管理。

```
src/rbac/
├── mod.rs         ✅ 模块入口、文档、集成测试
├── role.rs        ✅ 角色定义、继承、RoleManager
├── permission.rs  ✅ 权限检查、通配符支持、PermissionSet
└── policy.rs      ✅ 策略引擎、条件评估、Decision
```

**功能点：**
- [x] 角色定义（Role, RoleBuilder, RoleStore）
- [x] 权限定义与检查（Permission, PermissionSet, 通配符支持）
- [x] 角色-权限映射（RoleManager, 继承链解析）
- [x] 简单策略引擎（PolicyEngine, Policy, PolicyEffect）
- [x] 基于属性的条件（PolicyCondition）
- [x] 循环继承检测

---

### 🟢 低优先级

#### 6. ~~Passwordless 认证模块~~ ✅ 已完成

```rust
// src/passwordless/ ✅

// Magic Link
pub struct MagicLinkManager { ... }  // ✅ Magic Link 管理器
pub struct MagicLinkConfig { ... }   // ✅ 配置
pub trait MagicLinkStore { ... }     // ✅ 存储接口

// OTP (Email/SMS)
pub struct OtpManager { ... }        // ✅ OTP 管理器
pub struct OtpConfig { ... }         // ✅ 配置
pub enum OtpPurpose { ... }          // ✅ 用途枚举
pub trait OtpStore { ... }           // ✅ 存储接口
```

**功能点：**
- [x] Magic Link 生成与验证
- [x] Magic Link 撤销和批量撤销
- [x] OTP (一次性密码) 生成与验证
- [x] OTP 用途分离 (Login, Registration, PasswordReset 等)
- [x] 最大尝试次数限制
- [x] 最小生成间隔（防滥用）
- [x] 常量时间比较（防时序攻击）
- [x] 内存存储实现

#### 7. ~~安全 Cookie 助手~~ ✅ 已完成

```rust
// security/cookie.rs ✅

pub struct SecureCookie { ... }  // ✅ Cookie 结构体
pub enum SameSite { ... }        // ✅ SameSite 属性
pub fn sign_cookie(...) -> String;     // ✅ Cookie 签名
pub fn verify_cookie(...) -> Result<String>; // ✅ Cookie 验证
pub fn delete_cookie_header(...) -> String;  // ✅ 删除 Cookie
```

**功能点：**
- [x] Cookie 签名 (HMAC-SHA256)
- [x] Cookie 验证
- [x] 安全属性封装 (HttpOnly, Secure, SameSite, Max-Age, Path, Domain)
- [x] Set-Cookie 头生成
- [x] 删除 Cookie 助手

#### 8. ~~密钥派生函数~~ ✅ 已完成

```rust
// src/crypto/kdf.rs ✅

pub fn hkdf_sha256(...) -> Result<Vec<u8>>;  // ✅ HKDF-SHA256
pub fn hkdf_sha512(...) -> Result<Vec<u8>>;  // ✅ HKDF-SHA512
pub struct Hkdf { ... }                       // ✅ 构建器 API
pub fn derive_key_from_password(...) -> Result<Vec<u8>>; // ✅ 密码派生
pub fn derive_subkeys(...) -> Result<Vec<Vec<u8>>>;      // ✅ 批量派生
```

**功能点：**
- [x] HKDF-SHA256
- [x] HKDF-SHA512
- [x] 构建器 API (Hkdf)
- [x] 从密码派生密钥
- [x] 从主密钥派生多个子密钥
- [x] RFC 5869 测试向量验证

#### 9. ~~审计日志 Trait~~ ✅ 已完成

```rust
// src/audit.rs ✅

pub enum EventType { ... }           // ✅ 事件类型枚举
pub enum EventSeverity { ... }       // ✅ 严重程度枚举
pub struct SecurityEvent { ... }     // ✅ 安全事件结构
pub trait AuditLogger { ... }        // ✅ 日志 Trait
pub struct InMemoryAuditLogger { ... } // ✅ 内存实现
pub struct NoOpAuditLogger { ... }   // ✅ 空操作实现
```

**功能点：**
- [x] 安全事件枚举 (登录、MFA、账户锁定、API Key 等)
- [x] 严重程度分级 (Debug, Info, Warning, Error, Critical)
- [x] 日志 Trait 定义
- [x] 内存实现（支持过滤、查询、统计）
- [x] 空操作实现（用于禁用审计）
- [x] 便捷构造方法
- [x] 事件序列化

#### 10. scrypt 密码哈希

在 `password/hasher.rs` 中增加 scrypt 支持作为另一个算法选项。

**功能点：**
- [ ] scrypt 哈希
- [ ] scrypt 验证
- [ ] 可配置参数

---

## 🔧 改进计划

### 项目结构

- [x] 增加 `tests/` 集成测试目录
- [x] 增加 `examples/` 目录，提供完整用例演示
- [ ] 增加 `benches/` 基准测试目录

### 功能增强

- [ ] 考虑异步支持 - 某些 Store trait 可能需要 `async` 版本
- [ ] 增加 `serde` feature - 让序列化可选
- [ ] 更完善的文档和 API 示例

### Feature Flags 规划

```toml
[features]
# 默认组合
default = ["argon2", "jwt", "mfa"]

# 密码哈希
argon2 = ["dep:argon2"]
bcrypt = ["dep:bcrypt"]

# Token / MFA
jwt = ["dep:jsonwebtoken"]
mfa = ["dep:sha1"]

# 已有可选模块
oauth = []
rbac = []
webauthn = ["dep:url", "dep:webauthn-rs"]
passwordless = []
crypto = []
api-key = []

# 计划新增
scrypt = ["dep:scrypt"]

# 完整功能集合
full = [
    "argon2",
    "bcrypt",
    "jwt",
    "mfa",
    "oauth",
    "rbac",
    "webauthn",
    "passwordless",
    "crypto",
    "api-key",
]
```

---

## 📅 版本规划

### v0.2.0 ✅ 进行中
- [x] OAuth 2.0 基础支持 (PKCE, 客户端管理, Token 内省)
- [x] 账户锁定机制
- [x] API Key 管理增强
- [x] WebAuthn/Passkeys 支持
- [x] RBAC 模块（角色权限管理、策略引擎）
- [x] 审计日志模块
- [x] 安全 Cookie 助手
- [x] 集成测试

### v0.3.0
- [x] 示例目录 (已完成)
- 异步 Store 支持
- 更完善的文档

### v0.4.0
- ~~Passwordless 认证~~ ✅ 已完成
- ~~安全 Cookie 助手~~ ✅ 已完成
- scrypt 密码哈希

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
