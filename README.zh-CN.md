# AuthRS | Rust 认证工具包

[English README](README.md)

## 项目简介
AuthRS 是一个基于 Rust 2024 的认证工具包，整合了密码哈希、JWT/Session、MFA、Passwordless（魔法链接/OTP）、CSRF、速率限制以及安全随机工具，帮助你快速构建可靠且安全的认证流程。

## 功能特性
- 密码哈希与强度校验（Argon2、bcrypt、自定义策略）
- 安全随机生成器与常量时间比较函数
- JWT 生成/验证、Refresh Token 与 Session 管理
- 支持 TOTP/HOTP 的多因素认证与恢复码
- API Key 生命周期管理与校验
- Passwordless（魔法链接/OTP）流程与内存存储实现
- 基于 HKDF 的密码学辅助函数（SHA-256/SHA-512）
- CSRF 防护与自适应速率限制
- 通过 Cargo Feature 精准裁剪（`argon2`、`bcrypt`、`jwt`、`mfa`、`api-key`、`passwordless`、`crypto`、`oauth`、`rbac`、`webauthn`、`full`）

## 项目结构
```
src/
  lib.rs        # 库入口与公共导出
  main.rs       # 简单的二进制示例入口
  error.rs      # 公共 Error/Result 定义
  password/     # 哈希与强度规则
  token/        # jwt.rs、refresh.rs、session.rs
  mfa/          # TOTP/HOTP 与恢复模块
  passwordless/ # 魔法链接与 OTP 辅助模块
  crypto/       # HKDF 密钥派生辅助
  api_key/      # API Key 生命周期管理
  security/     # csrf.rs、rate_limit.rs
  random.rs     # 安全随机与比较工具
```

## 快速开始
```bash
cargo add authrs                # 添加依赖
cargo build                     # 默认特性编译
cargo test --features full      # 全特性测试
```
通过 `--no-default-features --features <列表>` 精准组合模块（例：`cargo build --no-default-features --features jwt,passwordless`）。

## 使用示例
```rust
use authrs::password::hash_password;
use authrs::token::jwt::{JwtBuilder, JwtValidator};

let hash = hash_password("Str0ng_P@ss")?;
let token = JwtBuilder::new()
    .subject("user123")
    .issuer("authrs-demo")
    .expires_in_hours(24)
    .build_with_secret(b"my-secret-key-at-least-32-bytes!")?;
let claims = JwtValidator::new(b"my-secret-key-at-least-32-bytes!").validate(&token)?;
println!("subject={}", claims.sub.unwrap_or_default());
```

## 功能开关
- 默认启用：`argon2`、`jwt`、`mfa`
- 可选：`bcrypt`、`oauth`、`rbac`、`webauthn`、`passwordless`、`crypto`、`api-key`
- `full` 打开全部可选模块
- 通过 `cargo build --no-default-features --features jwt,api-key` 仅编译所需模块

## 开发流程
```bash
cargo fmt                                  # rustfmt 格式化
cargo clippy --all-targets --all-features  # 静态检查
cargo test --all-features                  # 运行测试
cargo doc --open                           # 构建 API 文档
```
单元测试建议与模块放在一起；组合多个模块的端到端流程放在 `tests/` 目录。需要稳定断言时可使用 `StdRng::seed_from_u64` 提供确定随机性，生产环境仍使用 `OsRng`。

## 安全提示
- 不要提交任何密钥或示例 JWT，改用环境变量或被忽略的配置文件。
- 未经设计评审与测试，不要降低 Argon2/bcrypt 参数、CSRF 过期时间或速率限制阈值。
- 比较敏感数据时请使用 `random.rs` 中的常量时间工具（如 `constant_time_compare`）。

## 许可协议
项目采用 MIT 许可证，详见 `LICENSE` 文件。
