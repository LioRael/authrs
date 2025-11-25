//! MFA (多因素认证) 设置示例
//!
//! 展示如何使用 AuthRS 实现 TOTP/HOTP 多因素认证和恢复码功能。
//!
//! 运行: cargo run --example mfa_setup --features mfa

use authrs::mfa::hotp::{HotpConfig, HotpGenerator};
use authrs::mfa::recovery::{RecoveryCodeManager, RecoveryConfig};
use authrs::mfa::totp::{TotpConfig, TotpManager, TotpSecret};

/// MFA 服务
struct MfaService {
    totp_manager: TotpManager,
    hotp_generator: HotpGenerator,
    recovery_manager: RecoveryCodeManager,
}

/// 用户的 MFA 配置
struct UserMfaConfig {
    user_id: String,
    totp_secret: Option<TotpSecret>,
    hotp_secret: Option<TotpSecret>,
    hotp_counter: u64,
    recovery_hashes: Vec<String>,
}

impl UserMfaConfig {
    fn new(user_id: &str) -> Self {
        Self {
            user_id: user_id.to_string(),
            totp_secret: None,
            hotp_secret: None,
            hotp_counter: 0,
            recovery_hashes: Vec::new(),
        }
    }
}

impl MfaService {
    fn new() -> Self {
        let totp_config = TotpConfig::default().with_issuer("AuthRS Example");

        let hotp_config = HotpConfig::default();

        let recovery_config = RecoveryConfig::default();

        Self {
            totp_manager: TotpManager::new(totp_config),
            hotp_generator: HotpGenerator::new(hotp_config),
            recovery_manager: RecoveryCodeManager::new(recovery_config),
        }
    }

    /// 启用 TOTP
    fn enable_totp(&self, config: &mut UserMfaConfig) -> Result<SetupResult, String> {
        // 1. 生成密钥
        let secret = self
            .totp_manager
            .generate_secret()
            .map_err(|e| format!("密钥生成失败: {}", e))?;

        // 2. 生成 otpauth URI (用于 QR 码)
        let uri = self.totp_manager.generate_uri(&secret, &config.user_id);

        // 3. 生成当前验证码（用于验证设置）
        let current_code = self
            .totp_manager
            .generate_code(&secret)
            .map_err(|e| format!("验证码生成失败: {}", e))?;

        // 4. 保存密钥
        config.totp_secret = Some(secret.clone());

        Ok(SetupResult {
            secret_base32: secret.base32.clone(),
            otpauth_uri: uri,
            current_code,
        })
    }

    /// 验证 TOTP 设置（用户输入验证器 App 显示的码）
    fn verify_totp_setup(&self, config: &UserMfaConfig, code: &str) -> Result<bool, String> {
        let secret = config.totp_secret.as_ref().ok_or("TOTP 未设置")?;

        self.totp_manager
            .verify(secret, code)
            .map_err(|e| format!("验证失败: {}", e))
    }

    /// 验证 TOTP 登录
    fn verify_totp(&self, config: &UserMfaConfig, code: &str) -> Result<bool, String> {
        let secret = config.totp_secret.as_ref().ok_or("TOTP 未启用")?;

        self.totp_manager
            .verify(secret, code)
            .map_err(|e| format!("验证失败: {}", e))
    }

    /// 生成当前 TOTP 码（用于测试）
    fn generate_totp(&self, config: &UserMfaConfig) -> Result<String, String> {
        let secret = config.totp_secret.as_ref().ok_or("TOTP 未启用")?;

        self.totp_manager
            .generate_code(secret)
            .map_err(|e| format!("生成失败: {}", e))
    }

    /// 启用 HOTP
    fn enable_hotp(&self, config: &mut UserMfaConfig) -> Result<String, String> {
        let secret = self
            .hotp_generator
            .generate_secret()
            .map_err(|e| format!("密钥生成失败: {}", e))?;

        let base32 = secret.base32.clone();
        config.hotp_secret = Some(secret);
        config.hotp_counter = 0;

        Ok(base32)
    }

    /// 生成 HOTP 码
    fn generate_hotp(&self, config: &mut UserMfaConfig) -> Result<String, String> {
        let secret = config.hotp_secret.as_ref().ok_or("HOTP 未启用")?;

        let code = self
            .hotp_generator
            .generate(secret, config.hotp_counter)
            .map_err(|e| format!("生成失败: {}", e))?;

        // 递增计数器
        config.hotp_counter += 1;

        Ok(code)
    }

    /// 验证 HOTP
    fn verify_hotp(&self, config: &mut UserMfaConfig, code: &str) -> Result<bool, String> {
        let secret = config.hotp_secret.as_ref().ok_or("HOTP 未启用")?;

        // 验证 HOTP - 使用 verify_with_result 获取验证结果
        let result = self
            .hotp_generator
            .verify_with_result(secret, code, config.hotp_counter)
            .map_err(|e| format!("验证失败: {}", e))?;

        if result.valid {
            // 更新计数器到下一个值
            config.hotp_counter = result.next_counter;
        }

        Ok(result.valid)
    }

    /// 生成恢复码
    fn generate_recovery_codes(&self, config: &mut UserMfaConfig) -> Result<Vec<String>, String> {
        let codes = self
            .recovery_manager
            .generate()
            .map_err(|e| format!("恢复码生成失败: {}", e))?;

        // 保存哈希后的恢复码
        config.recovery_hashes = codes.hashed_codes;

        // 返回明文恢复码（只显示一次）
        Ok(codes.plain_codes)
    }

    /// 使用恢复码
    fn use_recovery_code(&self, config: &mut UserMfaConfig, code: &str) -> Result<bool, String> {
        let result = self
            .recovery_manager
            .verify(code, &config.recovery_hashes)
            .map_err(|e| format!("恢复码验证失败: {}", e))?;

        if let Some(used_index) = result {
            // 移除已使用的恢复码
            config.recovery_hashes.remove(used_index);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

struct SetupResult {
    secret_base32: String,
    otpauth_uri: String,
    current_code: String,
}

fn main() {
    println!("=== AuthRS MFA 设置示例 ===\n");

    let mfa_service = MfaService::new();
    let mut user_config = UserMfaConfig::new("alice@example.com");

    // ===== TOTP 演示 =====
    println!("📱 设置 TOTP (基于时间的一次性密码)...");
    println!("   这种方式适用于 Google Authenticator、Authy 等 App\n");

    match mfa_service.enable_totp(&mut user_config) {
        Ok(result) => {
            println!("   ✅ TOTP 密钥生成成功");
            println!("   Base32 密钥: {}", result.secret_base32);
            println!("   OTPAuth URI: {}", result.otpauth_uri);
            println!("   当前验证码: {}\n", result.current_code);

            // 模拟用户输入验证码验证设置
            println!("   🔍 验证 TOTP 设置...");
            match mfa_service.verify_totp_setup(&user_config, &result.current_code) {
                Ok(true) => println!("   ✅ TOTP 设置验证成功\n"),
                Ok(false) => println!("   ❌ TOTP 验证码错误\n"),
                Err(e) => println!("   ❌ 验证失败: {}\n", e),
            }

            // 模拟登录验证
            println!("   🔐 模拟登录验证...");
            let login_code = mfa_service.generate_totp(&user_config).unwrap();
            println!("   当前验证码: {}", login_code);
            match mfa_service.verify_totp(&user_config, &login_code) {
                Ok(true) => println!("   ✅ TOTP 登录验证成功\n"),
                Ok(false) => println!("   ❌ TOTP 验证码错误\n"),
                Err(e) => println!("   ❌ 验证失败: {}\n", e),
            }

            // 验证错误码
            println!("   🔐 尝试错误验证码...");
            match mfa_service.verify_totp(&user_config, "000000") {
                Ok(true) => println!("   ✅ 验证成功\n"),
                Ok(false) => println!("   ❌ 验证码错误（预期行为）\n"),
                Err(e) => println!("   ❌ 验证失败: {}\n", e),
            }
        }
        Err(e) => {
            println!("   ❌ TOTP 设置失败: {}\n", e);
        }
    }

    // ===== HOTP 演示 =====
    println!("🔢 设置 HOTP (基于计数器的一次性密码)...");
    println!("   这种方式适用于硬件令牌等设备\n");

    match mfa_service.enable_hotp(&mut user_config) {
        Ok(secret) => {
            println!("   ✅ HOTP 密钥生成成功");
            println!("   Base32 密钥: {}\n", secret);

            // 生成几个 HOTP 码
            println!("   📊 生成 HOTP 序列:");
            for _i in 0..5 {
                let counter_before = user_config.hotp_counter;
                let code = mfa_service.generate_hotp(&mut user_config).unwrap();
                println!("   计数器 {}: {}", counter_before, code);
            }
            println!();

            // 重置计数器用于验证测试
            user_config.hotp_counter = 0;

            // 验证 HOTP
            println!("   🔐 验证 HOTP...");
            let code_to_verify = mfa_service.generate_hotp(&mut user_config).unwrap();
            // 重置计数器模拟服务端
            user_config.hotp_counter = 0;

            match mfa_service.verify_hotp(&mut user_config, &code_to_verify) {
                Ok(true) => println!(
                    "   ✅ HOTP 验证成功, 新计数器: {}\n",
                    user_config.hotp_counter
                ),
                Ok(false) => println!("   ❌ HOTP 验证码错误\n"),
                Err(e) => println!("   ❌ 验证失败: {}\n", e),
            }
        }
        Err(e) => {
            println!("   ❌ HOTP 设置失败: {}\n", e);
        }
    }

    // ===== 恢复码演示 =====
    println!("🔑 生成恢复码...");
    println!("   恢复码用于在丢失 MFA 设备时恢复账户访问\n");

    match mfa_service.generate_recovery_codes(&mut user_config) {
        Ok(codes) => {
            println!("   ✅ 恢复码生成成功");
            println!("   ⚠️  请妥善保存以下恢复码（只显示一次）:\n");
            for (i, code) in codes.iter().enumerate() {
                println!("   {}. {}", i + 1, code);
            }
            println!();

            // 使用一个恢复码
            let code_to_use = &codes[0].clone();
            println!("   🔐 使用恢复码 #1: {}", code_to_use);
            match mfa_service.use_recovery_code(&mut user_config, code_to_use) {
                Ok(true) => println!(
                    "   ✅ 恢复码验证成功, 剩余恢复码: {}\n",
                    user_config.recovery_hashes.len()
                ),
                Ok(false) => println!("   ❌ 恢复码无效\n"),
                Err(e) => println!("   ❌ 验证失败: {}\n", e),
            }

            // 尝试重复使用同一个恢复码
            println!("   🔐 尝试重复使用恢复码 #1...");
            match mfa_service.use_recovery_code(&mut user_config, code_to_use) {
                Ok(true) => println!("   恢复码验证成功\n"),
                Ok(false) => println!("   ❌ 恢复码已被使用（预期行为）\n"),
                Err(e) => println!("   ❌ 验证失败: {}\n", e),
            }

            // 使用另一个恢复码
            let code_to_use_2 = &codes[1].clone();
            println!("   🔐 使用恢复码 #2: {}", code_to_use_2);
            match mfa_service.use_recovery_code(&mut user_config, code_to_use_2) {
                Ok(true) => println!(
                    "   ✅ 恢复码验证成功, 剩余恢复码: {}\n",
                    user_config.recovery_hashes.len()
                ),
                Ok(false) => println!("   ❌ 恢复码无效\n"),
                Err(e) => println!("   ❌ 验证失败: {}\n", e),
            }
        }
        Err(e) => {
            println!("   ❌ 恢复码生成失败: {}\n", e);
        }
    }

    println!("=== 示例结束 ===");
}
