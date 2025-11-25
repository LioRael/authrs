//! JWT (JSON Web Token) 实现模块
//!
//! 提供 JWT 的创建、验证和管理功能。
//!
//! ## 支持的算法
//!
//! - **HS256**: HMAC-SHA256（对称加密，默认）
//! - **HS384**: HMAC-SHA384
//! - **HS512**: HMAC-SHA512
//! - **RS256**: RSA-SHA256（非对称加密）
//! - **RS384**: RSA-SHA384
//! - **RS512**: RSA-SHA512
//! - **ES256**: ECDSA-SHA256
//! - **ES384**: ECDSA-SHA384
//!
//! ## 示例
//!
//! ### 使用 HMAC 算法（对称加密）
//!
//! ```rust
//! use authrs::token::jwt::{JwtBuilder, JwtValidator};
//!
//! // 创建 JWT
//! let secret = b"my-secret-key-at-least-32-bytes!";
//! let token = JwtBuilder::new()
//!     .subject("user123")
//!     .issuer("my-app")
//!     .expires_in_hours(24)
//!     .claim("role", "admin")
//!     .build_with_secret(secret)
//!     .unwrap();
//!
//! // 验证 JWT
//! let validator = JwtValidator::new(secret);
//! let claims = validator.validate(&token).unwrap();
//! assert_eq!(claims.sub, Some("user123".to_string()));
//! ```

use chrono::{Duration, Utc};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, dangerous::insecure_decode,
    decode, encode,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::HashMap;

use crate::error::{Error, Result, TokenError};

/// JWT 签名算法
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum JwtAlgorithm {
    /// HMAC-SHA256（默认）
    #[default]
    HS256,
    /// HMAC-SHA384
    HS384,
    /// HMAC-SHA512
    HS512,
    /// RSA-SHA256
    RS256,
    /// RSA-SHA384
    RS384,
    /// RSA-SHA512
    RS512,
    /// ECDSA-SHA256
    ES256,
    /// ECDSA-SHA384
    ES384,
}

impl From<JwtAlgorithm> for Algorithm {
    fn from(alg: JwtAlgorithm) -> Self {
        match alg {
            JwtAlgorithm::HS256 => Algorithm::HS256,
            JwtAlgorithm::HS384 => Algorithm::HS384,
            JwtAlgorithm::HS512 => Algorithm::HS512,
            JwtAlgorithm::RS256 => Algorithm::RS256,
            JwtAlgorithm::RS384 => Algorithm::RS384,
            JwtAlgorithm::RS512 => Algorithm::RS512,
            JwtAlgorithm::ES256 => Algorithm::ES256,
            JwtAlgorithm::ES384 => Algorithm::ES384,
        }
    }
}

/// 标准 JWT Claims
///
/// 包含 JWT 规范定义的标准字段和自定义字段
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Claims {
    /// 主题（通常是用户 ID）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// 签发者
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// 接收者
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    /// 过期时间（Unix 时间戳）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// 生效时间（Unix 时间戳）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// 签发时间（Unix 时间戳）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// JWT ID（唯一标识符）
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// 自定义字段
    #[serde(flatten)]
    pub custom: HashMap<String, serde_json::Value>,
}

impl Claims {
    /// 创建新的空 Claims
    pub fn new() -> Self {
        Self::default()
    }

    /// 检查 token 是否已过期
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.exp {
            Utc::now().timestamp() > exp
        } else {
            false
        }
    }

    /// 检查 token 是否尚未生效
    pub fn is_not_yet_valid(&self) -> bool {
        if let Some(nbf) = self.nbf {
            Utc::now().timestamp() < nbf
        } else {
            false
        }
    }

    /// 获取自定义字段值
    pub fn get_custom<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.custom
            .get(key)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }
}

/// JWT 构建器
///
/// 使用 Builder 模式创建 JWT token
#[derive(Debug, Clone, Default)]
pub struct JwtBuilder {
    claims: Claims,
    algorithm: JwtAlgorithm,
}

impl JwtBuilder {
    /// 创建新的 JWT 构建器
    pub fn new() -> Self {
        let mut builder = Self::default();
        // 默认设置签发时间
        builder.claims.iat = Some(Utc::now().timestamp());
        builder
    }

    /// 设置主题（Subject）
    ///
    /// 通常用于存储用户 ID
    pub fn subject(mut self, sub: impl Into<String>) -> Self {
        self.claims.sub = Some(sub.into());
        self
    }

    /// 设置签发者（Issuer）
    pub fn issuer(mut self, iss: impl Into<String>) -> Self {
        self.claims.iss = Some(iss.into());
        self
    }

    /// 设置接收者（Audience）
    pub fn audience(mut self, aud: impl Into<String>) -> Self {
        self.claims.aud = Some(aud.into());
        self
    }

    /// 设置过期时间（秒数，从现在开始）
    pub fn expires_in_seconds(mut self, seconds: i64) -> Self {
        self.claims.exp = Some(Utc::now().timestamp() + seconds);
        self
    }

    /// 设置过期时间（分钟数，从现在开始）
    pub fn expires_in_minutes(self, minutes: i64) -> Self {
        self.expires_in_seconds(minutes * 60)
    }

    /// 设置过期时间（小时数，从现在开始）
    pub fn expires_in_hours(self, hours: i64) -> Self {
        self.expires_in_seconds(hours * 3600)
    }

    /// 设置过期时间（天数，从现在开始）
    pub fn expires_in_days(self, days: i64) -> Self {
        self.expires_in_seconds(days * 86400)
    }

    /// 设置过期时间（Duration）
    pub fn expires_in(mut self, duration: Duration) -> Self {
        self.claims.exp = Some(Utc::now().timestamp() + duration.num_seconds());
        self
    }

    /// 设置生效时间（Not Before）
    pub fn not_before(mut self, nbf: i64) -> Self {
        self.claims.nbf = Some(nbf);
        self
    }

    /// 设置延迟生效（秒数，从现在开始）
    pub fn not_before_in_seconds(mut self, seconds: i64) -> Self {
        self.claims.nbf = Some(Utc::now().timestamp() + seconds);
        self
    }

    /// 设置 JWT ID
    pub fn jwt_id(mut self, jti: impl Into<String>) -> Self {
        self.claims.jti = Some(jti.into());
        self
    }

    /// 自动生成 JWT ID
    pub fn with_random_jwt_id(mut self) -> Self {
        self.claims.jti = Some(crate::random::generate_random_hex(16).unwrap_or_default());
        self
    }

    /// 添加自定义字段
    pub fn claim<V: Serialize>(mut self, key: impl Into<String>, value: V) -> Self {
        if let Ok(json_value) = serde_json::to_value(value) {
            self.claims.custom.insert(key.into(), json_value);
        }
        self
    }

    /// 设置算法
    pub fn algorithm(mut self, algorithm: JwtAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// 使用密钥构建 JWT（适用于 HMAC 算法）
    ///
    /// # 参数
    ///
    /// * `secret` - 用于签名的密钥
    ///
    /// # 返回
    ///
    /// 返回编码后的 JWT 字符串
    pub fn build_with_secret(self, secret: &[u8]) -> Result<String> {
        let header = Header::new(self.algorithm.into());
        let key = EncodingKey::from_secret(secret);

        encode(&header, &self.claims, &key).map_err(|e| {
            Error::Token(TokenError::EncodingFailed(format!(
                "failed to encode JWT: {}",
                e
            )))
        })
    }

    /// 使用 RSA 私钥构建 JWT
    ///
    /// # 参数
    ///
    /// * `private_key_pem` - PEM 格式的 RSA 私钥
    pub fn build_with_rsa_private_key(self, private_key_pem: &[u8]) -> Result<String> {
        let header = Header::new(self.algorithm.into());
        let key = EncodingKey::from_rsa_pem(private_key_pem).map_err(|e| {
            Error::Token(TokenError::EncodingFailed(format!(
                "invalid RSA key: {}",
                e
            )))
        })?;

        encode(&header, &self.claims, &key).map_err(|e| {
            Error::Token(TokenError::EncodingFailed(format!(
                "failed to encode JWT: {}",
                e
            )))
        })
    }

    /// 使用 EC 私钥构建 JWT
    ///
    /// # 参数
    ///
    /// * `private_key_pem` - PEM 格式的 EC 私钥
    pub fn build_with_ec_private_key(self, private_key_pem: &[u8]) -> Result<String> {
        let header = Header::new(self.algorithm.into());
        let key = EncodingKey::from_ec_pem(private_key_pem).map_err(|e| {
            Error::Token(TokenError::EncodingFailed(format!("invalid EC key: {}", e)))
        })?;

        encode(&header, &self.claims, &key).map_err(|e| {
            Error::Token(TokenError::EncodingFailed(format!(
                "failed to encode JWT: {}",
                e
            )))
        })
    }

    /// 获取 claims 引用（用于调试）
    pub fn get_claims(&self) -> &Claims {
        &self.claims
    }
}

/// JWT 验证器配置
#[derive(Debug, Clone)]
pub struct JwtValidatorConfig {
    /// 验证过期时间
    pub validate_exp: bool,
    /// 验证生效时间
    pub validate_nbf: bool,
    /// 期望的签发者
    pub issuer: Option<String>,
    /// 期望的接收者
    pub audience: Option<String>,
    /// 允许的时钟偏差（秒）
    pub leeway: u64,
    /// 允许的算法
    pub algorithms: Vec<JwtAlgorithm>,
}

impl Default for JwtValidatorConfig {
    fn default() -> Self {
        Self {
            validate_exp: true,
            validate_nbf: true,
            issuer: None,
            audience: None,
            leeway: 0,
            algorithms: vec![JwtAlgorithm::HS256],
        }
    }
}

impl JwtValidatorConfig {
    /// 创建新的验证器配置
    pub fn new() -> Self {
        Self::default()
    }

    /// 设置期望的签发者
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// 设置期望的接收者
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// 设置时钟偏差容忍度
    pub fn with_leeway(mut self, leeway: u64) -> Self {
        self.leeway = leeway;
        self
    }

    /// 设置允许的算法
    pub fn with_algorithms(mut self, algorithms: Vec<JwtAlgorithm>) -> Self {
        self.algorithms = algorithms;
        self
    }

    /// 禁用过期时间验证
    pub fn without_exp_validation(mut self) -> Self {
        self.validate_exp = false;
        self
    }

    /// 禁用生效时间验证
    pub fn without_nbf_validation(mut self) -> Self {
        self.validate_nbf = false;
        self
    }
}

/// JWT 验证器
///
/// 用于验证和解码 JWT token
pub struct JwtValidator {
    decoding_key: DecodingKey,
    config: JwtValidatorConfig,
}

impl JwtValidator {
    /// 使用密钥创建验证器（适用于 HMAC 算法）
    pub fn new(secret: &[u8]) -> Self {
        Self {
            decoding_key: DecodingKey::from_secret(secret),
            config: JwtValidatorConfig::default(),
        }
    }

    /// 使用密钥和配置创建验证器
    pub fn with_config(secret: &[u8], config: JwtValidatorConfig) -> Self {
        Self {
            decoding_key: DecodingKey::from_secret(secret),
            config,
        }
    }

    /// 使用 RSA 公钥创建验证器
    pub fn from_rsa_public_key(public_key_pem: &[u8]) -> Result<Self> {
        let key = DecodingKey::from_rsa_pem(public_key_pem).map_err(|e| {
            Error::Token(TokenError::DecodingFailed(format!(
                "invalid RSA public key: {}",
                e
            )))
        })?;

        Ok(Self {
            decoding_key: key,
            config: JwtValidatorConfig {
                algorithms: vec![
                    JwtAlgorithm::RS256,
                    JwtAlgorithm::RS384,
                    JwtAlgorithm::RS512,
                ],
                ..Default::default()
            },
        })
    }

    /// 使用 EC 公钥创建验证器
    pub fn from_ec_public_key(public_key_pem: &[u8]) -> Result<Self> {
        let key = DecodingKey::from_ec_pem(public_key_pem).map_err(|e| {
            Error::Token(TokenError::DecodingFailed(format!(
                "invalid EC public key: {}",
                e
            )))
        })?;

        Ok(Self {
            decoding_key: key,
            config: JwtValidatorConfig {
                algorithms: vec![JwtAlgorithm::ES256, JwtAlgorithm::ES384],
                ..Default::default()
            },
        })
    }

    /// 设置配置
    pub fn set_config(&mut self, config: JwtValidatorConfig) {
        self.config = config;
    }

    /// 验证并解码 JWT，返回标准 Claims
    pub fn validate(&self, token: &str) -> Result<Claims> {
        self.validate_with_claims::<Claims>(token)
    }

    /// 验证并解码 JWT，返回自定义 Claims 类型
    pub fn validate_with_claims<T: DeserializeOwned>(&self, token: &str) -> Result<T> {
        let validation = self.build_validation();

        let token_data: TokenData<T> =
            decode(token, &self.decoding_key, &validation).map_err(|e| {
                let error = match e.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => TokenError::Expired,
                    jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                        TokenError::InvalidSignature
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidToken => {
                        TokenError::InvalidFormat("invalid token structure".to_string())
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidIssuer => {
                        TokenError::InvalidClaim("invalid issuer".to_string())
                    }
                    jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                        TokenError::InvalidClaim("invalid audience".to_string())
                    }
                    jsonwebtoken::errors::ErrorKind::ImmatureSignature => {
                        TokenError::InvalidClaim("token not yet valid".to_string())
                    }
                    _ => TokenError::DecodingFailed(e.to_string()),
                };
                Error::Token(error)
            })?;

        Ok(token_data.claims)
    }

    /// 不验证签名，仅解码 JWT（危险操作，仅用于调试）
    ///
    /// # 警告
    ///
    /// 此方法不验证签名，不应在生产环境中使用
    pub fn decode_without_validation(token: &str) -> Result<Claims> {
        let token_data: TokenData<Claims> = insecure_decode(token).map_err(|e| {
            Error::Token(TokenError::DecodingFailed(format!(
                "failed to decode JWT: {}",
                e
            )))
        })?;

        Ok(token_data.claims)
    }

    fn build_validation(&self) -> Validation {
        let algorithms: Vec<Algorithm> =
            self.config.algorithms.iter().map(|a| (*a).into()).collect();

        let mut validation = Validation::new(algorithms[0]);
        validation.algorithms = algorithms;
        validation.validate_exp = self.config.validate_exp;
        validation.validate_nbf = self.config.validate_nbf;
        validation.leeway = self.config.leeway;

        if let Some(ref iss) = self.config.issuer {
            validation.set_issuer(&[iss]);
        }

        if let Some(ref aud) = self.config.audience {
            validation.set_audience(&[aud]);
        }

        validation
    }
}

/// Access Token 和 Refresh Token 对
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    /// Access Token（短期有效）
    pub access_token: String,
    /// Refresh Token（长期有效）
    pub refresh_token: String,
    /// Access Token 过期时间（Unix 时间戳）
    pub access_token_expires_at: i64,
    /// Refresh Token 过期时间（Unix 时间戳）
    pub refresh_token_expires_at: i64,
    /// Token 类型（通常为 "Bearer"）
    pub token_type: String,
}

/// Token 对生成器
pub struct TokenPairGenerator {
    secret: Vec<u8>,
    issuer: Option<String>,
    audience: Option<String>,
    access_token_lifetime: Duration,
    refresh_token_lifetime: Duration,
}

impl TokenPairGenerator {
    /// 创建新的 Token 对生成器
    ///
    /// # 参数
    ///
    /// * `secret` - 用于签名的密钥
    pub fn new(secret: &[u8]) -> Self {
        Self {
            secret: secret.to_vec(),
            issuer: None,
            audience: None,
            access_token_lifetime: Duration::hours(1), // 默认 1 小时
            refresh_token_lifetime: Duration::days(7), // 默认 7 天
        }
    }

    /// 设置签发者
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// 设置接收者
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// 设置 Access Token 有效期
    pub fn with_access_token_lifetime(mut self, duration: Duration) -> Self {
        self.access_token_lifetime = duration;
        self
    }

    /// 设置 Refresh Token 有效期
    pub fn with_refresh_token_lifetime(mut self, duration: Duration) -> Self {
        self.refresh_token_lifetime = duration;
        self
    }

    /// 生成 Token 对
    ///
    /// # 参数
    ///
    /// * `subject` - 主题（通常是用户 ID）
    pub fn generate(&self, subject: impl Into<String>) -> Result<TokenPair> {
        let sub = subject.into();
        let now = Utc::now().timestamp();
        let access_exp = now + self.access_token_lifetime.num_seconds();
        let refresh_exp = now + self.refresh_token_lifetime.num_seconds();

        // 生成 Access Token
        let mut access_builder = JwtBuilder::new()
            .subject(&sub)
            .expires_in(self.access_token_lifetime)
            .claim("type", "access");

        if let Some(ref iss) = self.issuer {
            access_builder = access_builder.issuer(iss);
        }
        if let Some(ref aud) = self.audience {
            access_builder = access_builder.audience(aud);
        }

        let access_token = access_builder.build_with_secret(&self.secret)?;

        // 生成 Refresh Token
        let mut refresh_builder = JwtBuilder::new()
            .subject(&sub)
            .expires_in(self.refresh_token_lifetime)
            .with_random_jwt_id()
            .claim("type", "refresh");

        if let Some(ref iss) = self.issuer {
            refresh_builder = refresh_builder.issuer(iss);
        }
        if let Some(ref aud) = self.audience {
            refresh_builder = refresh_builder.audience(aud);
        }

        let refresh_token = refresh_builder.build_with_secret(&self.secret)?;

        Ok(TokenPair {
            access_token,
            refresh_token,
            access_token_expires_at: access_exp,
            refresh_token_expires_at: refresh_exp,
            token_type: "Bearer".to_string(),
        })
    }

    /// 使用 Refresh Token 刷新 Access Token
    ///
    /// # 参数
    ///
    /// * `refresh_token` - 有效的 Refresh Token
    ///
    /// # 返回
    ///
    /// 返回新的 Token 对
    pub fn refresh(&self, refresh_token: &str) -> Result<TokenPair> {
        // 验证 Refresh Token
        let validator = JwtValidator::new(&self.secret);
        let claims = validator.validate(refresh_token)?;

        // 检查是否为 refresh token 类型
        let token_type: Option<String> = claims.get_custom("type");
        if token_type.as_deref() != Some("refresh") {
            return Err(Error::Token(TokenError::InvalidClaim(
                "not a refresh token".to_string(),
            )));
        }

        // 获取 subject
        let subject = claims
            .sub
            .ok_or_else(|| Error::Token(TokenError::MissingClaim("sub".to_string())))?;

        // 生成新的 Token 对
        self.generate(subject)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SECRET: &[u8] = b"test-secret-key-at-least-32-bytes!";

    #[test]
    fn test_jwt_builder_basic() {
        let token = JwtBuilder::new()
            .subject("user123")
            .issuer("test-app")
            .expires_in_hours(1)
            .build_with_secret(TEST_SECRET)
            .unwrap();

        assert!(!token.is_empty());
        assert_eq!(token.matches('.').count(), 2); // JWT 有两个点
    }

    #[test]
    fn test_jwt_validate() {
        let token = JwtBuilder::new()
            .subject("user123")
            .issuer("test-app")
            .expires_in_hours(1)
            .build_with_secret(TEST_SECRET)
            .unwrap();

        let validator = JwtValidator::new(TEST_SECRET);
        let claims = validator.validate(&token).unwrap();

        assert_eq!(claims.sub, Some("user123".to_string()));
        assert_eq!(claims.iss, Some("test-app".to_string()));
    }

    #[test]
    fn test_jwt_custom_claims() {
        let token = JwtBuilder::new()
            .subject("user123")
            .claim("role", "admin")
            .claim("permissions", vec!["read", "write"])
            .expires_in_hours(1)
            .build_with_secret(TEST_SECRET)
            .unwrap();

        let validator = JwtValidator::new(TEST_SECRET);
        let claims = validator.validate(&token).unwrap();

        let role: Option<String> = claims.get_custom("role");
        assert_eq!(role, Some("admin".to_string()));

        let permissions: Option<Vec<String>> = claims.get_custom("permissions");
        assert_eq!(
            permissions,
            Some(vec!["read".to_string(), "write".to_string()])
        );
    }

    #[test]
    fn test_jwt_expired() {
        let token = JwtBuilder::new()
            .subject("user123")
            .expires_in_seconds(-10) // 已过期
            .build_with_secret(TEST_SECRET)
            .unwrap();

        let validator = JwtValidator::new(TEST_SECRET);
        let result = validator.validate(&token);

        assert!(result.is_err());
        if let Err(Error::Token(TokenError::Expired)) = result {
            // 正确
        } else {
            panic!("Expected TokenError::Expired");
        }
    }

    #[test]
    fn test_jwt_invalid_signature() {
        let token = JwtBuilder::new()
            .subject("user123")
            .expires_in_hours(1)
            .build_with_secret(TEST_SECRET)
            .unwrap();

        let wrong_secret = b"wrong-secret-key-at-least-32-bytes!";
        let validator = JwtValidator::new(wrong_secret);
        let result = validator.validate(&token);

        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_validator_config() {
        let token = JwtBuilder::new()
            .subject("user123")
            .issuer("test-app")
            .audience("api")
            .expires_in_hours(1)
            .build_with_secret(TEST_SECRET)
            .unwrap();

        let config = JwtValidatorConfig::new()
            .with_issuer("test-app")
            .with_audience("api");

        let validator = JwtValidator::with_config(TEST_SECRET, config);
        let claims = validator.validate(&token).unwrap();

        assert_eq!(claims.sub, Some("user123".to_string()));
    }

    #[test]
    fn test_jwt_validator_wrong_issuer() {
        let token = JwtBuilder::new()
            .subject("user123")
            .issuer("test-app")
            .expires_in_hours(1)
            .build_with_secret(TEST_SECRET)
            .unwrap();

        let config = JwtValidatorConfig::new().with_issuer("wrong-app");
        let validator = JwtValidator::with_config(TEST_SECRET, config);
        let result = validator.validate(&token);

        assert!(result.is_err());
    }

    #[test]
    fn test_token_pair_generator() {
        let generator = TokenPairGenerator::new(TEST_SECRET)
            .with_issuer("test-app")
            .with_access_token_lifetime(Duration::minutes(15))
            .with_refresh_token_lifetime(Duration::days(7));

        let pair = generator.generate("user123").unwrap();

        assert!(!pair.access_token.is_empty());
        assert!(!pair.refresh_token.is_empty());
        assert_eq!(pair.token_type, "Bearer");
        assert!(pair.access_token_expires_at > Utc::now().timestamp());
        assert!(pair.refresh_token_expires_at > pair.access_token_expires_at);
    }

    #[test]
    fn test_token_refresh() {
        let generator = TokenPairGenerator::new(TEST_SECRET);
        let pair = generator.generate("user123").unwrap();

        // 等待一小段时间以确保时间戳不同
        std::thread::sleep(std::time::Duration::from_millis(1100));

        // 使用 refresh token 刷新
        let new_pair = generator.refresh(&pair.refresh_token).unwrap();

        assert!(!new_pair.access_token.is_empty());
        // 新的 token 应该有不同的过期时间
        assert!(new_pair.access_token_expires_at >= pair.access_token_expires_at);
    }

    #[test]
    fn test_cannot_refresh_with_access_token() {
        let generator = TokenPairGenerator::new(TEST_SECRET);
        let pair = generator.generate("user123").unwrap();

        // 尝试用 access token 刷新应该失败
        let result = generator.refresh(&pair.access_token);
        assert!(result.is_err());
    }

    #[test]
    fn test_claims_is_expired() {
        let mut claims = Claims::new();

        // 未设置过期时间，不过期
        assert!(!claims.is_expired());

        // 设置过去的时间
        claims.exp = Some(Utc::now().timestamp() - 100);
        assert!(claims.is_expired());

        // 设置未来的时间
        claims.exp = Some(Utc::now().timestamp() + 100);
        assert!(!claims.is_expired());
    }

    #[test]
    fn test_decode_without_validation() {
        let token = JwtBuilder::new()
            .subject("user123")
            .claim("data", "test")
            .expires_in_hours(1)
            .build_with_secret(TEST_SECRET)
            .unwrap();

        let claims = JwtValidator::decode_without_validation(&token).unwrap();
        assert_eq!(claims.sub, Some("user123".to_string()));
    }

    #[test]
    fn test_jwt_algorithm() {
        let token = JwtBuilder::new()
            .algorithm(JwtAlgorithm::HS512)
            .subject("user123")
            .expires_in_hours(1)
            .build_with_secret(TEST_SECRET)
            .unwrap();

        let config = JwtValidatorConfig::new().with_algorithms(vec![JwtAlgorithm::HS512]);
        let validator = JwtValidator::with_config(TEST_SECRET, config);
        let claims = validator.validate(&token).unwrap();

        assert_eq!(claims.sub, Some("user123".to_string()));
    }

    #[test]
    fn test_jwt_with_random_id() {
        let token = JwtBuilder::new()
            .subject("user123")
            .with_random_jwt_id()
            .expires_in_hours(1)
            .build_with_secret(TEST_SECRET)
            .unwrap();

        let validator = JwtValidator::new(TEST_SECRET);
        let claims = validator.validate(&token).unwrap();

        assert!(claims.jti.is_some());
        assert!(!claims.jti.unwrap().is_empty());
    }
}
