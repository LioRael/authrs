# AuthRS | Rust Authentication Toolkit

[中文版 README](README.zh-CN.md)

## Overview
AuthRS is a Rust 2024 authentication toolkit that consolidates password hashing, JWT/session tokens, MFA, passwordless (Magic Link / OTP), CSRF, rate limiting, and secure randomness utilities so you can assemble robust auth flows without re-implementing primitives.

## Features
- Password hashing and strength validation (Argon2, bcrypt, policy helpers)
- Secure random generators and constant-time comparison helpers
- JWT creation/validation plus refresh/session token management
- MFA (TOTP/HOTP) with recovery codes and otpauth helpers
- API key lifecycle management and validation
- Passwordless (Magic Link / OTP) flows with in-memory stores
- HKDF-based crypto helpers (SHA-256/SHA-512)
- CSRF protection and adaptive rate limiting
- Cargo feature flags to tailor footprint (`argon2`, `bcrypt`, `jwt`, `mfa`, `api-key`, `passwordless`, `crypto`, `oauth`, `rbac`, `webauthn`, `full`)

## Project Structure
```
src/
  lib.rs        # Library entry + public exports
  main.rs       # Minimal binary stub for manual experiments
  error.rs      # Shared Error/Result definitions
  password/     # Hashers + strength rules
  token/        # jwt.rs, refresh.rs, session.rs
  mfa/          # TOTP/HOTP + recovery modules
  passwordless/ # Magic Link & OTP helpers
  crypto/       # HKDF key derivation helpers
  api_key/      # API key lifecycle management
  security/     # csrf.rs, rate_limit.rs
  random.rs     # Secure RNG helpers
```

## Getting Started
```bash
cargo add authrs                # Add as a dependency
cargo build                     # Build with default features
cargo test --features full      # Run tests with all modules
```
Use `--no-default-features --features <list>` to mix modules precisely (e.g., `cargo build --no-default-features --features jwt,passwordless`).

## Example
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

## Feature Flags
- Defaults: `argon2`, `jwt`, `mfa`
- Optional: `bcrypt`, `oauth`, `rbac`, `webauthn`, `passwordless`, `crypto`, `api-key`
- `full` turns on every optional module
- Combine selectively via `cargo build --no-default-features --features jwt,api-key`

## Development Workflow
```bash
cargo fmt                                  # Format with rustfmt
cargo clippy --all-targets --all-features  # Run static analysis
cargo test --all-features                  # Execute test suite
cargo doc --open                           # Build API docs
```
Place unit tests alongside modules, and integration tests under `tests/` when composing flows. Prefer deterministic RNG (`StdRng::seed_from_u64`) for assertions; reserve `OsRng` for production randomness.

## Security Notes
- Never commit secrets or sample JWT keys—load them via ignored config or environment variables.
- Avoid relaxing Argon2/bcrypt parameters, CSRF TTLs, or rate-limit thresholds without design review and regression tests.
- Use constant-time helpers such as `constant_time_compare` from `random.rs` when comparing secrets.

## License
MIT License — see `LICENSE` for the full text.
