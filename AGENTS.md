# Repository Guidelines

## Project Structure & Module Organization
- Library entry: `src/lib.rs`. Keep `src/main.rs` as a thin CLI stub; concentrate behavior in the library.
- Core areas: `src/password/` (hashing in `hasher.rs`, strength rules in `strength.rs`); `src/token/` (`jwt.rs`, `refresh.rs`, `session.rs`); `src/security/` (`csrf.rs`, `rate_limit.rs`); `src/mfa/` (HOTP/TOTP/recovery flows); `src/random.rs` (secure generators); `src/error.rs` (shared `Result`/`Error`).
- Features in `Cargo.toml`: defaults `argon2`, `jwt`, `mfa`; optional `bcrypt`; use `--features full` for everything. Examples live in `examples/`; integration tests in `tests/`.

## Build, Test, and Development Commands
- `cargo build` — compile with default features; add `--no-default-features --features <list>` to target specific sets.
- `cargo test` — run unit + integration suites; favor `cargo test --features full` before release.
- `cargo fmt` then `cargo clippy --all-targets --all-features` — enforce style and lints; run before opening a PR.
- `cargo doc --open` — ensure public API docs render and examples compile.

## Coding Style & Naming Conventions
- Rust 2024 edition with rustfmt defaults (4-space indent, trailing commas, sorted imports).
- Public APIs need doc comments and explicit types; return the re-exported `Result<T>`/`Error` for consistency.
- Modules/files snake_case; types/traits PascalCase; functions/vars snake_case; constants SCREAMING_SNAKE_CASE. Prefer early returns over deep nesting.

## Testing Guidelines
- Co-locate unit tests with implementations; compose flows in `tests/`. Use `#[tokio::test]` for async.
- Cover default features and `--features full`; add targeted cases for feature-guarded code (JWT/MFA helpers, bcrypt variants).
- For deterministic checks on randomness, use `StdRng` with a fixed seed; reserve `OsRng` for nondeterministic behaviors only.

## Commit & Pull Request Guidelines
- Commit subjects mirror history: short, imperative, scoped (e.g., "Tighten token session validation"), ~72 chars, no trailing punctuation.
- PRs should outline behavior changes, feature flags touched, and test runs (`cargo test`, `clippy`, `fmt`); note security-sensitive choices (hash params, token lifetimes) and link issues. Include minimal repro steps for bug fixes.

## Security & Configuration Tips
- Never commit secrets or sample JWT keys; load via environment when running examples/tests.
- Do not weaken cryptographic defaults (Argon2 params, CSRF/rate-limit thresholds) without rationale and tests; prefer constant-time helpers in `src/random.rs` for comparisons.
