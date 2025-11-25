# Repository Guidelines

## Project Structure & Modules
- Library entry is `src/lib.rs`; CLI stub is `src/main.rs` (keep it minimal, focus changes in the library).
- Core modules: `src/password/` (hashing in `hasher.rs`, strength rules in `strength.rs`), `src/token/` (`jwt.rs`, `refresh.rs`, `session.rs`), `src/security/` (`csrf.rs`, `rate_limit.rs`), `src/mfa/` (HOTP/TOTP/recovery), `src/random.rs` (secure generators), `src/error.rs` (shared `Result`).
- Features live in `Cargo.toml`: defaults `argon2`, `jwt`, `mfa`; optional `bcrypt`; use `full` to enable everything.

## Build, Test, and Development Commands
- `cargo build` — build with default features; add `--no-default-features --features <list>` to target specific combos.
- `cargo test` — run unit/integration tests; prefer `cargo test --features full` before release.
- `cargo fmt` then `cargo clippy --all-targets --all-features` — enforce style and lints.
- `cargo doc --open` — verify public API docs render and examples compile.

## Coding Style & Naming Conventions
- Rust 2024 edition; keep rustfmt defaults (4-space indent, trailing commas, sorted imports).
- Public APIs should use explicit types and doc comments; return the re-exported `Result<T>`/`Error` for consistency.
- Modules/files snake_case; types/traits PascalCase; functions/constants snake_case/SCREAMING_SNAKE_CASE.
- Favor clear, deterministic tests and early returns over nested control flow.

## Testing Guidelines
- Place unit tests beside implementations; use `tests/` for integration flows that compose modules.
- Async tests should use `#[tokio::test]` (dev-dep available).
- Cover feature permutations: at minimum default features and `--features full`; add targeted tests for feature-guarded code paths (e.g., JWT or MFA helpers).
- When randomness is involved, prefer `StdRng` with a fixed seed for deterministic assertions; keep `OsRng` for behavior that must stay non-deterministic.

## Commit & Pull Request Guidelines
- Commit subjects follow the current history: short, imperative statements with scope context (e.g., "Add metadata support and improve token/session APIs"); keep to ~72 chars and avoid trailing punctuation.
- PRs should include: summary of behavior changes, feature flags touched, test run notes (`cargo test`, `clippy`, `fmt`), and any security-sensitive decisions (e.g., algorithm defaults, token lifetimes). Link issues when applicable and add minimal repro steps for bug fixes.

## Security & Configuration Notes
- Do not commit secrets or sample JWT keys; load secrets via environment when running local examples/tests.
- Avoid weakening cryptographic defaults (e.g., Argon2 params, CSRF/rate-limit thresholds) without rationale and tests; prefer constant-time helpers in `random.rs` for comparisons.
