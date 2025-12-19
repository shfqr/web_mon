# Repository Guidelines

This repository is currently bare; use this guide to keep upcoming work consistent and easy to onboard.

## Project Structure & Module Organization
- Place application code under `src/`; native monitor lives in `src/c/sysmon.c`.
- Keep CLI/ops helpers in `scripts/` (executable with `#!/usr/bin/env bash` and `chmod +x`).
- Keep configuration defaults in `config/` or `.env.example`; never commit real secrets.
- Store documentation in `docs/` (design notes, architecture, operational runbooks).

## Build, Test, and Development Commands
- `make build-c` — compile the C monitor (`webmon`); set `CC` to cross-compile.
- `make run` — start the web UI + JSON server (default host `127.0.0.1`, port `61080`).
- `make clean-c` — remove build outputs.
- Keep commands deterministic; pin versions in lockfiles and make tasks cacheable where possible.

## Coding Style & Naming Conventions
- Default indent: 4 spaces for code, 2 for JSON/YAML.
- C code should stay pedantic-friendly (`-Wall -Wextra -pedantic`); keep functions focused and avoid platform-specific calls when possible.
- Use snake_case for files and modules, kebab-case for scripts, and PascalCase for classes.
- Prefer small, single-purpose functions; add brief comments for non-obvious logic.
- Run formatters before commits; keep imports ordered and remove unused code.

## Testing Guidelines
- Add lightweight unit or integration tests for future changes (e.g., parsing logic); keep tests fast and isolated.
- Mirror `src/` when placing tests; name files `test_<feature>.*`.
- Aim for ≥80% coverage on new code; include edge cases and error paths.
- Use fixtures/fakes instead of hitting real services; keep tests parallelizable and isolated.

## Commit & Pull Request Guidelines
- Write imperative commit subjects with a short scope (e.g., `feat: add resource monitor loop`, `fix: handle empty payload`).
- Keep commits small and reviewable; avoid mixing refactors with behavioral changes.
- PRs should describe intent, list key changes, note tests run, and link issues; attach screenshots for UI changes.
- Ensure PRs stay green in CI; update docs and config samples when behavior or interfaces change.

## Security & Configuration Tips
- Keep secrets out of the repo; load them via environment variables and provide `.env.example`.
- Validate inputs at boundaries and log errors with enough context without leaking secrets.
- Review dependency updates for CVEs and remove unused packages promptly.
