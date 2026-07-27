# Contributing

## Workflow

1. **Fork** this repo.
2. **Branch** from `main` (`git checkout -b fix/sw024-const` or `feat/...`).
3. **Change** code + tests.
4. **PR** into `main` of `sentio-security/sentio-rs`.

Do not commit directly to `main`. One PR ≈ one focused change.

## Before you open a PR

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test --all
```

All three must pass.

## Rules (sentio-core)

| Do | Don't |
|----|--------|
| Add/update fixtures under `crates/sentio-core/tests/fixtures/swXXX/` | Ship a rule with no tests |
| Keep `risky.rs` / `safe.rs` / `suppressed.rs` in sync | Flag style that is already safe (precision > recall) |
| Register new rules in `RuleRegistry::baseline()` | Reuse an existing SW id |

New rule id: next free `SWxxx`. Match existing rule modules for structure.

## False positives

Open a GitHub issue with:

- rule id (e.g. `SW024`)
- short code snippet
- why it is safe

PRs that fix FPs with a regression test are preferred.

## Scope

- Prefer high-signal security / precision fixes.
- Discuss large features in an issue first.
- No drive-by dependency or format-only noise PRs.

## Scope / limitations

Read [docs/LIMITATIONS.md](./docs/LIMITATIONS.md). Sentio is AST-only: **no ZK proof verification, no cross-program trust.**

## Questions

Use Discord or a GitHub issue. Keep security reports responsible (no exploit dumps against third parties).
