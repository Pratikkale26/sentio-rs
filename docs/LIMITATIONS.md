# Limitations

Sentio is an **AST-based static scanner** for Anchor/Solana Rust source. It does **not** execute programs, expand all macros, or prove cryptographic properties.

## What Sentio can see

- `#[account(...)]` constraints and common equivalents (`token::mint`, custom `constraint = …`)
- Instruction bodies: guards, CPI patterns, writes, basic field usage (`.key()`, data/lamports, seeds)

## What Sentio cannot see (by design)

| Out of scope | Why | What to do |
|--------------|-----|------------|
| **ZK / Groth16 / proof public inputs** | Proof binding is not in the Rust AST | `/// CHECK:`, `// sentio-ignore SWxxx`, or baseline |
| **Checks only in another program (CPI callee)** | Cross-program analysis not supported | Ignore / baseline; document trust in the other program |
| **Runtime-only values** | No full const-eval / symbolic execution | Prefer checked math and explicit guards |
| **Off-chain indexers / intent** | Cannot know your indexer contract | Use `emit!` or structured `msg!` if you want SW027 quiet |

## UncheckedAccount

Using `UncheckedAccount` is allowed. Sentio flags **missing visible guards** (owner / address / identity usage), not the type name.

- **Safe (visible):** `constraint = x.key() == config.x`, seed-only / `.key()`-only identity, `owner =` / `address =`
- **Still flagged:** data use (e.g. `try_borrow_data`) with no owner/address guard
- **Not auto-trusted:** “integrity comes from a ZK proof” without a check we can parse

## False positives

Report with rule id + snippet: GitHub issues or Discord `#false-positives`. Prefer a PR with a regression fixture when fixing FPs.
