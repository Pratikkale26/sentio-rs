# anvil-audit

**Static security analysis for native and pinocchio Solana programs — the
checks Anchor automates, verified on raw code.**

Anchor makes a set of safety properties declarative: signer, owner,
discriminator, CPI target, PDA identity, token mint/authority. Raw
[solana-program] and [pinocchio] code has no declarative surface — every one of
those checks is a hand-written statement, and any of them can silently be
missing. This scanner builds an account-level index of raw handler code and
runs rule layers over it to detect those missing checks.

It powers one concrete, validated workflow: `anvil audit` in
[Anvil](https://github.com/Pratikkale26/Anvil), which verifies that an
Anchor→pinocchio transpilation preserved the source program's security posture.
Use on other codebases is welcome, but experimental — hence the repo name.

[solana-program]: https://docs.rs/solana-program
[pinocchio]: https://github.com/anza-xyz/pinocchio

---

## Validation

The native layers were validated differentially, using byte-equal
transpilation as ground truth:

- **Precision** — measured against 71 programs transpiled from Anchor with
  byte-equal verification (plus 23 hand-written native `program-examples`
  programs). Because the transpile provably preserves semantics, any
  output-only finding is a false positive by construction. End state: **zero
  non-parity findings** across the corpus, with 155 false positives eliminated
  along the way.
- **Recall** — a committed mutation matrix (`tests/native_mutations.rs`):
  strip one protection from a fixture, exactly the matching rule fires; the
  fully-checked fixture scans empty.
- **One real bug found**: a transpiled oracle path read a typed account with
  no owner or discriminator check where the Anchor original enforced both —
  caught by the scanner, fixed in `anvil-sol` 0.8.1.

**Scope**: analysis is intra-function and static — a clean scan means the
checked classes are present, not that the program is audited. Validation to
date covers the corpus families above; broader real-world hardening is
ongoing. Full per-rule semantics and known limits:
[docs/native-rules.md](docs/native-rules.md).

---

## Install & run

```bash
cargo install --git https://github.com/Pratikkale26/anvil-audit-undertest sentio-cli
sentio scan ./path/to/program
```

> **Naming note:** the crates (`sentio-core`, `sentio-cli`), the binary
> (`sentio`), the config file (`sentio.toml`), the env var
> (`SENTIO_NO_TELEMETRY`), and inline suppressions (`// sentio-ignore SWxxx`)
> carry the names of the upstream project this repo was forked from; a rename
> pass is pending.

Useful flags:

```bash
sentio scan . --format json --output report.json   # machine-readable
sentio scan . --fail-on high                       # CI gate
sentio scan . --rule SW003                         # one rule only
sentio rules list                                  # all rule IDs
```

Exit codes: `0` clean (or below `--fail-on`), `1` findings at/above threshold,
`2` parse errors. Scans never make network calls; set `SENTIO_NO_TELEMETRY=1`
to also silence the version-check ping.

---

## What it checks

22 rules total; 15 (all that apply to raw code) run on native/pinocchio
programs via the account-index layers. The native-relevant classes:

| Class | Rules |
| --- | --- |
| Missing signer check on authority accounts | SW001 |
| Missing owner / discriminator check on data reads | SW002, SW006 |
| Arbitrary CPI target | SW003 |
| Token account owner / mint trust | SW009, SW010 |
| PDA identity binding (seeds, bump, canonicality) | SW012, SW026 |
| Post-CPI stale data, unvalidated forwarded accounts | SW008, SW023 |
| Manual close without full drain | SW022 |
| Arithmetic / panic hygiene | SW005, SW024, SW025 |

How the account index works, per-rule semantics, and the known-limits list:
[docs/native-rules.md](docs/native-rules.md).

---

## Lineage & license

This repo started as a fork of an upstream open-source Anchor security
scanner; the Anchor-side rules and CLI architecture come from that project and
are intentionally unchanged here (78/78 corpus programs scan identically to
upstream). See [LICENSE](LICENSE) (MIT) for the upstream copyright notice.
The native/pinocchio layers are new in this repo, built and validated with
[Anvil](https://github.com/Pratikkale26/Anvil)'s byte-equal differential
corpus.

The full story of how the two tools debugged each other:
[the article](https://x.com/PratikKale26/status/2086665374859497620).
