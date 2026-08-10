# Native & Pinocchio rule layers

Sentio's original rules key off Anchor's declarative surface — `#[derive(Accounts)]`
types and constraints. Raw [solana-program] and [pinocchio] programs have no such
surface: every safety property is an explicit statement in imperative code. These
layers recover that analysis for raw programs.

## The claim (read this before quoting anything)

**These layers verify that the checks Anchor automates survived being hand-written
(or transpiled). They do not — and cannot — prove a raw program safe.** Static
analysis of arbitrary imperative code is incomplete by nature; a clean scan means
"the checked classes look present," never "audited." What we *can* say precisely:

- **Precision is measured.** Validated against 71 programs transpiled from Anchor
  by [Anvil] with byte-equal verification — because the transpile provably
  preserves semantics and the Anchor sources scan with sentio's mature rules,
  any finding on the output that has no counterpart on the input is by
  construction a false positive. End state: **zero non-parity findings** across
  the corpus, plus 23 hand-written `program-examples` native programs.
- **Recall is measured where it can be.** The committed mutation matrix
  (`tests/fixtures/native/`, driven by `tests/native_mutations.rs`) strips one
  protection per fixture and asserts exactly the matching rule fires — and that
  the fully-checked fixture scans empty.
- It has caught one real-world bug: the analysis flagged Anvil's transpiled
  pyth-oracle path reading a typed account with **no owner or discriminator
  check** where the Anchor original enforces both (fixed in `anvil-sol` 0.8.1).

## Foundation

`native_accounts.rs` — the raw-code counterpart of `anchor_accounts.rs`:

- **Handlers**: any fn taking `&[AccountInfo]` / `&[AccountView]` (pinocchio 0.10)
- **Account bindings** with slice positions: `next_account_info`, slice
  destructuring (`let [a, b, ..] = accounts`), direct indexing; plain aliases
  (`let x_account = x;`) resolve to their root binding
- **Check evidence** across both API dialects: signer (`.is_signer` /
  `.is_signer()`), owner (`.owner ==` / `.is_owned_by(..)`), key pins
  (const-side comparisons only — a has_one relation is not an identity pin),
  PDA derivation (compare against `find_program_address` results *or* a
  whole-argument `<account>.key()` operand of a bump-search helper)
- **Writes**, **data access** (borrow-data family + resolved deserializers),
  **in-handler creation**, **CPI forwarding**, **PDA-seed usage**
- **Token trust** (`collect_token_trust`): sites where a balance is read — via a
  resolved free fn whose body reads SPL amount bytes `[64..72]`, or an
  `::unpack` local whose `.amount` is used — with mint/owner field-check
  tracking

Cross-file resolution rides on `RuleContext` (the whole scan), so helper bodies,
deserializers, and call sites resolve across a project.

## Rule scorecard (raw-code coverage)

| Rule | Class | Native/pinocchio behavior |
|---|---|---|
| SW001 | missing signer | authority-named binding (head noun) never `is_signer`-checked; exempt: const key pin, PDA derivation, stored-pubkey-only use, CPI-forwarded (runtime privilege propagation) |
| SW002 | missing owner | data read with no owner check, no address pin, no PDA derivation; exempt: created in handler, unresolved externals |
| SW003 | arbitrary CPI | const-program builders exempt; helper invokes with param-supplied program IDs exempt only when **every** call site key-validates first (cross-file) |
| SW005/24/25/26/27 | arithmetic, div-zero, unwrap, `create_program_address`, events | dialect-agnostic already; SW026 exempts exhaustive descending bump searches |
| SW006 | type cosplay | project-local deserializers resolved cross-file; flagged only when the resolved body verifies no discriminator |
| SW008 | stale post-CPI read | array-literal account resolution, invoke-family accounts-arg only; fresh rebind after CPI exempt; pre-CPI deserialization from a CPI-touched account flagged |
| SW009/SW010 | token mint / owner | trusted balance with no mint/owner field check and no address binding |
| SW012 | identity binding | deserialized + mutated state with no PDA check, key pin, or has_one-shape compare; init patterns exempt |
| SW022 | unsafe close | only FULL drains flag; `assign`+`realloc(0)`/`resize(0)`/`close()` sequences are safe closes |
| SW023 | remaining accounts | raw slice / subslice forwarded as a CPI's account infos |
| SW011/13/14/16/18/20/21 | Anchor-constraint forms | no separate native analog — they fold into the layers above |

## Known limits (the honest part)

- Analysis is mostly intra-function with targeted cross-file resolution — a
  check living behind an unresolvable indirection reads as missing (FP) or an
  exemption can hide a gap behind a resolvable one (FN).
- Named FN class: an account both CPI-forwarded *and* gating unenforced state
  writes is exempted by SW001's privilege-propagation rule.
- No runtime adversarial execution — findings are AST-level evidence, not
  exploits.

[solana-program]: https://crates.io/crates/solana-program
[pinocchio]: https://crates.io/crates/pinocchio
[Anvil]: https://github.com/Pratikkale26/Anvil
