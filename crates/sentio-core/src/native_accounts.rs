//! Native / pinocchio handler analysis — the counterpart of `anchor_accounts`
//! for programs that do not use Anchor's `#[derive(Accounts)]`.
//!
//! Anchor rules key off the typed constraint model extracted from the accounts
//! struct. Raw solana_program and pinocchio programs have no such anchor point:
//! accounts arrive as an ordered `&[AccountInfo]` slice and every check is an
//! explicit statement in the handler body. This module recovers a comparable
//! model:
//!
//! - **Handlers**: functions taking a `&[AccountInfo]` / `&[AccountView]`
//!   parameter (covers `process_instruction` entrypoints and per-instruction
//!   processor functions).
//! - **Account bindings**: how each local name was extracted from the slice —
//!   `next_account_info(iter)?` (solana_program), slice destructuring
//!   `let [payer, counter, ..] = accounts` (pinocchio idiom), or direct
//!   indexing `&accounts[0]` / `accounts.get(0)`.
//! - **Checks**: per-binding evidence of signer / owner / key / PDA
//!   verification, in statement order, across both API dialects
//!   (`x.is_signer` field vs `x.is_signer()` method, `x.owner ==` vs
//!   `x.is_owned_by(..)`, `x.key` vs `x.key()`).
//! - **Writes**: whether the account's data or lamports are mutated.
//!
//! Native rules are built on this index the same way Anchor rules are built
//! on `AnchorAccountsIndex` + `InstructionIndex`.

use crate::ast_index::{span_of, AstSpan};
use quote::ToTokens;
use serde::Serialize;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NativeIndex {
    pub handlers: Vec<NativeHandler>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeHandler {
    pub name: String,
    pub qualified_name: String,
    pub span: AstSpan,
    /// Name of the `&[AccountInfo]` parameter the handler receives.
    pub accounts_param: String,
    /// Name of the `&Pubkey` program-id parameter, when present.
    pub program_id_param: Option<String>,
    pub accounts: Vec<NativeAccountBinding>,
    pub checks: Vec<NativeCheck>,
    pub writes: Vec<NativeWrite>,
}

impl NativeHandler {
    /// All checks of `kind` that reference the account binding `name`.
    pub fn checks_for<'a>(
        &'a self,
        name: &'a str,
        kind: NativeCheckKind,
    ) -> impl Iterator<Item = &'a NativeCheck> {
        self.checks
            .iter()
            .filter(move |c| c.kind == kind && c.account == name)
    }

    pub fn has_check(&self, name: &str, kind: NativeCheckKind) -> bool {
        self.checks_for(name, kind).next().is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeAccountBinding {
    /// Local variable name the account is bound to.
    pub name: String,
    /// Position in the accounts slice, when statically known. Sequential for
    /// `next_account_info`, the pattern position for destructuring, the
    /// literal for indexing; `None` when the position can't be determined.
    pub position: Option<usize>,
    pub extraction: NativeExtraction,
    pub span: AstSpan,
    /// How many times the binding is referenced in the handler body after
    /// extraction.
    pub reference_count: usize,
    /// How many of those references immediately read `.key` — a binding used
    /// *only* as a key source (`state.admin = *admin.key`) is a stored
    /// pubkey, not a live authority.
    pub key_reference_count: usize,
    /// The binding's key feeds a PDA derivation (`find_program_address` /
    /// `create_program_address` / bump-search helper seeds). Deriving a
    /// written account from this key makes it a live authority, not a
    /// stored pubkey.
    pub used_as_derivation_seed: bool,
    /// The binding is forwarded into a CPI (invoke args or an instruction
    /// builder). For signer-role accounts the runtime enforces the signature
    /// during the inner instruction (privilege propagation), so an explicit
    /// is_signer is defense-in-depth rather than the security boundary.
    pub forwarded_to_cpi: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeExtraction {
    /// `let x = next_account_info(iter)?`
    NextAccountInfo,
    /// `let [a, b, ..] = accounts` (pinocchio's canonical shape)
    Destructure,
    /// `&accounts[0]` / `accounts.get(0)`
    Index,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeCheck {
    pub kind: NativeCheckKind,
    /// Account binding name the check references.
    pub account: String,
    /// Full condition text (compacted) for diagnostics.
    pub expression: String,
    pub span: AstSpan,
    pub order: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeCheckKind {
    /// `x.is_signer` / `x.is_signer()` inside a condition or assert.
    Signer,
    /// `x.owner == ..` / `x.owner() == ..` / `x.is_owned_by(..)`.
    Owner,
    /// `x.key == ..` / `x.key() == ..` address comparison.
    Key,
    /// `x.key` compared against a `find_program_address` /
    /// `create_program_address` result.
    PdaDerivation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NativeWrite {
    /// Account binding name the write targets.
    pub account: String,
    /// Compacted target text for diagnostics.
    pub target: String,
    pub span: AstSpan,
    pub order: usize,
}

pub fn collect_native_index(file: &syn::File) -> NativeIndex {
    let mut collector = FileCollector::default();
    collector.visit_file(file);
    NativeIndex {
        handlers: collector.handlers,
    }
}

// ─── handler discovery ──────────────────────────────────────────────────────

#[derive(Default)]
struct FileCollector {
    handlers: Vec<NativeHandler>,
    module_stack: Vec<String>,
}

impl<'ast> Visit<'ast> for FileCollector {
    fn visit_item_mod(&mut self, node: &'ast syn::ItemMod) {
        self.module_stack.push(node.ident.to_string());
        visit::visit_item_mod(self, node);
        self.module_stack.pop();
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.collect_handler(&node.sig, &node.block, node.span());
        visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        self.collect_handler(&node.sig, &node.block, node.span());
        visit::visit_impl_item_fn(self, node);
    }
}

impl FileCollector {
    fn collect_handler(
        &mut self,
        sig: &syn::Signature,
        block: &syn::Block,
        span: proc_macro2::Span,
    ) {
        let Some(accounts_param) = accounts_slice_param(sig) else {
            return;
        };
        let program_id_param = program_id_param(sig);

        let mut body = BodyCollector {
            accounts_param: accounts_param.clone(),
            ..BodyCollector::default()
        };
        body.visit_block(block);

        // Reference counting is text-based over the whole body: occurrences
        // of the binding at identifier boundaries, and how many of those are
        // immediately followed by `.key`. The binding statement itself
        // contributes one occurrence — subtracted below.
        let body_text = compact(block);
        for account in &mut body.accounts {
            let (refs, key_refs) = count_references(&body_text, &account.name);
            account.reference_count = refs.saturating_sub(1);
            account.key_reference_count = key_refs;
            account.used_as_derivation_seed = body.seed_sources.contains(&account.name);
            account.forwarded_to_cpi = body.cpi_forwarded.contains(&account.name);
        }

        let name = sig.ident.to_string();
        let qualified_name = {
            let mut parts = self.module_stack.clone();
            parts.push(name.clone());
            parts.join("::")
        };

        self.handlers.push(NativeHandler {
            name,
            qualified_name,
            span: span_of(span),
            accounts_param,
            program_id_param,
            accounts: body.accounts,
            checks: body.checks,
            writes: body.writes,
        });
    }
}

/// Returns the name of the first parameter typed as an account slice:
/// `&[AccountInfo]`, `&[AccountInfo<'a>]`, or pinocchio 0.10's `&[AccountView]`.
fn accounts_slice_param(sig: &syn::Signature) -> Option<String> {
    for input in &sig.inputs {
        let syn::FnArg::Typed(pat_type) = input else {
            continue;
        };
        let ty = compact(&pat_type.ty);
        if ty.starts_with("&[AccountInfo") || ty.starts_with("&[AccountView") {
            if let syn::Pat::Ident(ident) = &*pat_type.pat {
                return Some(ident.ident.to_string());
            }
        }
    }
    None
}

/// Returns the name of a `&Pubkey` / `&Address` parameter (the program id in
/// entrypoint-shaped handlers), preferring one literally named `program_id`.
fn program_id_param(sig: &syn::Signature) -> Option<String> {
    let mut candidate = None;
    for input in &sig.inputs {
        let syn::FnArg::Typed(pat_type) = input else {
            continue;
        };
        let ty = compact(&pat_type.ty);
        if ty == "&Pubkey" || ty == "&Address" {
            if let syn::Pat::Ident(ident) = &*pat_type.pat {
                let name = ident.ident.to_string();
                if name == "program_id" {
                    return Some(name);
                }
                candidate.get_or_insert(name);
            }
        }
    }
    candidate
}

// ─── handler body analysis ──────────────────────────────────────────────────

#[derive(Default)]
struct BodyCollector {
    accounts_param: String,
    accounts: Vec<NativeAccountBinding>,
    checks: Vec<NativeCheck>,
    writes: Vec<NativeWrite>,
    next_order: usize,
    next_sequential_position: usize,
    /// Locals bound to a `find_program_address` / `create_program_address`
    /// result — a key comparison against one of these is a PDA verification.
    derived_vars: std::collections::HashSet<String>,
    /// Account names whose key feeds a PDA derivation call.
    seed_sources: std::collections::HashSet<String>,
    /// Account names forwarded into CPI calls or instruction builders.
    cpi_forwarded: std::collections::HashSet<String>,
}

impl BodyCollector {
    fn order(&mut self) -> usize {
        self.next_order += 1;
        self.next_order
    }

    fn account_names(&self) -> Vec<String> {
        self.accounts.iter().map(|a| a.name.clone()).collect()
    }

    fn record_condition(&mut self, cond: &syn::Expr) {
        let text = compact(cond);
        let span = span_of(cond.span());
        // Evaluate against a snapshot of the names bound so far — a check can
        // only reference accounts extracted before it.
        for name in self.account_names() {
            for kind in classify_condition(&text, &name, &self.derived_vars) {
                let order = self.order();
                self.checks.push(NativeCheck {
                    kind,
                    account: name.clone(),
                    expression: text.clone(),
                    span,
                    order,
                });
            }
        }
    }

    /// assert!/require!-style macros carry their condition as tokens.
    fn record_macro(&mut self, mac: &syn::Macro) {
        if !is_assert_macro(&mac.path) {
            return;
        }
        if let Ok(cond) = mac.parse_body::<syn::Expr>() {
            self.record_condition(&cond);
        } else if let Ok(args) = mac.parse_body_with(
            syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated,
        ) {
            if let Some(first) = args.first() {
                self.record_condition(first);
            }
        }
    }

    fn record_write_target(&mut self, target_text: String, span: proc_macro2::Span) {
        for name in self.account_names() {
            if references_account(&target_text, &name) {
                let order = self.order();
                self.writes.push(NativeWrite {
                    account: name.clone(),
                    target: target_text.clone(),
                    span: span_of(span),
                    order,
                });
            }
        }
    }
}

impl<'ast> Visit<'ast> for BodyCollector {
    fn visit_local(&mut self, node: &'ast syn::Local) {
        // `let [a, b, _rest @ ..] = accounts else { .. }` — pinocchio idiom.
        if let syn::Pat::Slice(slice) = &node.pat {
            if let Some(init) = &node.init {
                if compact(&init.expr) == self.accounts_param {
                    for (position, elem) in slice.elems.iter().enumerate() {
                        // Skip `..` and `_rest @ ..` — rest patterns are not
                        // account bindings.
                        if let syn::Pat::Ident(ident) = elem {
                            let is_rest_binding = ident
                                .subpat
                                .as_ref()
                                .is_some_and(|(_, sub)| matches!(**sub, syn::Pat::Rest(_)));
                            if is_rest_binding {
                                continue;
                            }
                            self.accounts.push(NativeAccountBinding {
                                name: ident.ident.to_string(),
                                position: Some(position),
                                extraction: NativeExtraction::Destructure,
                                span: span_of(elem.span()),
                                reference_count: 0,
                                key_reference_count: 0,
                                used_as_derivation_seed: false,
                                forwarded_to_cpi: false,
                            });
                        }
                    }
                }
            }
        }

        // Track locals holding PDA derivation results, including tuple
        // destructuring: `let (pda, bump) = find_program_address(..)`.
        if let Some(init) = &node.init {
            if compact(&init.expr).contains("program_address") {
                match &node.pat {
                    syn::Pat::Ident(ident) => {
                        self.derived_vars.insert(ident.ident.to_string());
                    }
                    syn::Pat::Tuple(tuple) => {
                        for elem in &tuple.elems {
                            if let syn::Pat::Ident(ident) = elem {
                                self.derived_vars.insert(ident.ident.to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // `let x = next_account_info(iter)?` and `let x = &accounts[0]`.
        if let (syn::Pat::Ident(ident), Some(init)) = (&node.pat, &node.init) {
            let init_text = compact(&init.expr);
            if init_text.contains("next_account_info(") {
                let position = self.next_sequential_position;
                self.next_sequential_position += 1;
                self.accounts.push(NativeAccountBinding {
                    name: ident.ident.to_string(),
                    position: Some(position),
                    extraction: NativeExtraction::NextAccountInfo,
                    span: span_of(node.span()),
                    reference_count: 0,
                    key_reference_count: 0,
                    used_as_derivation_seed: false,
                    forwarded_to_cpi: false,
                });
            } else if let Some(position) = slice_index_of(&init_text, &self.accounts_param) {
                self.accounts.push(NativeAccountBinding {
                    name: ident.ident.to_string(),
                    position,
                    extraction: NativeExtraction::Index,
                    span: span_of(node.span()),
                    reference_count: 0,
                    key_reference_count: 0,
                    used_as_derivation_seed: false,
                    forwarded_to_cpi: false,
                });
            }
        }

        visit::visit_local(self, node);
    }

    fn visit_stmt(&mut self, node: &'ast syn::Stmt) {
        // Statement-position macros (`assert!(..);`) are Stmt::Macro, not
        // ExprMacro — mirror instruction_analysis's handling.
        if let syn::Stmt::Macro(stmt) = node {
            self.record_macro(&stmt.mac);
        }
        visit::visit_stmt(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        let callee = compact(&node.func);
        if callee.contains("program_address") || callee.contains("bump_seed") {
            for name in self.account_names() {
                if node
                    .args
                    .iter()
                    .any(|arg| references_account(&compact(arg), &name))
                {
                    self.seed_sources.insert(name);
                }
            }
        }
        if callee.contains("invoke") || callee.contains("instruction::") {
            for name in self.account_names() {
                if node
                    .args
                    .iter()
                    .any(|arg| references_account(&compact(arg), &name))
                {
                    self.cpi_forwarded.insert(name);
                }
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.record_condition(&node.cond);
        visit::visit_expr_if(self, node);
    }

    fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
        self.record_macro(&node.mac);
        visit::visit_expr_macro(self, node);
    }

    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        self.record_write_target(compact(&node.left), node.left.span());
        visit::visit_expr_assign(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        if matches!(
            node.op,
            syn::BinOp::AddAssign(_)
                | syn::BinOp::SubAssign(_)
                | syn::BinOp::MulAssign(_)
                | syn::BinOp::DivAssign(_)
        ) {
            self.record_write_target(compact(&node.left), node.left.span());
        }
        visit::visit_expr_binary(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        // pinocchio struct CPIs: `Transfer { from, to, .. }.invoke()` /
        // `.invoke_signed(..)` — accounts referenced by the receiver are
        // CPI-forwarded.
        let m = node.method.to_string();
        if m == "invoke" || m == "invoke_signed" {
            let recv = compact(&node.receiver);
            for name in self.account_names() {
                if references_account(&recv, &name) {
                    self.cpi_forwarded.insert(name);
                }
            }
        }

        // Mutable-borrow methods on an account are writes even without a
        // visible assignment (`x.try_borrow_mut_data()?`, serialize-into).
        let method = node.method.to_string();
        if matches!(
            method.as_str(),
            "try_borrow_mut_data"
                | "borrow_mut_data_unchecked"
                | "try_borrow_mut_lamports"
                | "borrow_mut_lamports_unchecked"
                | "realloc"
                | "resize"
                | "assign"
                | "close"
        ) {
            self.record_write_target(compact(&node.receiver), node.receiver.span());
        }
        visit::visit_expr_method_call(self, node);
    }
}

// ─── classification helpers ─────────────────────────────────────────────────

fn compact(tokens: impl ToTokens) -> String {
    tokens.to_token_stream().to_string().replace(' ', "")
}

/// True when `text` references the binding `name` as an expression head:
/// `name.`, `name)`, `*name.`, `&name.` — but not as a substring of a longer
/// identifier (`payer` must not match `fee_payer`).
fn references_account(text: &str, name: &str) -> bool {
    for (idx, _) in text.match_indices(name) {
        let before_ok = idx == 0
            || !text.as_bytes()[idx - 1].is_ascii_alphanumeric()
                && text.as_bytes()[idx - 1] != b'_';
        let after = idx + name.len();
        let after_ok = after >= text.len()
            || !text.as_bytes()[after].is_ascii_alphanumeric() && text.as_bytes()[after] != b'_';
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// Counts identifier-boundary occurrences of `name` in `text`, and how many
/// of them are immediately followed by `.key` (field or method access).
fn count_references(text: &str, name: &str) -> (usize, usize) {
    let mut refs = 0;
    let mut key_refs = 0;
    for (idx, _) in text.match_indices(name) {
        let before_ok = idx == 0
            || !text.as_bytes()[idx - 1].is_ascii_alphanumeric()
                && text.as_bytes()[idx - 1] != b'_';
        let after = idx + name.len();
        let after_ok = after >= text.len()
            || !text.as_bytes()[after].is_ascii_alphanumeric() && text.as_bytes()[after] != b'_';
        if before_ok && after_ok {
            refs += 1;
            if text[after..].starts_with(".key") {
                key_refs += 1;
            }
        }
    }
    (refs, key_refs)
}

/// True when a key comparison pins `name` against something constant — a
/// `::ID` / `::id()` path or an ALL_CAPS const — rather than a runtime value
/// like a state field (`state.authority != *authority.key()` is a has_one
/// relation, not an identity pin, and must not stand in for a signer check).
fn has_const_pin(text: &str, name: &str) -> bool {
    let remainder = text
        .replace(&format!("{name}.key()"), "")
        .replace(&format!("{name}.key"), "");
    if remainder.contains("::ID") || remainder.contains("::id()") {
        return true;
    }
    // ALL_CAPS const ident of length >= 3 at identifier boundaries.
    let bytes = remainder.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let start_ok = i == 0 || !bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'_';
        if start_ok && bytes[i].is_ascii_uppercase() {
            let mut j = i + 1;
            while j < bytes.len()
                && (bytes[j].is_ascii_uppercase() || bytes[j].is_ascii_digit() || bytes[j] == b'_')
            {
                j += 1;
            }
            let end_ok = j >= bytes.len() || !bytes[j].is_ascii_alphanumeric() && bytes[j] != b'_';
            if j - i >= 3 && end_ok {
                return true;
            }
            i = j;
        } else {
            i += 1;
        }
    }
    false
}

/// Classifies which checks a condition expression performs on account `name`.
fn classify_condition(
    text: &str,
    name: &str,
    derived_vars: &std::collections::HashSet<String>,
) -> Vec<NativeCheckKind> {
    if !references_account(text, name) {
        return Vec::new();
    }
    let mut kinds = Vec::new();

    // `x.is_signer` (solana_program field) or `x.is_signer()` (pinocchio).
    if text.contains(&format!("{name}.is_signer")) {
        kinds.push(NativeCheckKind::Signer);
    }

    // `x.owner==` / `x.owner!=` / `x.owner()==` / `x.is_owned_by(..)`.
    if text.contains(&format!("{name}.owner"))
        || text.contains(&format!("{name}.is_owned_by("))
        || text.contains(&format!("!{name}.is_owned_by("))
    {
        kinds.push(NativeCheckKind::Owner);
    }

    // Key checks: `x.key` / `x.key()` in a comparison. A PDA derivation check
    // is a key comparison whose other side is (or holds) a
    // *_program_address result.
    let key_ref = text.contains(&format!("{name}.key"));
    if key_ref {
        let against_derivation = text.contains("program_address")
            || derived_vars.iter().any(|v| references_account(text, v));
        if against_derivation {
            kinds.push(NativeCheckKind::PdaDerivation);
        } else if (text.contains("==") || text.contains("!=")) && has_const_pin(text, name) {
            kinds.push(NativeCheckKind::Key);
        }
    }

    kinds
}

fn is_assert_macro(path: &syn::Path) -> bool {
    path.segments.last().is_some_and(|s| {
        let name = s.ident.to_string();
        name == "assert"
            || name == "assert_eq"
            || name == "assert_ne"
            || name.starts_with("require")
    })
}

/// Parses `&accounts[N]` / `accounts[N]` / `accounts.get(N)` returning the
/// index when it is a literal; `Some(None)`-style unknown positions are
/// returned as `None` position via the outer Option: the outer Option is
/// whether this IS a slice access at all.
fn slice_index_of(init_text: &str, accounts_param: &str) -> Option<Option<usize>> {
    for prefix in [format!("&{accounts_param}["), format!("{accounts_param}[")] {
        if let Some(rest) = init_text.strip_prefix(&prefix) {
            let idx = rest.split(']').next().unwrap_or("");
            return Some(idx.parse::<usize>().ok());
        }
    }
    for prefix in [
        format!("{accounts_param}.get("),
        format!("&{accounts_param}.get("),
    ] {
        if let Some(rest) = init_text.strip_prefix(&prefix) {
            let idx = rest.split(')').next().unwrap_or("");
            return Some(idx.parse::<usize>().ok());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index_of(source: &str) -> NativeIndex {
        let file = syn::parse_file(source).expect("source should parse");
        collect_native_index(&file)
    }

    #[test]
    fn detects_solana_program_next_account_info_handler() {
        let index = index_of(
            r#"
            pub fn process_increment(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
                let accounts_iter = &mut accounts.iter();
                let counter = next_account_info(accounts_iter)?;
                let payer = next_account_info(accounts_iter)?;
                if !payer.is_signer {
                    return Err(ProgramError::MissingRequiredSignature);
                }
                if counter.owner != program_id {
                    return Err(ProgramError::IncorrectProgramId);
                }
                let mut state = Counter::try_from_slice(&counter.data.borrow())?;
                state.count += 1;
                state.serialize(&mut &mut counter.try_borrow_mut_data()?[..])?;
                Ok(())
            }
            "#,
        );
        assert_eq!(index.handlers.len(), 1);
        let h = &index.handlers[0];
        assert_eq!(h.accounts_param, "accounts");
        assert_eq!(h.program_id_param.as_deref(), Some("program_id"));
        assert_eq!(h.accounts.len(), 2);
        assert_eq!(h.accounts[0].name, "counter");
        assert_eq!(h.accounts[0].position, Some(0));
        assert_eq!(h.accounts[0].extraction, NativeExtraction::NextAccountInfo);
        assert_eq!(h.accounts[1].name, "payer");
        assert_eq!(h.accounts[1].position, Some(1));
        assert!(h.has_check("payer", NativeCheckKind::Signer));
        assert!(h.has_check("counter", NativeCheckKind::Owner));
        assert!(!h.has_check("counter", NativeCheckKind::Signer));
        assert!(h.writes.iter().any(|w| w.account == "counter"));
    }

    #[test]
    fn detects_pinocchio_destructure_handler() {
        let index = index_of(
            r#"
            pub fn process_increment(program_id: &Pubkey, accounts: &[AccountInfo], _data: &[u8]) -> ProgramResult {
                let [counter, payer, _rest @ ..] = accounts else {
                    return Err(ProgramError::NotEnoughAccountKeys);
                };
                if !payer.is_signer() {
                    return Err(ProgramError::MissingRequiredSignature);
                }
                if !counter.is_owned_by(program_id) {
                    return Err(ProgramError::IncorrectProgramId);
                }
                let expected = find_program_address(&[b"counter"], program_id).0;
                if counter.key() != &expected {
                    return Err(ProgramError::InvalidSeeds);
                }
                let mut data = counter.try_borrow_mut_data()?;
                Ok(())
            }
            "#,
        );
        assert_eq!(index.handlers.len(), 1);
        let h = &index.handlers[0];
        assert_eq!(
            h.accounts.len(),
            2,
            "wildcard rest pattern is not a binding"
        );
        assert_eq!(h.accounts[0].name, "counter");
        assert_eq!(h.accounts[0].position, Some(0));
        assert_eq!(h.accounts[0].extraction, NativeExtraction::Destructure);
        assert!(h.has_check("payer", NativeCheckKind::Signer));
        assert!(h.has_check("counter", NativeCheckKind::Owner));
        assert!(h.has_check("counter", NativeCheckKind::PdaDerivation));
        assert!(h.writes.iter().any(|w| w.account == "counter"));
    }

    #[test]
    fn detects_index_extraction_and_key_check() {
        let index = index_of(
            r#"
            pub fn handler(accounts: &[AccountInfo]) -> ProgramResult {
                let token_program = &accounts[2];
                if token_program.key != &spl_token::ID {
                    return Err(ProgramError::IncorrectProgramId);
                }
                Ok(())
            }
            "#,
        );
        let h = &index.handlers[0];
        assert_eq!(h.accounts.len(), 1);
        assert_eq!(h.accounts[0].position, Some(2));
        assert_eq!(h.accounts[0].extraction, NativeExtraction::Index);
        assert!(h.has_check("token_program", NativeCheckKind::Key));
    }

    #[test]
    fn ignores_functions_without_account_slice() {
        let index = index_of(
            r#"
            pub fn helper(a: u64, b: u64) -> u64 { a + b }
            pub fn also_not(ctx: Context<Foo>) -> Result<()> { Ok(()) }
            "#,
        );
        assert!(index.handlers.is_empty());
    }

    #[test]
    fn name_matching_does_not_cross_identifier_boundaries() {
        let index = index_of(
            r#"
            pub fn handler(accounts: &[AccountInfo]) -> ProgramResult {
                let payer = &accounts[0];
                let fee_payer = &accounts[1];
                if !fee_payer.is_signer {
                    return Err(ProgramError::MissingRequiredSignature);
                }
                Ok(())
            }
            "#,
        );
        let h = &index.handlers[0];
        assert!(h.has_check("fee_payer", NativeCheckKind::Signer));
        assert!(
            !h.has_check("payer", NativeCheckKind::Signer),
            "substring of fee_payer must not credit payer"
        );
    }

    #[test]
    fn detects_pinocchio_account_view_dialect() {
        let index = index_of(
            r#"
            pub fn process(program_id: &Address, accounts: &[AccountView]) -> ProgramResult {
                let [vault] = accounts else { return Err(ProgramError::NotEnoughAccountKeys); };
                if !vault.is_owned_by(program_id) {
                    return Err(ProgramError::IncorrectProgramId);
                }
                Ok(())
            }
            "#,
        );
        assert_eq!(index.handlers.len(), 1);
        assert!(index.handlers[0].has_check("vault", NativeCheckKind::Owner));
    }

    #[test]
    fn records_assert_macro_checks() {
        let index = index_of(
            r#"
            pub fn handler(accounts: &[AccountInfo]) -> ProgramResult {
                let authority = &accounts[0];
                assert!(authority.is_signer, "authority must sign");
                Ok(())
            }
            "#,
        );
        assert!(index.handlers[0].has_check("authority", NativeCheckKind::Signer));
    }
}
