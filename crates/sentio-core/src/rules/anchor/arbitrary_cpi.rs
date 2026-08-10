use crate::anchor_accounts::{collect_anchor_accounts_index, AnchorFieldTypeKind};
use crate::finding::SourceLocation;
use crate::instruction_analysis::{collect_instruction_index, CallKind};
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;
use std::collections::HashSet;

#[derive(Debug, Default)]
pub struct ArbitraryCpiRule;

impl Rule for ArbitraryCpiRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW003",
            title: "Arbitrary CPI target",
            severity: RuleSeverity::Critical,
            description: "Detects CPI calls (invoke/invoke_signed) without prior program ID \
                validation. An attacker-supplied program can receive the transaction's signer \
                privileges (confused deputy): e.g. a marketplace CPI to a fake \"royalty\" \
                program that drains the buyer. Always validate program IDs or use \
                Program<'info, T> / an allowlist — never trust user-provided program addresses.",
            fix_guidance: "require!(program.key() == expected::ID, ...) or Program<'info, T> \
                before CPI. Prefer allowlists for optional external programs (royalties, hooks). \
                Never pass a Signer into a CPI whose program account is unvalidated.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let index = collect_instruction_index(&file.syntax);
        let accounts = collect_anchor_accounts_index(&file.syntax);
        let signer_fields = collect_signer_field_names(&accounts);
        let mut findings = Vec::new();

        let const_invoke_lines = collect_const_program_invoke_lines(&file.syntax);
        let param_invokes = collect_param_program_invokes(&file.syntax);

        for function in &index.functions {
            let cpi_calls: Vec<_> = function
                .calls
                .iter()
                .filter(|c| c.kind == CallKind::Cpi && is_raw_invoke(&c.callee))
                .collect();

            if cpi_calls.is_empty() {
                continue;
            }

            for cpi_call in cpi_calls {
                if has_program_validation_before(function, cpi_call.order) {
                    continue;
                }

                // The invoked Instruction was built with a compile-time-constant
                // program ID (system_instruction::*, or a builder handed a
                // `::id()` / `::ID` path constant). The CPI target cannot be
                // attacker-supplied — the runtime resolves the program account
                // by the instruction's own program_id — so there is nothing to
                // validate.
                if const_invoke_lines.contains(&cpi_call.span.start_line) {
                    continue;
                }

                // Helper-with-validated-callers: the Instruction's program ID
                // comes from a fn parameter, and EVERY call site of this
                // helper (across all scanned files) key-validates the account
                // it passes for that parameter before calling. The check
                // exists — one function up the call stack. Any unvalidated or
                // unresolvable call site (or a helper with no visible
                // callers) keeps the finding.
                if param_invoke_validated_by_all_callers(
                    &param_invokes,
                    &function.name,
                    cpi_call.span.start_line,
                    ctx,
                ) {
                    continue;
                }

                let delegated_signers: Vec<&String> = cpi_call
                    .cpi_account_names
                    .iter()
                    .filter(|name| signer_fields.iter().any(|s| s.eq_ignore_ascii_case(name)))
                    .collect();

                let (message, help) = if !delegated_signers.is_empty() {
                    let names = delegated_signers
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    (
                        format!(
                            "CPI `{}` in `{}` has no program ID check and passes signer \
                             privilege(s) (`{names}`) into the callee — classic confused-deputy: \
                             a malicious program can act with those signers (e.g. extra transfers).",
                            cpi_call.callee, function.name
                        ),
                        "Validate the CPI program ID (require! / Program<'info, T> / allowlist) \
                         before invoke. Do not forward buyer/authority Signers to untrusted programs."
                            .to_string(),
                    )
                } else {
                    (
                        format!(
                            "CPI call `{}` in `{}` has no preceding program key validation; \
                             an attacker can supply a malicious CPI target.",
                            cpi_call.callee, function.name
                        ),
                        "Add require!(program.key() == expected::ID, ...) before the CPI, use \
                         Program<'info, T>, or an allowlist for external programs (royalties, hooks)."
                            .to_string(),
                    )
                };

                findings.push(RuleMatch {
                    rule_id: "SW003",
                    severity: RuleSeverity::Critical,
                    message,
                    location: SourceLocation {
                        path: file.path.display().to_string(),
                        line: cpi_call.span.start_line,
                        column: cpi_call.span.start_column,
                    },
                    help: Some(help),
                });
            }
        }

        findings
    }
}

fn is_raw_invoke(callee: &str) -> bool {
    let n = callee.trim();
    n == "invoke"
        || n == "invoke_signed"
        || n == "invoke_unchecked"
        || n.ends_with("::invoke")
        || n.ends_with("::invoke_signed")
        || n.ends_with("::invoke_unchecked")
}

fn has_program_validation_before(
    function: &crate::instruction_analysis::InstructionFunction,
    cpi_order: usize,
) -> bool {
    function.guards.iter().any(|g| {
        g.order < cpi_order
            && (g.references_key || guard_looks_like_program_allowlist(&g.expression))
    })
}

/// Broader than bare `.key()` — allowlist / program_id / ::ID comparisons in require!/if.
fn guard_looks_like_program_allowlist(expression: &str) -> bool {
    let compact: String = expression
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_ascii_lowercase();
    compact.contains("program_id")
        || compact.contains("::id")
        || compact.contains("allowlist")
        || compact.contains("allowed_program")
        || compact.contains("approved_program")
        || (compact.contains("program") && compact.contains("key()") && compact.contains("=="))
}

/// Returns the start lines of raw `invoke` / `invoke_signed` calls whose
/// Instruction argument was built with a compile-time-constant program ID —
/// either directly inline or through a local `let` binding in the same
/// function. Two builder shapes qualify:
///
/// - `system_instruction::*` — these builders take no program-ID argument
///   and always target the System Program.
/// - an `::instruction::` builder given a `::id()` / `::ID` path constant,
///   e.g. `spl_token::instruction::transfer(&spl_token::id(), ..)`.
///
/// `spl_token::instruction::transfer(token_program.key, ..)` does NOT
/// qualify — an account-supplied key is exactly the arbitrary-CPI risk.
fn collect_const_program_invoke_lines(file: &syn::File) -> HashSet<usize> {
    use quote::ToTokens;
    use syn::spanned::Spanned;
    use syn::visit::{self, Visit};

    fn compact(tokens: impl ToTokens) -> String {
        tokens.to_token_stream().to_string().replace(' ', "")
    }

    /// Strips `&`, parens, and `?` to reach the underlying expression.
    fn peel(expr: &syn::Expr) -> &syn::Expr {
        match expr {
            syn::Expr::Reference(r) => peel(&r.expr),
            syn::Expr::Paren(p) => peel(&p.expr),
            syn::Expr::Try(t) => peel(&t.expr),
            _ => expr,
        }
    }

    fn is_const_program_builder(expr: &syn::Expr) -> bool {
        let syn::Expr::Call(call) = peel(expr) else {
            return false;
        };
        let func = compact(&call.func);
        if func.contains("system_instruction::") {
            return true;
        }
        if func.contains("::instruction::") {
            return call.args.iter().any(|arg| {
                let a = compact(arg);
                a.contains("::id()") || a.contains("::ID")
            });
        }
        false
    }

    #[derive(Default)]
    struct ConstInvokeVisitor {
        /// Local bindings (per enclosing fn) whose initializer is a
        /// const-program instruction builder, e.g. `let ix = system_instruction::transfer(..)`.
        const_bindings: Vec<HashSet<String>>,
        lines: HashSet<usize>,
    }

    impl ConstInvokeVisitor {
        fn arg_is_const_instruction(&self, expr: &syn::Expr) -> bool {
            let peeled = peel(expr);
            if is_const_program_builder(peeled) {
                return true;
            }
            if let syn::Expr::Path(p) = peeled {
                if let Some(name) = p.path.get_ident().map(|i| i.to_string()) {
                    return self
                        .const_bindings
                        .iter()
                        .any(|scope| scope.contains(&name));
                }
            }
            false
        }
    }

    impl<'ast> Visit<'ast> for ConstInvokeVisitor {
        fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
            self.const_bindings.push(HashSet::new());
            visit::visit_item_fn(self, node);
            self.const_bindings.pop();
        }

        fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
            self.const_bindings.push(HashSet::new());
            visit::visit_impl_item_fn(self, node);
            self.const_bindings.pop();
        }

        fn visit_local(&mut self, node: &'ast syn::Local) {
            if let (Some(init), syn::Pat::Ident(pat)) = (&node.init, &node.pat) {
                if is_const_program_builder(&init.expr) {
                    if let Some(scope) = self.const_bindings.last_mut() {
                        scope.insert(pat.ident.to_string());
                    }
                }
            }
            visit::visit_local(self, node);
        }

        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            let func = compact(&node.func);
            let is_invoke = func == "invoke"
                || func == "invoke_signed"
                || func == "invoke_unchecked"
                || func.ends_with("::invoke")
                || func.ends_with("::invoke_signed")
                || func.ends_with("::invoke_unchecked");
            if is_invoke {
                if let Some(first) = node.args.first() {
                    if self.arg_is_const_instruction(first) {
                        self.lines.insert(node.span().start().line);
                    }
                }
            }
            visit::visit_expr_call(self, node);
        }
    }

    let mut visitor = ConstInvokeVisitor::default();
    visitor.visit_file(file);
    visitor.lines
}

/// A raw invoke inside a fn whose Instruction program ID derives from a fn
/// parameter (`Instruction { program_id: token_metadata_program.key(), .. }`
/// or an `::instruction::` builder handed `<param>.key`).
struct ParamProgramInvoke {
    fn_name: String,
    param_index: usize,
    lines: std::collections::HashSet<usize>,
}

fn collect_param_program_invokes(file: &syn::File) -> Vec<ParamProgramInvoke> {
    use quote::ToTokens;
    use syn::spanned::Spanned;
    use syn::visit::{self, Visit};

    fn compact(tokens: impl ToTokens) -> String {
        tokens.to_token_stream().to_string().replace(' ', "")
    }

    fn peel(expr: &syn::Expr) -> &syn::Expr {
        match expr {
            syn::Expr::Reference(r) => peel(&r.expr),
            syn::Expr::Paren(p) => peel(&p.expr),
            syn::Expr::Try(t) => peel(&t.expr),
            _ => expr,
        }
    }

    fn references_ident(text: &str, name: &str) -> bool {
        for (idx, _) in text.match_indices(name) {
            let before_ok = idx == 0
                || !text.as_bytes()[idx - 1].is_ascii_alphanumeric()
                    && text.as_bytes()[idx - 1] != b'_';
            let after = idx + name.len();
            let after_ok = after >= text.len()
                || !text.as_bytes()[after].is_ascii_alphanumeric()
                    && text.as_bytes()[after] != b'_';
            if before_ok && after_ok {
                return true;
            }
        }
        false
    }

    /// Which fn parameter's `.key` feeds this expression, if any.
    fn param_key_source(expr: &syn::Expr, params: &[String]) -> Option<usize> {
        let text = compact(expr);
        params
            .iter()
            .position(|p| references_ident(&text, &format!("{p}.key")))
    }

    /// Instruction-producing expression whose program ID is a param key:
    /// `..Instruction { program_id: <param>.key.., .. }` struct literal, or
    /// an `::instruction::` builder call with a `<param>.key` argument.
    fn instruction_param_source(expr: &syn::Expr, params: &[String]) -> Option<usize> {
        match peel(expr) {
            syn::Expr::Struct(s) => {
                let path = compact(&s.path);
                if !path.ends_with("Instruction") {
                    return None;
                }
                s.fields.iter().find_map(|f| {
                    let is_program_id = matches!(
                        &f.member,
                        syn::Member::Named(name) if name == "program_id"
                    );
                    if is_program_id {
                        param_key_source(&f.expr, params)
                    } else {
                        None
                    }
                })
            }
            syn::Expr::Call(call) => {
                let func = compact(&call.func);
                if !func.contains("::instruction::") && !func.contains("_instruction::") {
                    return None;
                }
                call.args
                    .iter()
                    .find_map(|arg| param_key_source(arg, params))
            }
            _ => None,
        }
    }

    #[derive(Default)]
    struct FnState {
        name: String,
        params: Vec<String>,
        /// local binding name -> param index feeding its program id
        bindings: std::collections::HashMap<String, usize>,
        /// param index -> invoke lines
        hits: std::collections::HashMap<usize, std::collections::HashSet<usize>>,
    }

    #[derive(Default)]
    struct Collector {
        stack: Vec<FnState>,
        out: Vec<ParamProgramInvoke>,
    }

    impl Collector {
        fn enter(&mut self, sig: &syn::Signature) {
            let params = sig
                .inputs
                .iter()
                .map(|input| match input {
                    syn::FnArg::Typed(t) => match &*t.pat {
                        syn::Pat::Ident(i) => i.ident.to_string(),
                        _ => String::new(),
                    },
                    syn::FnArg::Receiver(_) => String::new(),
                })
                .collect();
            self.stack.push(FnState {
                name: sig.ident.to_string(),
                params,
                ..FnState::default()
            });
        }

        fn exit(&mut self) {
            if let Some(state) = self.stack.pop() {
                for (param_index, lines) in state.hits {
                    self.out.push(ParamProgramInvoke {
                        fn_name: state.name.clone(),
                        param_index,
                        lines,
                    });
                }
            }
        }
    }

    impl<'ast> Visit<'ast> for Collector {
        fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
            self.enter(&node.sig);
            visit::visit_item_fn(self, node);
            self.exit();
        }

        fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
            self.enter(&node.sig);
            visit::visit_impl_item_fn(self, node);
            self.exit();
        }

        fn visit_local(&mut self, node: &'ast syn::Local) {
            if let Some(state) = self.stack.last_mut() {
                if let (syn::Pat::Ident(ident), Some(init)) = (&node.pat, &node.init) {
                    if let Some(idx) = instruction_param_source(&init.expr, &state.params) {
                        state.bindings.insert(ident.ident.to_string(), idx);
                    }
                }
            }
            visit::visit_local(self, node);
        }

        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            let func = compact(&node.func);
            let is_invoke = func == "invoke"
                || func == "invoke_signed"
                || func == "invoke_unchecked"
                || func.ends_with("::invoke")
                || func.ends_with("::invoke_signed")
                || func.ends_with("::invoke_unchecked");
            if is_invoke {
                if let (Some(state), Some(first)) = (self.stack.last(), node.args.first()) {
                    let param_index = match peel(first) {
                        syn::Expr::Path(p) => p
                            .path
                            .get_ident()
                            .and_then(|i| state.bindings.get(&i.to_string()).copied()),
                        other => instruction_param_source(other, &state.params),
                    };
                    if let Some(idx) = param_index {
                        let line = node.span().start().line;
                        if let Some(state) = self.stack.last_mut() {
                            state.hits.entry(idx).or_default().insert(line);
                        }
                    }
                }
            }
            visit::visit_expr_call(self, node);
        }
    }

    let mut collector = Collector::default();
    collector.visit_file(file);
    collector.out
}

/// True when the finding at `line` in `fn_name` is a param-program invoke AND
/// every call site of `fn_name` across the scanned files key-validates the
/// account it passes for that parameter before the call.
fn param_invoke_validated_by_all_callers(
    param_invokes: &[ParamProgramInvoke],
    fn_name: &str,
    line: usize,
    ctx: &RuleContext<'_>,
) -> bool {
    let Some(invoke) = param_invokes
        .iter()
        .find(|p| p.fn_name == fn_name && p.lines.contains(&line))
    else {
        return false;
    };

    let mut call_sites_found = 0usize;
    for scanned in ctx.files {
        let caller_index = collect_instruction_index(&scanned.syntax);
        for site in collect_call_sites(&scanned.syntax, fn_name) {
            call_sites_found += 1;
            let Some(arg) = site.args.get(invoke.param_index) else {
                return false;
            };
            // Only a plain identifier argument can be traced to a guard.
            let arg = arg.trim_start_matches('&');
            let arg = arg.strip_suffix(".clone()").unwrap_or(arg);
            if arg.is_empty() || !arg.chars().all(|c| c.is_alphanumeric() || c == '_') {
                return false;
            }
            let validated = caller_index
                .functions
                .iter()
                .filter(|f| f.name == site.enclosing_fn)
                .flat_map(|f| f.guards.iter())
                .any(|g| {
                    g.span.start_line < site.line
                        && g.references_key
                        && guard_references_ident(&g.expression, arg)
                });
            if !validated {
                return false;
            }
        }
    }

    call_sites_found > 0
}

fn guard_references_ident(expression: &str, ident: &str) -> bool {
    let compacted: String = expression.chars().filter(|c| !c.is_whitespace()).collect();
    for (idx, _) in compacted.match_indices(ident) {
        let before_ok = idx == 0
            || !compacted.as_bytes()[idx - 1].is_ascii_alphanumeric()
                && compacted.as_bytes()[idx - 1] != b'_';
        let after = idx + ident.len();
        let after_ok = after >= compacted.len()
            || !compacted.as_bytes()[after].is_ascii_alphanumeric()
                && compacted.as_bytes()[after] != b'_';
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

struct CallSite {
    args: Vec<String>,
    enclosing_fn: String,
    line: usize,
}

/// All plain-path call expressions `callee(..)` matching `callee_name`
/// (last path segment), with their enclosing fn and argument texts.
fn collect_call_sites(file: &syn::File, callee_name: &str) -> Vec<CallSite> {
    use quote::ToTokens;
    use syn::spanned::Spanned;
    use syn::visit::{self, Visit};

    struct Collector<'a> {
        callee_name: &'a str,
        fn_stack: Vec<String>,
        out: Vec<CallSite>,
    }

    impl<'ast> Visit<'ast> for Collector<'_> {
        fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
            self.fn_stack.push(node.sig.ident.to_string());
            visit::visit_item_fn(self, node);
            self.fn_stack.pop();
        }

        fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
            self.fn_stack.push(node.sig.ident.to_string());
            visit::visit_impl_item_fn(self, node);
            self.fn_stack.pop();
        }

        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let syn::Expr::Path(p) = &*node.func {
                let matches_name = p
                    .path
                    .segments
                    .last()
                    .is_some_and(|s| s.ident == self.callee_name);
                if matches_name {
                    if let Some(enclosing) = self.fn_stack.last() {
                        self.out.push(CallSite {
                            args: node
                                .args
                                .iter()
                                .map(|a| a.to_token_stream().to_string().replace(' ', ""))
                                .collect(),
                            enclosing_fn: enclosing.clone(),
                            line: node.span().start().line,
                        });
                    }
                }
            }
            visit::visit_expr_call(self, node);
        }
    }

    let mut collector = Collector {
        callee_name,
        fn_stack: Vec::new(),
        out: Vec::new(),
    };
    collector.visit_file(file);
    collector.out
}

fn collect_signer_field_names(
    accounts: &crate::anchor_accounts::AnchorAccountsIndex,
) -> HashSet<String> {
    let mut names = HashSet::new();
    for item in &accounts.structs {
        for field in &item.fields {
            let Some(name) = field.ast.name.clone() else {
                continue;
            };
            let is_signer_type = field.type_info.kind == AnchorFieldTypeKind::Signer;
            let has_signer_constraint = field.constraints.is_signer;
            if is_signer_type || has_signer_constraint {
                names.insert(name);
            }
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleContext;
    use crate::syntax::ParsedFile;
    use std::path::PathBuf;

    fn parse_file(source: &str) -> ParsedFile {
        ParsedFile {
            path: PathBuf::from("src/lib.rs"),
            source: source.to_string(),
            syntax: syn::parse_file(source).expect("source should parse"),
        }
    }

    fn run(file: &ParsedFile) -> Vec<RuleMatch> {
        ArbitraryCpiRule.match_file(
            file,
            &RuleContext {
                files: std::slice::from_ref(file),
            },
        )
    }

    #[test]
    fn does_not_flag_invoke_of_const_program_builder_binding() {
        // Native helper shape (as emitted by Anchor->native transpilers, e.g.
        // Anvil): the Instruction is built with a compile-time-constant
        // program ID, so the CPI target cannot be attacker-supplied.
        let file = parse_file(
            r#"
            pub fn spl_token_transfer<'a>(
                from: &AccountInfo<'a>,
                to: &AccountInfo<'a>,
                authority: &AccountInfo<'a>,
                amount: u64,
            ) -> ProgramResult {
                let transfer_ix = spl_token::instruction::transfer(
                    &spl_token::id(),
                    from.key,
                    to.key,
                    authority.key,
                    &[],
                    amount,
                )?;
                invoke(
                    &transfer_ix,
                    &[from.clone(), to.clone(), authority.clone()],
                )?;
                Ok(())
            }
            "#,
        );
        assert!(run(&file).is_empty());
    }

    #[test]
    fn does_not_flag_system_instruction_invoke_signed() {
        // system_instruction builders take no program-ID argument and always
        // target the System Program.
        let file = parse_file(
            r#"
            pub fn create_program_account<'a>(
                account: &AccountInfo<'a>,
                payer: &AccountInfo<'a>,
                space: u64,
                program_id: &Pubkey,
                signer_seeds: &[&[&[u8]]],
            ) -> ProgramResult {
                let lamports = Rent::get()?.minimum_balance(space as usize);
                let create_ix = system_instruction::create_account(
                    payer.key,
                    account.key,
                    lamports,
                    space,
                    program_id,
                );
                invoke_signed(
                    &create_ix,
                    &[payer.clone(), account.clone()],
                    signer_seeds,
                )?;
                Ok(())
            }
            "#,
        );
        assert!(run(&file).is_empty());
    }

    #[test]
    fn does_not_flag_inline_const_builder_invoke() {
        let file = parse_file(
            r#"
            pub fn tip(payer: &AccountInfo, jar: &AccountInfo, amount: u64) -> ProgramResult {
                invoke(
                    &system_instruction::transfer(payer.key, jar.key, amount),
                    &[payer.clone(), jar.clone()],
                )?;
                Ok(())
            }
            "#,
        );
        assert!(run(&file).is_empty());
    }

    #[test]
    fn still_flags_builder_with_account_supplied_program_id() {
        // An account-supplied key as the builder's program-ID argument is
        // exactly the arbitrary-CPI risk — the const-builder exemption must
        // not apply.
        let file = parse_file(
            r#"
            pub fn forward(token_program: &AccountInfo, from: &AccountInfo, to: &AccountInfo, auth: &AccountInfo, amount: u64) -> ProgramResult {
                let ix = spl_token::instruction::transfer(
                    token_program.key,
                    from.key,
                    to.key,
                    auth.key,
                    &[],
                    amount,
                )?;
                invoke(&ix, &[from.clone(), to.clone(), auth.clone()])?;
                Ok(())
            }
            "#,
        );
        let findings = run(&file);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW003");
    }

    // ─── caller-aware param-program invokes (pinocchio scope) ──────────────

    /// The transpiled-mpl pinocchio shape: helper builds an Instruction whose
    /// program id is a fn parameter's key, invokes it; the PROCESSOR (other
    /// file) key-validates the program account before calling the helper.
    const PINOCCHIO_HELPER: &str = r#"
        pub fn mpl_approve_collection_authority(
            collection_authority_record: &AccountInfo,
            new_collection_authority: &AccountInfo,
            update_authority: &AccountInfo,
            token_metadata_program: &AccountInfo,
            signer_seeds: Option<&[&[&[u8]]]>,
        ) -> ProgramResult {
            let metas = [
                pinocchio::instruction::AccountMeta::new(collection_authority_record.key(), true, false),
                pinocchio::instruction::AccountMeta::new(new_collection_authority.key(), false, false),
                pinocchio::instruction::AccountMeta::new(update_authority.key(), true, true),
            ];
            let data = [23u8];
            let ix = pinocchio::instruction::Instruction {
                program_id: token_metadata_program.key(),
                accounts: &metas,
                data: &data,
            };
            let infos = [collection_authority_record, new_collection_authority, update_authority];
            match signer_seeds {
                Some(_) => pinocchio::cpi::invoke_signed(&ix, &infos, &[]),
                None => pinocchio::cpi::invoke(&ix, &infos),
            }
        }
    "#;

    fn caller_file(validated: bool) -> String {
        let guard = if validated {
            r#"
                if token_metadata_program.key() != &[11, 112, 101, 177, 227, 209, 124, 69, 56, 157, 82, 127, 107, 4, 195, 205, 88, 184, 108, 115, 26, 160, 253, 181, 73, 182, 209, 188, 3, 248, 41, 70] {
                    return Err(ProgramError::IncorrectProgramId);
                }
            "#
        } else {
            ""
        };
        format!(
            r#"
            pub fn approve(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {{
                let [record, new_authority, update_authority, token_metadata_program] = accounts else {{
                    return Err(ProgramError::NotEnoughAccountKeys);
                }};
                {guard}
                mpl_approve_collection_authority(record, new_authority, update_authority, token_metadata_program, None)?;
                Ok(())
            }}
            "#
        )
    }

    fn parse_named(path: &str, source: &str) -> ParsedFile {
        ParsedFile {
            path: PathBuf::from(path),
            source: source.to_string(),
            syntax: syn::parse_file(source).expect("source should parse"),
        }
    }

    #[test]
    fn exempts_param_program_invoke_when_all_callers_validate_cross_file() {
        let helper = parse_named("src/helpers.rs", PINOCCHIO_HELPER);
        let caller = parse_named("src/instructions/approve.rs", &caller_file(true));
        let files = vec![helper, caller];
        let findings = ArbitraryCpiRule.match_file(&files[0], &RuleContext { files: &files });
        assert!(
            findings.is_empty(),
            "validated caller must exempt the helper invoke: {findings:?}"
        );
    }

    #[test]
    fn still_flags_param_program_invoke_when_caller_does_not_validate() {
        let helper = parse_named("src/helpers.rs", PINOCCHIO_HELPER);
        let caller = parse_named("src/instructions/approve.rs", &caller_file(false));
        let files = vec![helper, caller];
        let findings = ArbitraryCpiRule.match_file(&files[0], &RuleContext { files: &files });
        assert_eq!(findings.len(), 2, "both invoke arms must flag");
    }

    #[test]
    fn still_flags_param_program_invoke_with_no_visible_callers() {
        let helper = parse_named("src/helpers.rs", PINOCCHIO_HELPER);
        let files = vec![helper];
        let findings = ArbitraryCpiRule.match_file(&files[0], &RuleContext { files: &files });
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn still_flags_when_any_caller_is_unvalidated() {
        let helper = parse_named("src/helpers.rs", PINOCCHIO_HELPER);
        let good = parse_named("src/instructions/approve.rs", &caller_file(true));
        let bad_src = caller_file(false).replace("pub fn approve(", "pub fn approve_open(");
        let bad = parse_named("src/instructions/open.rs", &bad_src);
        let files = vec![helper, good, bad];
        let findings = ArbitraryCpiRule.match_file(&files[0], &RuleContext { files: &files });
        assert_eq!(
            findings.len(),
            2,
            "one unvalidated caller keeps the finding"
        );
    }

    #[test]
    fn flags_cpi_without_key_check() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke;

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                invoke(
                    &instruction,
                    &[ctx.accounts.target_program.to_account_info()],
                )?;
                Ok(())
            }
        "#,
        );
        let findings = run(&file);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW003");
    }

    #[test]
    fn does_not_flag_cpi_with_key_check_before() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke;

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                require!(
                    ctx.accounts.target_program.key() == &expected_program::ID,
                    ErrorCode::InvalidProgram
                );
                invoke(
                    &instruction,
                    &[ctx.accounts.target_program.to_account_info()],
                )?;
                Ok(())
            }
        "#,
        );
        assert!(run(&file).is_empty());
    }

    #[test]
    fn does_not_flag_function_with_no_cpi() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                ctx.accounts.vault.balance = 100;
                Ok(())
            }
        "#,
        );
        assert!(run(&file).is_empty());
    }

    #[test]
    fn flags_confused_deputy_signer_passed_to_unvalidated_program() {
        // Marketplace-style: CPI to user-supplied royalty program with buyer as signer.
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke;

            #[derive(Accounts)]
            pub struct Buy<'info> {
                pub buyer: Signer<'info>,
                /// CHECK: supposed royalty program — unvalidated
                pub royalty_program: AccountInfo<'info>,
                #[account(mut)]
                pub buyer_token: AccountInfo<'info>,
            }

            pub fn buy(ctx: Context<Buy>) -> Result<()> {
                let ix = solana_program::instruction::Instruction {
                    program_id: *ctx.accounts.royalty_program.key,
                    accounts: vec![],
                    data: vec![],
                };
                invoke(
                    &ix,
                    &[
                        ctx.accounts.buyer.to_account_info(),
                        ctx.accounts.buyer_token.to_account_info(),
                        ctx.accounts.royalty_program.to_account_info(),
                    ],
                )?;
                Ok(())
            }
        "#,
        );
        let findings = run(&file);
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].message.to_lowercase().contains("signer")
                || findings[0].message.to_lowercase().contains("confused"),
            "expected confused-deputy messaging: {}",
            findings[0].message
        );
    }

    #[test]
    fn does_not_flag_when_program_validated_even_with_signer_in_metas() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke;

            #[derive(Accounts)]
            pub struct Buy<'info> {
                pub buyer: Signer<'info>,
                pub royalty_program: AccountInfo<'info>,
            }

            pub fn buy(ctx: Context<Buy>) -> Result<()> {
                require_keys_eq!(*ctx.accounts.royalty_program.key, royalty::ID);
                invoke(
                    &ix,
                    &[
                        ctx.accounts.buyer.to_account_info(),
                        ctx.accounts.royalty_program.to_account_info(),
                    ],
                )?;
                Ok(())
            }
        "#,
        );
        assert!(
            run(&file).is_empty(),
            "validated program ID must clear SW003 even with signer in metas: {:?}",
            run(&file)
        );
    }
}
