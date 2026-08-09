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

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let index = collect_instruction_index(&file.syntax);
        let accounts = collect_anchor_accounts_index(&file.syntax);
        let signer_fields = collect_signer_field_names(&accounts);
        let mut findings = Vec::new();

        let const_invoke_lines = collect_const_program_invoke_lines(&file.syntax);

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
