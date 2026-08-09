use crate::finding::SourceLocation;
use crate::instruction_analysis::{collect_instruction_index, CallKind};
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;

#[derive(Debug, Default)]
pub struct CpiRemainingAccountsRule;

impl Rule for CpiRemainingAccountsRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW023",
            title: "Unvalidated remaining_accounts forwarded to CPI",
            severity: RuleSeverity::Critical,
            description: "Detects instruction handlers that forward ctx.remaining_accounts into a \
                          CPI call. Accounts in remaining_accounts are not declared in the Accounts \
                          struct so they carry no type, owner, or signer constraints. Any account \
                          that was a signer in the outer transaction retains that signer privilege \
                          inside the CPI, letting an attacker escalate privileges by supplying \
                          unexpected signers.",
            fix_guidance: "Declare every account needed by the CPI in the Accounts struct with \
                           explicit constraints (Program<'info, T>, Signer<'info>, owner, address). \
                           If remaining_accounts is unavoidable, validate each account's owner, \
                           key, and signer status before passing it to the CPI.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let _ = ctx;
        let index = collect_instruction_index(&file.syntax);
        let source_lines: Vec<&str> = file.source.lines().collect();
        let mut findings = Vec::new();

        for function in &index.functions {
            let cpi_calls: Vec<_> = function
                .calls
                .iter()
                .filter(|c| c.kind == CallKind::Cpi)
                .collect();

            if cpi_calls.is_empty() {
                continue;
            }

            // Check whether remaining_accounts appears in the function body.
            let start = function.span.start_line.saturating_sub(1);
            let end = function.span.end_line.min(source_lines.len());
            let body_uses_remaining = source_lines[start..end]
                .iter()
                .any(|line| line.contains("remaining_accounts"));

            if !body_uses_remaining {
                continue;
            }

            // Flag the first CPI call in this function as the anchor location.
            if let Some(cpi_call) = cpi_calls.first() {
                findings.push(RuleMatch {
                    rule_id: "SW023",
                    severity: RuleSeverity::Critical,
                    message: format!(
                        "Function `{}` forwards `remaining_accounts` into a CPI; unvalidated \
                         accounts retain outer-transaction signer privileges inside the call.",
                        function.name
                    ),
                    location: SourceLocation {
                        path: file.path.display().to_string(),
                        line: cpi_call.span.start_line,
                        column: cpi_call.span.start_column,
                    },
                    help: Some(
                        "Declare CPI accounts explicitly in the Accounts struct with typed \
                         constraints. If remaining_accounts is required, validate each account's \
                         owner, key, and is_signer before forwarding it."
                            .to_string(),
                    ),
                });
            }
        }

        findings.extend(native_findings(file));

        findings
    }
}

/// Native / pinocchio layer: forwarding the handler's raw `&[AccountInfo]`
/// slice parameter (or a subslice of it) directly as a CPI's account-infos
/// argument is the native `remaining_accounts` — the callee receives
/// whatever the outer transaction supplied, unexamined, with outer signer
/// privileges intact. Explicitly enumerated arrays (`&[vault, mint]`) are
/// not flagged — those accounts were individually extracted and named.
fn native_findings(file: &ParsedFile) -> Vec<RuleMatch> {
    use quote::ToTokens;
    use syn::spanned::Spanned;
    use syn::visit::{self, Visit};

    fn compact(tokens: impl ToTokens) -> String {
        tokens.to_token_stream().to_string().replace(' ', "")
    }

    fn slice_param_of(sig: &syn::Signature) -> Option<String> {
        for input in &sig.inputs {
            if let syn::FnArg::Typed(t) = input {
                let ty = compact(&t.ty);
                if ty.starts_with("&[AccountInfo") || ty.starts_with("&[AccountView") {
                    if let syn::Pat::Ident(i) = &*t.pat {
                        return Some(i.ident.to_string());
                    }
                }
            }
        }
        None
    }

    /// Is `arg` the slice param itself or a range-subslice of it?
    fn forwards_slice(arg: &syn::Expr, param: &str) -> bool {
        let mut text = compact(arg);
        while let Some(stripped) = text.strip_prefix('&') {
            text = stripped.to_string();
        }
        if text == param {
            return true;
        }
        if let Some(rest) = text.strip_prefix(&format!("{param}[")) {
            return rest.contains("..");
        }
        false
    }

    struct Collector {
        stack: Vec<Option<(String, String)>>,
        /// (fn_name, callee, line)
        hits: Vec<(String, String, usize)>,
    }

    impl<'ast> Visit<'ast> for Collector {
        fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
            let entry = slice_param_of(&node.sig).map(|p| (node.sig.ident.to_string(), p));
            self.stack.push(entry);
            visit::visit_item_fn(self, node);
            self.stack.pop();
        }

        fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
            let entry = slice_param_of(&node.sig).map(|p| (node.sig.ident.to_string(), p));
            self.stack.push(entry);
            visit::visit_impl_item_fn(self, node);
            self.stack.pop();
        }

        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let Some(Some((fn_name, param))) = self.stack.last() {
                let func = compact(&node.func);
                let is_invoke = func == "invoke"
                    || func == "invoke_signed"
                    || func == "invoke_unchecked"
                    || func.ends_with("::invoke")
                    || func.ends_with("::invoke_signed")
                    || func.ends_with("::invoke_unchecked")
                    || func.ends_with("::slice_invoke")
                    || func.ends_with("::slice_invoke_signed");
                if is_invoke {
                    if let Some(infos_arg) = node.args.iter().nth(1) {
                        if forwards_slice(infos_arg, param) {
                            self.hits
                                .push((fn_name.clone(), func, node.span().start().line));
                        }
                    }
                }
            }
            visit::visit_expr_call(self, node);
        }
    }

    let mut collector = Collector {
        stack: Vec::new(),
        hits: Vec::new(),
    };
    collector.visit_file(&file.syntax);

    collector
        .hits
        .into_iter()
        .map(|(fn_name, callee, line)| RuleMatch {
            rule_id: "SW023",
            severity: RuleSeverity::Critical,
            message: format!(
                "Handler `{fn_name}` forwards its raw accounts slice into CPI `{callee}`; \
                 unexamined accounts retain outer-transaction signer privileges inside the call."
            ),
            location: SourceLocation {
                path: file.path.display().to_string(),
                line,
                column: 1,
            },
            help: Some(
                "Destructure the accounts you need into named bindings, validate them \
                 (key/owner/is_signer), and pass an explicit array to the CPI instead of \
                 the raw slice."
                    .to_string(),
            ),
        })
        .collect()
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

    #[test]
    fn flags_remaining_accounts_forwarded_to_cpi() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke;

            #[derive(Accounts)]
            pub struct RouteSwap<'info> {
                pub user: Signer<'info>,
            }

            pub fn route_swap(ctx: Context<RouteSwap>, data: Vec<u8>) -> Result<()> {
                let ix = build_ix(&data);
                let mut accounts = vec![ctx.accounts.user.to_account_info()];
                accounts.extend_from_slice(ctx.remaining_accounts);
                invoke(&ix, &accounts)?;
                Ok(())
            }
            "#,
        );

        let rule = CpiRemainingAccountsRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW023");
    }

    #[test]
    fn does_not_flag_cpi_without_remaining_accounts() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Swap<'info> {
                pub user: Signer<'info>,
                #[account(mut)]
                pub vault: Account<'info, Vault>,
                pub token_program: Program<'info, Token>,
            }

            pub fn swap(ctx: Context<Swap>, amount: u64) -> Result<()> {
                token::transfer(
                    CpiContext::new(ctx.accounts.token_program.to_account_info(), Transfer {
                        from: ctx.accounts.vault.to_account_info(),
                        to: ctx.accounts.user.to_account_info(),
                        authority: ctx.accounts.user.to_account_info(),
                    }),
                    amount,
                )?;
                Ok(())
            }

            #[account]
            pub struct Vault { pub amount: u64 }
            "#,
        );

        let rule = CpiRemainingAccountsRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_remaining_accounts_without_cpi() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct ReadAccounts<'info> {
                pub authority: Signer<'info>,
            }

            pub fn read_all(ctx: Context<ReadAccounts>) -> Result<()> {
                for acc in ctx.remaining_accounts.iter() {
                    msg!("account: {}", acc.key());
                }
                Ok(())
            }
            "#,
        );

        let rule = CpiRemainingAccountsRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    // ─── native / pinocchio slice-forwarding layer ──────────────────────────

    fn run(file: &ParsedFile) -> Vec<RuleMatch> {
        CpiRemainingAccountsRule.match_file(
            file,
            &RuleContext {
                files: std::slice::from_ref(file),
            },
        )
    }

    #[test]
    fn native_flags_raw_slice_forwarded_to_cpi() {
        let file = parse_file(
            r#"
            pub fn proxy(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
                let ix = Instruction { program_id: *program_id, accounts: metas, data: data.to_vec() };
                pinocchio::cpi::slice_invoke(&ix, accounts)?;
                Ok(())
            }
            "#,
        );
        let findings = run(&file);
        let sw023: Vec<_> = findings.iter().filter(|f| f.rule_id == "SW023").collect();
        assert_eq!(sw023.len(), 1, "{findings:?}");
    }

    #[test]
    fn native_flags_tail_subslice_forward() {
        let file = parse_file(
            r#"
            pub fn proxy(accounts: &[AccountInfo]) -> ProgramResult {
                invoke(&ix, &accounts[2..])?;
                Ok(())
            }
            "#,
        );
        let sw023 = run(&file).iter().filter(|f| f.rule_id == "SW023").count();
        assert_eq!(sw023, 1);
    }

    #[test]
    fn native_does_not_flag_explicit_account_array() {
        let file = parse_file(
            r#"
            pub fn transfer(accounts: &[AccountInfo]) -> ProgramResult {
                let [payer, vault] = accounts else { return Err(ProgramError::NotEnoughAccountKeys); };
                if !payer.is_signer() {
                    return Err(ProgramError::MissingRequiredSignature);
                }
                pinocchio::cpi::invoke(&ix, &[payer, vault])?;
                Ok(())
            }
            "#,
        );
        let sw023 = run(&file).iter().filter(|f| f.rule_id == "SW023").count();
        assert_eq!(sw023, 0);
    }
}
