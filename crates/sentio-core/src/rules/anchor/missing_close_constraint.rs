use crate::anchor_accounts::collect_anchor_accounts_index;
use crate::finding::SourceLocation;
use crate::instruction_analysis::collect_instruction_index;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;
use quote::ToTokens;
use std::collections::{HashMap, HashSet};
use syn::visit::{self, Visit};

#[derive(Debug, Default)]
pub struct MissingCloseConstraintRule;

impl Rule for MissingCloseConstraintRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW022",
            title: "Manual account closure without close constraint",
            severity: RuleSeverity::High,
            description: "Detects manual lamport draining (borrow_mut on lamports) used to close \
                          accounts without Anchor's `close` constraint. Without `close`, account \
                          data is not zeroed and the discriminator is not overwritten, leaving the \
                          account vulnerable to reinitialization or data revival attacks.",
            fix_guidance: "Use #[account(mut, close = recipient)] instead of manually zeroing \
                           lamports. Anchor's close constraint zeroes account data, sets the \
                           CLOSED_ACCOUNT_DISCRIMINATOR, and transfers lamports atomically.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let accounts_index = collect_anchor_accounts_index(&file.syntax);
        let instruction_index = collect_instruction_index(&file.syntax);
        let safe_close_fns = collect_safe_close_fns(&file.syntax);
        let mut findings = Vec::new();

        // Check if the file already uses close constraint anywhere — if so, the author is
        // aware of it and the manual drain may be intentional in a separate context.
        let has_close_constraint = accounts_index
            .structs
            .iter()
            .any(|s| s.fields.iter().any(|f| f.constraints.close));

        if has_close_constraint {
            return findings;
        }

        // Look for manual lamport drains: writes whose target contains both "lamports"
        // and "borrow_mut" — the canonical pattern for manual account closure.
        // Report once per function (both the drain and the recipient top-up match,
        // but they describe the same closure operation).
        let full_drains = collect_full_drain_sites(&file.syntax);

        for function in &instruction_index.functions {
            // A function that pairs the drain with the full safe-close sequence
            // (reassign to the System Program + shrink data to zero, or a
            // dedicated close() call) is doing exactly what Anchor's `close`
            // constraint does under the hood — nothing is left to revive.
            if safe_close_fns.contains(&function.name) {
                continue;
            }
            // Only a FULL drain (balance set to 0, or the account's whole
            // lamport balance subtracted) is a close. Partial moves — rent
            // top-ups on realloc, refunds on shrink — leave a live account
            // and are not a revival risk.
            let drain = function.writes.iter().find(|w| {
                let t = w.target.to_lowercase();
                t.contains("lamports")
                    && t.contains("borrow_mut")
                    && full_drains
                        .iter()
                        .any(|(f, line)| f == &function.name && *line == w.span.start_line)
            });
            if let Some(write) = drain {
                findings.push(RuleMatch {
                    rule_id: "SW022",
                    severity: RuleSeverity::High,
                    message: format!(
                        "Function `{}` manually drains lamports to close an account without \
                         using Anchor's `close` constraint; account data is not zeroed and \
                         the account may be revived with stale data.",
                        function.name
                    ),
                    location: SourceLocation {
                        path: file.path.display().to_string(),
                        line: write.span.start_line,
                        column: 1,
                    },
                    help: Some(
                        "Replace manual lamport draining with #[account(mut, close = recipient)] \
                         to zero account data and prevent reinitialization attacks."
                            .to_string(),
                    ),
                });
            }
        }

        findings
    }
}

/// Collects `(fn_name, line)` sites where an account's lamports are FULLY
/// drained: `**x.lamports.borrow_mut() = 0`, or `-=`/`= .. - ..` of the
/// account's entire balance (directly or via a local bound to
/// `x.lamports()`). Partial moves (rent top-ups, shrink refunds) don't
/// qualify.
fn collect_full_drain_sites(file: &syn::File) -> Vec<(String, usize)> {
    use syn::spanned::Spanned;

    fn compact(tokens: impl quote::ToTokens) -> String {
        tokens.to_token_stream().to_string().replace(' ', "")
    }

    /// Base identifier of a lamports write target:
    /// `**offer_info.lamports.borrow_mut()` → `offer_info`.
    fn base_ident(target: &str) -> String {
        target
            .trim_start_matches(['*', '&', '('])
            .split(['.', '[', ')'])
            .next()
            .unwrap_or("")
            .to_string()
    }

    struct Collector {
        fn_stack: Vec<String>,
        /// local var → compact source expr for `let v = <expr>.lamports();`
        balance_vars: HashMap<String, String>,
        out: Vec<(String, usize)>,
    }

    impl Collector {
        fn is_lamports_target(text: &str) -> bool {
            let t = text.to_lowercase();
            t.contains("lamports") && t.contains("borrow_mut")
        }

        fn record(&mut self, span: proc_macro2::Span) {
            if let Some(f) = self.fn_stack.last() {
                self.out.push((f.clone(), span.start().line));
            }
        }

        /// Does `rhs` amount to the account's full balance? Either it reads
        /// `<base>.lamports()` directly, or it is a local previously bound to
        /// that read.
        fn rhs_is_full_balance(&self, rhs: &str, base: &str) -> bool {
            if rhs.contains(&format!("{base}.lamports()")) {
                return true;
            }
            self.balance_vars
                .get(rhs)
                .is_some_and(|src| src.contains(&format!("{base}.lamports()")))
        }
    }

    impl<'ast> Visit<'ast> for Collector {
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

        fn visit_local(&mut self, node: &'ast syn::Local) {
            if let (syn::Pat::Ident(ident), Some(init)) = (&node.pat, &node.init) {
                let text = compact(&init.expr);
                if text.contains(".lamports()") {
                    self.balance_vars.insert(ident.ident.to_string(), text);
                }
            }
            visit::visit_local(self, node);
        }

        fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
            let left = compact(&node.left);
            if Self::is_lamports_target(&left) {
                let rhs = compact(&node.right);
                if rhs == "0" || rhs.starts_with("0u") || rhs.starts_with("0i") {
                    self.record(node.span());
                }
            }
            visit::visit_expr_assign(self, node);
        }

        fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
            if matches!(node.op, syn::BinOp::SubAssign(_)) {
                let left = compact(&node.left);
                if Self::is_lamports_target(&left) {
                    let rhs = compact(&node.right);
                    let base = base_ident(&left);
                    if self.rhs_is_full_balance(&rhs, &base) {
                        self.record(node.span());
                    }
                }
            }
            visit::visit_expr_binary(self, node);
        }
    }

    let mut collector = Collector {
        fn_stack: Vec::new(),
        balance_vars: HashMap::new(),
        out: Vec::new(),
    };
    collector.visit_file(file);
    collector.out
}

/// Collects names of functions whose body performs a SAFE manual close —
/// the same operations Anchor's `close` constraint performs — so draining
/// lamports there is not a data-revival risk:
///
/// - `.assign(<system program id>)` **and** `.realloc(0, ..)` / `.resize(0)`
///   (solana_program / pinocchio native style: the account is handed back to
///   the System Program with zero-length data), or
/// - a bare `.close()` call (e.g. pinocchio's AccountInfo::close, which
///   zeroes data length, lamports, and owner in one step).
fn collect_safe_close_fns(file: &syn::File) -> HashSet<String> {
    #[derive(Default)]
    struct FnState {
        assigns_to_system: bool,
        shrinks_to_zero: bool,
        calls_close: bool,
    }

    #[derive(Default)]
    struct SafeCloseVisitor {
        stack: Vec<(String, FnState)>,
        safe: HashSet<String>,
    }

    impl SafeCloseVisitor {
        fn enter(&mut self, name: String) {
            self.stack.push((name, FnState::default()));
        }

        fn exit(&mut self) {
            if let Some((name, state)) = self.stack.pop() {
                if state.calls_close || (state.assigns_to_system && state.shrinks_to_zero) {
                    self.safe.insert(name);
                }
            }
        }

        fn record_method_call(&mut self, node: &syn::ExprMethodCall) {
            let Some((_, state)) = self.stack.last_mut() else {
                return;
            };
            match node.method.to_string().as_str() {
                "assign" => {
                    let args = node
                        .args
                        .iter()
                        .map(|a| a.to_token_stream().to_string())
                        .collect::<String>()
                        .replace(' ', "")
                        .to_ascii_lowercase();
                    if args.contains("system_program") || args.contains("systemprogram") {
                        state.assigns_to_system = true;
                    }
                }
                "realloc" | "resize" => {
                    let first_is_zero = node.args.first().is_some_and(|a| {
                        matches!(
                            a,
                            syn::Expr::Lit(syn::ExprLit {
                                lit: syn::Lit::Int(int),
                                ..
                            }) if int.base10_digits() == "0"
                        )
                    });
                    if first_is_zero {
                        state.shrinks_to_zero = true;
                    }
                }
                "close" if node.args.is_empty() => {
                    state.calls_close = true;
                }
                _ => {}
            }
        }
    }

    impl<'ast> Visit<'ast> for SafeCloseVisitor {
        fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
            self.enter(node.sig.ident.to_string());
            visit::visit_item_fn(self, node);
            self.exit();
        }

        fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
            self.enter(node.sig.ident.to_string());
            visit::visit_impl_item_fn(self, node);
            self.exit();
        }

        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            self.record_method_call(node);
            visit::visit_expr_method_call(self, node);
        }
    }

    let mut visitor = SafeCloseVisitor::default();
    visitor.visit_file(file);
    visitor.safe
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
    fn flags_manual_lamport_drain_without_close_constraint() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct CloseVault<'info> {
                #[account(mut)]
                pub vault: Account<'info, Vault>,
                #[account(mut)]
                pub authority: Signer<'info>,
            }

            pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
                let vault = &ctx.accounts.vault;
                let authority = &ctx.accounts.authority;
                let lamports = vault.to_account_info().lamports();
                **vault.to_account_info().lamports.borrow_mut() = 0;
                **authority.lamports.borrow_mut() += lamports;
                Ok(())
            }
            "#,
        );

        let rule = MissingCloseConstraintRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW022");
    }

    #[test]
    fn does_not_flag_when_close_constraint_present() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct CloseVault<'info> {
                #[account(mut, close = authority)]
                pub vault: Account<'info, Vault>,
                #[account(mut)]
                pub authority: Signer<'info>,
            }

            pub fn close_vault(ctx: Context<CloseVault>) -> Result<()> {
                Ok(())
            }
            "#,
        );

        let rule = MissingCloseConstraintRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_native_assign_realloc_close() {
        // solana_program-style safe close: drain + assign(SystemProgram) +
        // realloc(0). This is byte-for-byte what anchor_lang's close does,
        // so there is no revival risk. Shape taken from Anchor->native
        // transpiler output (Anvil).
        let file = parse_file(
            r#"
            pub fn close_program_account<'a>(
                account: &AccountInfo<'a>,
                destination: &AccountInfo<'a>,
            ) -> ProgramResult {
                if account.key == destination.key {
                    return Err(ProgramError::InvalidAccountData);
                }
                let lamports = account.lamports();
                **destination.try_borrow_mut_lamports()? = destination
                    .lamports()
                    .checked_add(lamports)
                    .ok_or(ProgramError::ArithmeticOverflow)?;
                **account.try_borrow_mut_lamports()? = 0;
                account.assign(&solana_program::system_program::ID);
                account.realloc(0, false)?;
                Ok(())
            }
            "#,
        );

        let rule = MissingCloseConstraintRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_pinocchio_resize_assign_close() {
        // pinocchio-style safe close: drain + resize(0) + assign(system id).
        let file = parse_file(
            r#"
            pub fn settle_and_close(
                payer: &AccountInfo,
                buffer: &AccountInfo,
            ) -> ProgramResult {
                *payer.try_borrow_mut_lamports()? += buffer.lamports();
                *buffer.try_borrow_mut_lamports()? = 0;
                buffer.resize(0)?;
                unsafe { buffer.assign(&SYSTEM_PROGRAM_ID) };
                Ok(())
            }
            "#,
        );

        let rule = MissingCloseConstraintRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn still_flags_drain_with_assign_but_no_shrink() {
        // assign() alone leaves the data buffer intact at full length until
        // the tx ends — the incomplete sequence must still flag.
        let file = parse_file(
            r#"
            pub fn drain_only(account: &AccountInfo, destination: &AccountInfo) -> ProgramResult {
                **destination.try_borrow_mut_lamports()? += account.lamports();
                **account.try_borrow_mut_lamports()? = 0;
                account.assign(&solana_program::system_program::ID);
                Ok(())
            }
            "#,
        );

        let rule = MissingCloseConstraintRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW022");
    }

    #[test]
    fn does_not_flag_partial_rent_refund_on_shrink() {
        // Transpiled realloc shape: shrink refunds the rent DELTA — the
        // account stays alive above rent minimum. Not a close.
        let file = parse_file(
            r#"
            pub fn append(state: &AccountInfo, owner: &AccountInfo, new_size: usize) -> ProgramResult {
                let __cur_lamports = state.lamports();
                let __new_rent_minimum = 1000000u64;
                let __refund = __cur_lamports - __new_rent_minimum;
                *state.try_borrow_mut_lamports()? = __cur_lamports - __refund;
                *owner.try_borrow_mut_lamports()? = owner.lamports() + __refund;
                state.realloc(new_size, false)?;
                Ok(())
            }
            "#,
        );
        let rule = MissingCloseConstraintRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn still_flags_full_drain_via_balance_local() {
        // `let bal = x.lamports(); **x...borrow_mut() -= bal;` empties the
        // account — a close without cleanup, still flagged.
        let file = parse_file(
            r#"
            pub fn drain(target: &AccountInfo, receiver: &AccountInfo) -> ProgramResult {
                let bal = target.lamports();
                **receiver.lamports.borrow_mut() += bal;
                **target.lamports.borrow_mut() -= bal;
                Ok(())
            }
            "#,
        );
        let rule = MissingCloseConstraintRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn does_not_flag_normal_lamport_read() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                #[account(mut)]
                pub vault: Account<'info, Vault>,
                #[account(mut)]
                pub authority: Signer<'info>,
            }

            pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
                let balance = ctx.accounts.vault.to_account_info().lamports();
                msg!("balance: {}", balance);
                Ok(())
            }
            "#,
        );

        let rule = MissingCloseConstraintRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }
}
