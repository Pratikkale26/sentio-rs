use crate::finding::SourceLocation;
use crate::instruction_analysis::{
    collect_instruction_index, CallEvidence, CallKind, WriteEvidence,
};
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;

#[derive(Debug, Default)]
pub struct MissingCpiReloadRule;

impl Rule for MissingCpiReloadRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW008",
            title: "Missing post-CPI account reload",
            severity: RuleSeverity::High,
            description: "Detects functions where account data is written after a CPI call without an intervening reload(), meaning the program may act on stale account state mutated by the callee.",
            fix_guidance: "Call account.reload()? after any CPI that may mutate accounts you read or write afterwards.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let index = collect_instruction_index(&file.syntax);
        let mut findings = Vec::new();

        let let_bindings = collect_let_binding_lines(&file.syntax);

        for function in &index.functions {
            // Exclude CpiContext builders — those are not invocations; the actual CPI
            // call (e.g. `token::transfer`) appears separately and carries the resolved
            // `cpi_account_names` from the builder's arguments.
            let cpi_calls: Vec<_> = function
                .calls
                .iter()
                .filter(|c| c.kind == CallKind::Cpi && !is_cpi_context_builder(&c.callee))
                .collect();

            if cpi_calls.is_empty() {
                continue;
            }

            // Report at most one finding per function (the first unguarded CPI with a
            // post-CPI write to an account that was part of that CPI).
            //
            // A write whose target local was (re)bound BETWEEN the CPI and the
            // write is not stale — the data was freshly constructed or
            // deserialized after the CPI (the native/transpiler pattern:
            // CPI, then `let mut state = T::from_account_info(..)` /
            // `T { ..defaults }`, mutate, save).
            let concerns = |w: &crate::instruction_analysis::WriteEvidence,
                            cpi_call: &crate::instruction_analysis::CallEvidence|
             -> bool {
                if w.order <= cpi_call.order {
                    return false;
                }
                let direct = write_concerns_cpi_account(w, cpi_call);
                let stale = stale_source_write(
                    &let_bindings,
                    &function.name,
                    &w.target,
                    cpi_call.span.start_line,
                    &cpi_call.cpi_account_names,
                );
                (direct || stale)
                    && !rebound_between(
                        &let_bindings,
                        &function.name,
                        &w.target,
                        cpi_call.span.start_line,
                        w.span.start_line,
                    )
            };
            let first_unguarded = cpi_calls.iter().find(|cpi_call| {
                let has_write_after = function.writes.iter().any(|w| concerns(w, cpi_call));

                if !has_write_after {
                    return false;
                }

                let first_write_order = function
                    .writes
                    .iter()
                    .filter(|w| concerns(w, cpi_call))
                    .map(|w| w.order)
                    .min()
                    .unwrap_or(usize::MAX);

                !function.calls.iter().any(|c| {
                    c.kind == CallKind::Reload
                        && c.order > cpi_call.order
                        && c.order < first_write_order
                })
            });

            if let Some(cpi_call) = first_unguarded {
                findings.push(RuleMatch {
                    rule_id: "SW008",
                    severity: RuleSeverity::High,
                    message: format!(
                        "Function `{}` writes to an account after a CPI call to `{}` without reloading; account data may be stale.",
                        function.name, cpi_call.callee
                    ),
                    location: SourceLocation {
                        path: file.path.display().to_string(),
                        line: cpi_call.span.start_line,
                        column: cpi_call.span.start_column,
                    },
                    help: Some(
                        "Call account.reload()? after the CPI to refresh account data before reading or writing."
                            .to_string(),
                    ),
                });
            }
        }

        findings
    }
}

fn is_cpi_context_builder(callee: &str) -> bool {
    callee.contains("CpiContext::new")
}

/// Returns true when `write` targets an account that was part of `cpi_call`.
///
/// If `cpi_account_names` is empty (raw invoke / unresolvable binding) we fall
/// back to flagging any field-access write (`target` contains `'.'`), which is
/// the conservative pre-cross-reference behaviour.
struct LetBinding {
    fn_name: String,
    var: String,
    line: usize,
    /// Accounts a deserializer init read from (`T::from_account_info(vault)`
    /// → ["vault"]); empty otherwise.
    sources: Vec<String>,
}

/// Every `let <var> = ..` in the file, with deserializer source accounts.
fn collect_let_binding_lines(file: &syn::File) -> Vec<LetBinding> {
    use syn::spanned::Spanned;
    use syn::visit::{self, Visit};

    struct Collector {
        fn_stack: Vec<String>,
        out: Vec<LetBinding>,
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
            if let Some(f) = self.fn_stack.last() {
                let ident = match &node.pat {
                    syn::Pat::Ident(i) => Some(i.ident.to_string()),
                    syn::Pat::Type(t) => match &*t.pat {
                        syn::Pat::Ident(i) => Some(i.ident.to_string()),
                        _ => None,
                    },
                    _ => None,
                };
                if let Some(ident) = ident {
                    // When the init is a deserializer call
                    // (`T::from_account_info(vault)`, `T::unpack(..)`), the
                    // bare-ident args are the SOURCE accounts this local's
                    // data came from.
                    let mut sources = Vec::new();
                    if let Some(init) = &node.init {
                        let mut expr: &syn::Expr = &init.expr;
                        while let syn::Expr::Try(t) = expr {
                            expr = &t.expr;
                        }
                        if let syn::Expr::Call(call) = expr {
                            let func = quote::ToTokens::to_token_stream(&call.func)
                                .to_string()
                                .replace(' ', "");
                            if func.contains("from_account_info")
                                || func.contains("::unpack")
                                || func.contains("::load")
                                || func.contains("try_from_bytes")
                                || func.contains("try_from_slice")
                            {
                                for arg in &call.args {
                                    let mut inner = arg;
                                    while let syn::Expr::Reference(r) = inner {
                                        inner = &r.expr;
                                    }
                                    if let syn::Expr::Path(pp) = inner {
                                        if pp.path.segments.len() == 1 {
                                            if let Some(seg) = pp.path.segments.first() {
                                                sources.push(seg.ident.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    self.out.push(LetBinding {
                        fn_name: f.clone(),
                        var: ident,
                        line: node.span().start().line,
                        sources,
                    });
                }
            }
            visit::visit_local(self, node);
        }
    }

    let mut collector = Collector {
        fn_stack: Vec::new(),
        out: Vec::new(),
    };
    collector.visit_file(file);
    collector.out
}

/// True when the write target's base local was bound between `cpi_line` and
/// `write_line` in `fn_name` — freshly constructed/deserialized post-CPI.
fn rebound_between(
    let_bindings: &[LetBinding],
    fn_name: &str,
    write_target: &str,
    cpi_line: usize,
    write_line: usize,
) -> bool {
    let base = write_base(write_target);
    if base.is_empty() {
        return false;
    }
    let_bindings
        .iter()
        .any(|b| b.fn_name == fn_name && b.var == base && b.line > cpi_line && b.line <= write_line)
}

fn write_base(write_target: &str) -> String {
    write_target
        .trim_start_matches(['*', '&', '('])
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect()
}

/// True when the write target's base local was deserialized BEFORE the CPI
/// from an account that the CPI touches — the pre-CPI copy is stale.
fn stale_source_write(
    let_bindings: &[LetBinding],
    fn_name: &str,
    write_target: &str,
    cpi_line: usize,
    cpi_account_names: &[String],
) -> bool {
    let base = write_base(write_target);
    if base.is_empty() || cpi_account_names.is_empty() {
        return false;
    }
    // Most recent binding of `base` at or before the CPI.
    let_bindings
        .iter()
        .filter(|b| b.fn_name == fn_name && b.var == base && b.line <= cpi_line)
        .max_by_key(|b| b.line)
        .is_some_and(|b| b.sources.iter().any(|s| cpi_account_names.contains(s)))
}

fn write_concerns_cpi_account(write: &WriteEvidence, cpi_call: &CallEvidence) -> bool {
    if cpi_call.cpi_account_names.is_empty() {
        return write.target.contains('.');
    }
    let account = extract_account_name_from_target(&write.target);
    !account.is_empty() && cpi_call.cpi_account_names.contains(&account)
}

/// Extract the account name from a write target string.
///
/// - `ctx.accounts.vault.amount`  → `"vault"`
/// - `vault.amount`               → `"vault"`
/// - plain identifier             → `""`  (not a field write, ignore)
fn extract_account_name_from_target(target: &str) -> String {
    if let Some(pos) = target.find(".accounts.") {
        let after = &target[pos + ".accounts.".len()..];
        return after
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
    }
    if target.contains('.') {
        return target.split('.').next().unwrap_or("").to_string();
    }
    String::new()
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
    fn flags_write_after_cpi_without_reload() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke_signed;

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                invoke_signed(&ix, &accounts, &seeds)?;
                ctx.accounts.vault.balance = 100;
                Ok(())
            }
        "#,
        );

        let rule = MissingCpiReloadRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW008");
    }

    #[test]
    fn does_not_flag_when_reload_between_cpi_and_write() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke_signed;

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                invoke_signed(&ix, &accounts, &seeds)?;
                ctx.accounts.vault.reload()?;
                ctx.accounts.vault.balance = 100;
                Ok(())
            }
        "#,
        );

        let rule = MissingCpiReloadRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_cpi_with_no_subsequent_writes() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use solana_program::program::invoke_signed;

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                invoke_signed(&ix, &accounts, &seeds)?;
                Ok(())
            }
        "#,
        );

        let rule = MissingCpiReloadRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    // ─── native / transpiler patterns (pinocchio scope) ─────────────────────

    #[test]
    fn does_not_flag_struct_freshly_bound_after_cpi() {
        // Transpiled shape: CPI first, then construct/deserialize the state
        // local, mutate, save. Nothing read is stale.
        let file = parse_file(
            r#"
            pub fn create_escrow(accounts: &[AccountInfo], deposit_amount: u64) -> ProgramResult {
                let [escrow, vault, mint_a, payer] = accounts else { return Err(ProgramError::NotEnoughAccountKeys); };
                pinocchio::cpi::invoke(&__ta_init_ix, &[vault, mint_a])?;
                let escrow_account = escrow;
                let mut escrow = Escrow { maker: Pubkey::default(), deposit_amount: 0 };
                escrow.maker = *payer.key();
                escrow.deposit_amount = deposit_amount;
                Escrow::save(escrow_account, &escrow)?;
                Ok(())
            }
            "#,
        );
        let rule = MissingCpiReloadRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn still_flags_struct_deserialized_before_cpi_and_written_after() {
        // Genuinely stale: state read pre-CPI, the CPI touches the same
        // account, and the pre-CPI copy is mutated afterwards.
        let file = parse_file(
            r#"
            pub fn settle(accounts: &[AccountInfo], amount: u64) -> ProgramResult {
                let [vault, payer] = accounts else { return Err(ProgramError::NotEnoughAccountKeys); };
                let mut state = Vault::from_account_info(vault)?;
                pinocchio::cpi::invoke(&ix, &[vault, payer])?;
                state.balance += amount;
                Vault::save(vault, &state)?;
                Ok(())
            }
            "#,
        );
        let rule = MissingCpiReloadRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1, "{findings:?}");
    }
}
