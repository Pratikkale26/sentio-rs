use crate::anchor_accounts::collect_anchor_accounts_index;
use crate::finding::SourceLocation;
use crate::instruction_analysis::collect_instruction_index;
use crate::native_accounts::{collect_native_index, NativeCheckKind};
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;

#[derive(Debug, Default)]
pub struct MissingPdaSeedsBumpRule;

impl Rule for MissingPdaSeedsBumpRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW012",
            title: "Missing seeds + bump on PDA",
            severity: RuleSeverity::High,
            description:
                "Detects PDA-like account field constraints that do not include both seeds and bump.",
            fix_guidance:
                "For PDA accounts, use #[account(seeds = [...], bump)] or bump = <expr> and keep derivation tied to trusted inputs.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let _ = ctx;
        let index = collect_anchor_accounts_index(&file.syntax);
        let mut findings = Vec::new();

        for item in index.structs {
            for field in item.fields {
                let has_seeds = field.constraints.has_seeds;
                let has_bump = field.constraints.has_bump;

                if !has_seeds && !has_bump {
                    continue;
                }

                if has_seeds && has_bump {
                    continue;
                }

                let line = field.ast.span.start_line;
                findings.push(RuleMatch {
                    rule_id: "SW012",
                    severity: RuleSeverity::High,
                    message: format!(
                        "PDA-like account constraint on `{}` is missing either `seeds` or `bump`.",
                        field.ast.name.clone().unwrap_or_default()
                    ),
                    location: SourceLocation {
                        path: file.path.display().to_string(),
                        line,
                        column: 1,
                    },
                    help: Some(
                        "Use #[account(seeds = [...], bump)] (or bump = <expr>) for PDA fields."
                            .to_string(),
                    ),
                });
            }
        }

        findings.extend(native_findings(file));

        findings
    }
}

/// Native / pinocchio layer: a deserialized state account that the handler
/// MUTATES must have its identity bound — by a PDA derivation check, a
/// constant key pin, or a has_one-shape compare of stored state against
/// another account's key. With none of the three, any account of the right
/// owner and type can be swapped in (cross-instance state confusion: pay
/// into someone else's counter, drain someone else's vault).
///
/// Deliberately conservative: read-only accounts, accounts created in the
/// handler (identity established by the PDA-signed creation), and accounts
/// with any of the three bindings are exempt.
fn native_findings(file: &ParsedFile) -> Vec<RuleMatch> {
    let index = collect_native_index(&file.syntax);
    let instruction_index = collect_instruction_index(&file.syntax);
    let mut findings = Vec::new();

    let source_lines: Vec<&str> = file.source.lines().collect();

    for handler in &index.handlers {
        // Anchor's #[account(zero)] init pattern, transpiled: the handler
        // verifies the account is pristine and writes the discriminator +
        // initial fields — identity is being ESTABLISHED here, not consumed.
        let start = handler.span.start_line.saturating_sub(1);
        let end = handler.span.end_line.min(source_lines.len());
        let body = source_lines.get(start..end).unwrap_or(&[]).join("\n");
        let is_init_handler = body.contains("AlreadyInitialized")
            || (body.contains("DISCRIMINATOR") && body.contains("copy_from_slice"));
        if is_init_handler {
            continue;
        }

        for account in &handler.accounts {
            if !account.data_accessed || account.created_in_handler {
                continue;
            }
            let mutated = handler.writes.iter().any(|w| w.account == account.name);
            if !mutated {
                continue;
            }
            if handler.has_check(&account.name, NativeCheckKind::PdaDerivation)
                || handler.has_check(&account.name, NativeCheckKind::Key)
            {
                continue;
            }
            // has_one shape: any guard in this fn that references the account
            // (its state fields via the shadowing local share its name) AND
            // reads some `.key` — `counter.authority != *authority.key()`.
            let has_identity_guard = instruction_index
                .functions
                .iter()
                .filter(|f| f.name == handler.name)
                .flat_map(|f| f.guards.iter())
                .any(|g| {
                    let compacted: String = g
                        .expression
                        .chars()
                        .filter(|c| !c.is_whitespace())
                        .collect();
                    compacted.contains(".key") && ident_referenced(&compacted, &account.name)
                });
            if has_identity_guard {
                continue;
            }

            findings.push(RuleMatch {
                rule_id: "SW012",
                severity: RuleSeverity::High,
                message: format!(
                    "State account `{}` in handler `{}` is deserialized and mutated with no \
                     identity binding — no PDA derivation check, no key pin, and no stored-key \
                     compare; any account of this type can be substituted.",
                    account.name, handler.name
                ),
                location: SourceLocation {
                    path: file.path.display().to_string(),
                    line: account.span.start_line,
                    column: 1,
                },
                help: Some(
                    "Verify the account's address against find_program_address(seeds, ..), or \
                     compare a stored authority/owner field against the expected signer's key."
                        .to_string(),
                ),
            });
        }
    }

    findings
}

fn ident_referenced(text: &str, name: &str) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
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
    fn flags_pda_without_bump() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(seeds = [b"vault"])]
                pub vault: Account<'info, Vault>,
            }
            "#,
        );

        let rule = MissingPdaSeedsBumpRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW012");
    }

    #[test]
    fn does_not_flag_when_seeds_and_bump_exist() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(seeds = [b"vault"], bump)]
                pub vault: Account<'info, Vault>,
            }
            "#,
        );

        let rule = MissingPdaSeedsBumpRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    // ─── native / pinocchio identity-binding layer ──────────────────────────

    fn run(file: &ParsedFile) -> Vec<RuleMatch> {
        MissingPdaSeedsBumpRule.match_file(
            file,
            &RuleContext {
                files: std::slice::from_ref(file),
            },
        )
    }

    const NO_BINDING: &str = r#"
        pub fn increment(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
            let counter = &accounts[0];
            let authority = &accounts[1];
            if !authority.is_signer() {
                return Err(ProgramError::MissingRequiredSignature);
            }
            if !counter.is_owned_by(program_id) {
                return Err(ProgramError::IncorrectProgramId);
            }
            let counter_account = counter;
            let mut counter = CounterAccount::from_account_info(counter_account)?;
            counter.count += 1;
            CounterAccount::save(counter_account, &counter)?;
            Ok(())
        }
    "#;

    #[test]
    fn native_flags_mutated_state_without_identity_binding() {
        // Owner + signer checked, but nothing ties THIS account to THIS
        // authority — any counter of the right type can be substituted.
        let file = parse_file(NO_BINDING);
        let findings = run(&file);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0].message.contains("`counter`"));
    }

    #[test]
    fn native_does_not_flag_with_pda_derivation() {
        let src = NO_BINDING.replace(
            "let counter_account = counter;",
            r#"let _bump = bump_seed(program_id, &[b"counter", authority.key().as_ref()], counter.key())?;
               let counter_account = counter;"#,
        );
        let file = parse_file(&src);
        assert!(run(&file).is_empty());
    }

    #[test]
    fn native_does_not_flag_with_has_one_compare() {
        let src = NO_BINDING.replace(
            "counter.count += 1;",
            r#"if counter.authority != *authority.key() {
                   return Err(ProgramError::InvalidAccountData);
               }
               counter.count += 1;"#,
        );
        let file = parse_file(&src);
        assert!(run(&file).is_empty());
    }

    #[test]
    fn native_does_not_flag_account_created_in_handler() {
        let file = parse_file(
            r#"
            pub fn initialize(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
                let [counter, payer] = accounts else { return Err(ProgramError::NotEnoughAccountKeys); };
                if !payer.is_signer() {
                    return Err(ProgramError::MissingRequiredSignature);
                }
                create_program_account(counter, payer, 48, program_id, &[])?;
                let mut state = CounterAccount::from_account_info(counter)?;
                state.count = 0;
                CounterAccount::save(counter, &state)?;
                Ok(())
            }
            "#,
        );
        assert!(run(&file).is_empty());
    }

    #[test]
    fn native_does_not_flag_read_only_access() {
        let file = parse_file(
            r#"
            pub fn read(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
                let [counter] = accounts else { return Err(ProgramError::NotEnoughAccountKeys); };
                let state = CounterAccount::from_account_info(counter)?;
                Ok(())
            }
            "#,
        );
        assert!(run(&file).is_empty());
    }
}
