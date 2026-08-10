use crate::anchor_accounts::{
    collect_anchor_accounts_index, AnchorAccountsField, AnchorFieldTypeKind,
};
use crate::finding::SourceLocation;
use crate::instruction_analysis::collect_instruction_index;
use crate::native_accounts::{collect_native_index, collect_token_trust, NativeCheckKind};
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;

#[derive(Debug, Default)]
pub struct MissingTokenMintCheckRule;

impl Rule for MissingTokenMintCheckRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW009",
            title: "Missing token account mint check",
            severity: RuleSeverity::High,
            description: "Detects mutable token account fields that have no token::mint or \
                associated_token::mint constraint, allowing an attacker to substitute a token \
                account for a different mint.",
            fix_guidance: "Add token::mint = <expected_mint> to the account constraint, or \
                use associated_token::mint = <mint> if this is an associated token account.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let index = collect_anchor_accounts_index(&file.syntax);
        let mut findings = Vec::new();

        for item in index.structs {
            for field in &item.fields {
                if !is_token_account(field) {
                    continue;
                }
                if !field.constraints.is_mut {
                    continue;
                }
                if field.constraints.has_token_mint_check()
                    || field.constraints.address
                    || field.constraints.init
                    || field.constraints.init_if_needed
                {
                    continue;
                }

                let name = field.ast.name.clone().unwrap_or_default();
                findings.push(RuleMatch {
                    rule_id: "SW009",
                    severity: RuleSeverity::High,
                    message: format!(
                        "Mutable token account `{name}` has no `token::mint` constraint; \
                        an attacker can substitute a token account for a different mint"
                    ),
                    location: SourceLocation {
                        path: file.path.display().to_string(),
                        line: field.ast.span.start_line,
                        column: 1,
                    },
                    help: Some(
                        "Add #[account(mut, token::mint = <mint_field>)] to pin this account \
                        to the expected mint, or use associated_token::mint = <mint_field>."
                            .to_string(),
                    ),
                });
            }
        }

        findings.extend(native_findings(file, ctx));

        findings
    }
}

fn is_token_account(field: &AnchorAccountsField) -> bool {
    matches!(
        field.type_info.kind,
        AnchorFieldTypeKind::Account | AnchorFieldTypeKind::InterfaceAccount
    ) && field.type_info.display.contains("TokenAccount")
}

/// Native / pinocchio layer: a trusted token balance whose account has no
/// mint field check and no address binding lets an attacker substitute a
/// token account for a DIFFERENT mint — amounts in a worthless token count
/// as if they were the expected one. Shares collect_token_trust with the
/// SW010 layer; an address binding (pinned/derived/stored vault key)
/// implies the vault's mint and exempts.
fn native_findings(file: &ParsedFile, ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
    let scan: Vec<&syn::File> = ctx.files.iter().map(|f| &f.syntax).collect();
    let trusts = collect_token_trust(&file.syntax, &scan);
    if trusts.is_empty() {
        return Vec::new();
    }
    let index = collect_native_index(&file.syntax);
    let instruction_index = collect_instruction_index(&file.syntax);
    let mut findings = Vec::new();
    let mut seen: std::collections::HashSet<(String, String)> = std::collections::HashSet::new();

    for trust in &trusts {
        if trust.mint_field_checked {
            continue;
        }
        let handler = index
            .handlers
            .iter()
            .find(|h| !trust.handler.is_empty() && h.name == trust.handler)
            .or_else(|| {
                index
                    .handlers
                    .iter()
                    .find(|h| h.accounts.iter().any(|a| a.name == trust.account))
            });
        let Some(handler) = handler else { continue };

        let address_bound = handler.has_check(&trust.account, NativeCheckKind::Key)
            || handler.has_check(&trust.account, NativeCheckKind::PdaDerivation)
            || instruction_index
                .functions
                .iter()
                .filter(|f| f.name == handler.name)
                .flat_map(|f| f.guards.iter())
                .any(|g| {
                    let c: String = g
                        .expression
                        .chars()
                        .filter(|ch| !ch.is_whitespace())
                        .collect();
                    c.contains(".key") && c.contains(&format!("{}.", trust.account))
                        || c.contains(&format!("{}.key", trust.account))
                });
        if address_bound {
            continue;
        }
        if !seen.insert((handler.name.clone(), trust.account.clone())) {
            continue;
        }

        let line = if trust.span.start_line > 0 {
            trust.span.start_line
        } else {
            handler
                .accounts
                .iter()
                .find(|a| a.name == trust.account)
                .map(|a| a.span.start_line)
                .unwrap_or(handler.span.start_line)
        };

        findings.push(RuleMatch {
            rule_id: "SW009",
            severity: RuleSeverity::High,
            message: format!(
                "Token account `{}` in handler `{}` has its balance trusted with no mint \
                 field check and no address binding; a token account for a different mint \
                 can be substituted.",
                trust.account, handler.name
            ),
            location: SourceLocation {
                path: file.path.display().to_string(),
                line,
                column: 1,
            },
            help: Some(
                "Compare the token account's mint field against the expected mint, or bind \
                 the account's address (stored vault key, PDA derivation, or constant)."
                    .to_string(),
            ),
        });
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleContext;
    use std::path::PathBuf;

    fn parse_file(source: &str) -> ParsedFile {
        ParsedFile {
            path: PathBuf::from("src/lib.rs"),
            source: source.to_string(),
            syntax: syn::parse_file(source).expect("source should parse"),
        }
    }

    #[test]
    fn flags_mut_token_account_without_mint_constraint() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::TokenAccount;

            #[derive(Accounts)]
            pub struct Transfer<'info> {
                #[account(mut)]
                pub from: Account<'info, TokenAccount>,
                pub authority: Signer<'info>,
            }
        "#,
        );
        let rule = MissingTokenMintCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW009");
    }

    #[test]
    fn does_not_flag_when_token_mint_constraint_present() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::{Mint, TokenAccount};

            #[derive(Accounts)]
            pub struct Transfer<'info> {
                #[account(mut, token::mint = mint)]
                pub from: Account<'info, TokenAccount>,
                pub mint: Account<'info, Mint>,
                pub authority: Signer<'info>,
            }
        "#,
        );
        let rule = MissingTokenMintCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_associated_token_account() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::TokenAccount;

            #[derive(Accounts)]
            pub struct Transfer<'info> {
                #[account(mut, associated_token::mint = mint, associated_token::authority = authority)]
                pub from: Account<'info, TokenAccount>,
                pub authority: Signer<'info>,
            }
        "#,
        );
        let rule = MissingTokenMintCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_read_only_token_account() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::TokenAccount;

            #[derive(Accounts)]
            pub struct CheckBalance<'info> {
                pub token_account: Account<'info, TokenAccount>,
                pub authority: Signer<'info>,
            }
        "#,
        );
        let rule = MissingTokenMintCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_custom_constraint_mint_check() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            use anchor_spl::token::TokenAccount;

            #[derive(Accounts)]
            pub struct PlaceBet<'info> {
                pub market: Account<'info, Market>,
                #[account(
                    mut,
                    constraint = user_token_account.owner == user.key(),
                    constraint = user_token_account.mint == market.mint,
                )]
                pub user_token_account: Account<'info, TokenAccount>,
                #[account(
                    mut,
                    constraint = vault.mint == market.mint,
                    constraint = vault.owner == market.key(),
                )]
                pub vault: Account<'info, TokenAccount>,
                pub user: Signer<'info>,
            }
        "#,
        );
        let rule = MissingTokenMintCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(
            findings.is_empty(),
            "custom .mint == constraints should count: {findings:?}"
        );
    }

    // ─── native / pinocchio token-trust layer ───────────────────────────────

    fn parse_named(p: &str, s: &str) -> ParsedFile {
        ParsedFile {
            path: PathBuf::from(p),
            source: s.to_string(),
            syntax: syn::parse_file(s).expect("parse"),
        }
    }

    const HELPER: &str = r#"
        pub fn token_account_amount(account: &AccountInfo) -> Result<u64, ProgramError> {
            let data = unsafe { account.borrow_data_unchecked() };
            if data.len() < 72 { return Err(ProgramError::InvalidAccountData); }
            Ok(u64::from_le_bytes(data[64..72].try_into().map_err(|_| ProgramError::InvalidAccountData)?))
        }
    "#;

    #[test]
    fn native_flags_trusted_balance_without_mint_binding() {
        let handler = parse_named(
            "src/instructions/payout.rs",
            r#"
            pub fn payout(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
                let [vault, authority] = accounts else { return Err(ProgramError::NotEnoughAccountKeys); };
                if !authority.is_signer() { return Err(ProgramError::MissingRequiredSignature); }
                let balance = token_account_amount(vault)?;
                Ok(())
            }
            "#,
        );
        let helper = parse_named("src/helpers.rs", HELPER);
        let files = vec![handler, helper];
        let findings =
            MissingTokenMintCheckRule.match_file(&files[0], &RuleContext { files: &files });
        assert_eq!(
            findings
                .iter()
                .filter(|f| f.message.contains("`vault`"))
                .count(),
            1,
            "{findings:?}"
        );
    }

    #[test]
    fn native_does_not_flag_unpacked_with_mint_compare() {
        let handler = parse_named(
            "src/instructions/payout.rs",
            r#"
            pub fn payout(accounts: &[AccountInfo]) -> ProgramResult {
                let [vault] = accounts else { return Err(ProgramError::NotEnoughAccountKeys); };
                let v = spl_token::state::Account::unpack(&vault.try_borrow_data()?)?;
                if v.mint != EXPECTED_MINT {
                    return Err(ProgramError::InvalidAccountData);
                }
                let balance = v.amount;
                Ok(())
            }
            "#,
        );
        let helper = parse_named("src/helpers.rs", HELPER);
        let files = vec![handler, helper];
        let findings =
            MissingTokenMintCheckRule.match_file(&files[0], &RuleContext { files: &files });
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn native_does_not_flag_address_bound_vault() {
        let handler = parse_named(
            "src/instructions/payout.rs",
            r#"
            pub fn payout(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
                let [state, vault] = accounts else { return Err(ProgramError::NotEnoughAccountKeys); };
                let s = Config::from_account_info(state)?;
                if s.vault != *vault.key() {
                    return Err(ProgramError::InvalidAccountData);
                }
                let balance = token_account_amount(vault)?;
                Ok(())
            }
            "#,
        );
        let helper = parse_named("src/helpers.rs", HELPER);
        let files = vec![handler, helper];
        let findings =
            MissingTokenMintCheckRule.match_file(&files[0], &RuleContext { files: &files });
        assert!(findings.is_empty(), "{findings:?}");
    }
}
