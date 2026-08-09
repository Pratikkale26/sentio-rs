use crate::anchor_accounts::{collect_anchor_accounts_index, AnchorFieldTypeKind};
use crate::finding::SourceLocation;
use crate::instruction_analysis::{analyze_account_field_usage, collect_instruction_index};
use crate::native_accounts::{collect_native_index, NativeCheckKind};
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;

#[derive(Debug, Default)]
pub struct MissingOwnerCheckRule;

impl Rule for MissingOwnerCheckRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW002",
            title: "Missing owner check",
            severity: RuleSeverity::Critical,
            description: "Detects AccountInfo or UncheckedAccount fields with no owner or address constraint and no owner guard in instruction logic, allowing an attacker to pass an account owned by any program. Skips fields used only as pubkey/seed identity. Does not model ZK proofs or checks in other programs (AST limitation).",
            fix_guidance: "Add an owner constraint (#[account(owner = expected_program::ID)]) or an address constraint, or validate account.owner in your instruction handler. If integrity is intentional via ZK public inputs or another program, document with /// CHECK: and use // sentio-ignore SW002 or a baseline — Sentio cannot verify that.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let accounts_index = collect_anchor_accounts_index(&file.syntax);
        let instruction_index = collect_instruction_index(&file.syntax);
        let mut findings = Vec::new();

        // Build a set of field names that have an owner guard in any instruction function.
        let guarded_names: Vec<String> = instruction_index
            .functions
            .iter()
            .flat_map(|f| f.guards.iter())
            .filter(|g| g.references_owner)
            .flat_map(|g| {
                // Extract word tokens from the expression that could be field names.
                g.expression
                    .split(|c: char| !c.is_alphanumeric() && c != '_')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .collect();

        for item in accounts_index.structs {
            for field in item.fields {
                let kind = &field.type_info.kind;

                // Only target AccountInfo and UncheckedAccount.
                if *kind != AnchorFieldTypeKind::AccountInfo
                    && *kind != AnchorFieldTypeKind::UncheckedAccount
                {
                    continue;
                }

                let field_name = field.ast.name.as_deref().unwrap_or("").to_string();
                let c = &field.constraints;

                // Skip if owner/address is pinned — including custom
                // `constraint = account.key() == stored` (address identity).
                if c.has_owner_or_address_check() {
                    continue;
                }

                // Skip data-account fields (SW011) and program-named fields (SW020).
                let is_data_account =
                    c.init || c.init_if_needed || !c.has_one.is_empty() || c.has_seeds;
                let is_program_field = field_name.to_lowercase().contains("program");

                if is_data_account || is_program_field {
                    continue;
                }

                // Identity-only: `.key()` and/or PDA seed input — never data/owner/lamports.
                // Applies even when `mut` (payout keys copied into state / seeds).
                // Does NOT skip "trust me, ZK / other program validates" without usage proof.
                if analyze_account_field_usage(&file.syntax, &field_name).is_identity_only() {
                    continue;
                }

                // Check if any instruction guard references owner AND names this field.
                let has_owner_guard = guarded_names.iter().any(|token| token == &field_name);

                if !has_owner_guard {
                    findings.push(RuleMatch {
                        rule_id: "SW002",
                        severity: RuleSeverity::Critical,
                        message: format!(
                            "Account `{field_name}` has no owner constraint and no owner guard in instruction logic; any program-owned account can be passed.",
                        ),
                        location: SourceLocation {
                            path: file.path.display().to_string(),
                            line: field.ast.span.start_line,
                            column: 1,
                        },
                        help: Some(
                            "Add #[account(owner = expected_program::ID)] or verify account.owner explicitly in the instruction handler."
                                .to_string(),
                        ),
                    });
                }
            }
        }

        findings.extend(native_findings(file));

        findings
    }
}

/// Native / pinocchio layer: an account whose data the handler deserializes
/// or reads without any owner verification (`is_owned_by` / `owner ==`) and
/// without an address pin lets an attacker pass a lookalike account owned by
/// any program — the same trust gap as an unchecked `AccountInfo` field in
/// Anchor.
fn native_findings(file: &ParsedFile) -> Vec<RuleMatch> {
    let index = collect_native_index(&file.syntax);
    let mut findings = Vec::new();

    for handler in &index.handlers {
        for account in &handler.accounts {
            // Program accounts are SW020's domain (mirrors the Anchor layer).
            if account.name.to_lowercase().contains("program") {
                continue;
            }

            // Only accounts whose data is actually trusted.
            if !account.data_accessed {
                continue;
            }

            // Owner verified, or identity constrained by address pin / PDA
            // derivation (an account at this program's PDA cannot be created
            // by another program's authority without our signature).
            if handler.has_check(&account.name, NativeCheckKind::Owner)
                || handler.has_check(&account.name, NativeCheckKind::Key)
                || handler.has_check(&account.name, NativeCheckKind::PdaDerivation)
            {
                continue;
            }

            // Created in this handler: the owner is being established by the
            // creation CPI, not trusted from the caller.
            if account.created_in_handler {
                continue;
            }

            findings.push(RuleMatch {
                rule_id: "SW002",
                severity: RuleSeverity::Critical,
                message: format!(
                    "Account `{}` in handler `{}` has its data read without any owner \
                     check; any program-owned account can be passed.",
                    account.name, handler.name
                ),
                location: SourceLocation {
                    path: file.path.display().to_string(),
                    line: account.span.start_line,
                    column: 1,
                },
                help: Some(
                    "Verify ownership before trusting data: `if account.owner != program_id` \
                     (solana_program) or `if !account.is_owned_by(program_id)` (pinocchio)."
                        .to_string(),
                ),
            });
        }
    }

    findings
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
    fn flags_account_info_without_owner_check() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                pub vault: AccountInfo<'info>,
                pub authority: Signer<'info>,
            }

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                let data = ctx.accounts.vault.try_borrow_data()?;
                Ok(())
            }
        "#,
        );

        let rule = MissingOwnerCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW002");
    }

    #[test]
    fn does_not_flag_when_owner_constraint_present() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(owner = token::ID)]
                pub vault: AccountInfo<'info>,
                pub authority: Signer<'info>,
            }
        "#,
        );

        let rule = MissingOwnerCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_when_owner_guard_in_instruction() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                pub vault: AccountInfo<'info>,
                pub authority: Signer<'info>,
            }

            pub fn handler(ctx: Context<Example>) -> Result<()> {
                require!(
                    ctx.accounts.vault.owner == &token::ID,
                    ErrorCode::InvalidOwner
                );
                Ok(())
            }
        "#,
        );

        let rule = MissingOwnerCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_address_constrained_account() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(address = some_known::ID)]
                pub vault: AccountInfo<'info>,
                pub authority: Signer<'info>,
            }
        "#,
        );

        let rule = MissingOwnerCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_admin_stored_as_pubkey_only() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct CreateAmm<'info> {
                #[account(init, payer = payer, space = 8 + 64)]
                pub amm: Account<'info, Amm>,
                /// CHECK: Read only, delegatable creation
                pub admin: AccountInfo<'info>,
                #[account(mut)]
                pub payer: Signer<'info>,
                pub system_program: Program<'info, System>,
            }

            pub fn create_amm(ctx: Context<CreateAmm>) -> Result<()> {
                ctx.accounts.amm.admin = ctx.accounts.admin.key();
                Ok(())
            }

            #[account]
            pub struct Amm {
                pub admin: Pubkey,
            }
        "#,
        );

        let rule = MissingOwnerCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(
            findings.is_empty(),
            "stored-pubkey admin must not be SW002: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_custom_key_equality_constraint() {
        // Odomart FP: payout destination pinned to stored pubkey — address identity.
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct WithdrawTeamFees<'info> {
                pub team_config: Account<'info, TeamConfig>,
                #[account(
                    constraint = team_wallet.key() == team_config.team_wallet @ RiseError::InvalidTeamWallet
                )]
                pub team_wallet: UncheckedAccount<'info>,
            }

            #[account]
            pub struct TeamConfig {
                pub team_wallet: Pubkey,
            }
        "#,
        );

        let rule = MissingOwnerCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(
            findings.is_empty(),
            "key() == stored pubkey must not be SW002: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_custom_owner_equality_constraint() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Example<'info> {
                #[account(constraint = vault.owner == &token_program.key())]
                pub vault: AccountInfo<'info>,
                pub token_program: AccountInfo<'info>,
            }
        "#,
        );

        let rule = MissingOwnerCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(
            findings.is_empty(),
            "custom .owner == must not be SW002: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_mut_pubkey_only_identity() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Init<'info> {
                #[account(init, payer = payer, space = 8 + 32)]
                pub config: Account<'info, Config>,
                /// CHECK: pubkey stored in config only
                #[account(mut)]
                pub recipient: UncheckedAccount<'info>,
                #[account(mut)]
                pub payer: Signer<'info>,
                pub system_program: Program<'info, System>,
            }

            pub fn init(ctx: Context<Init>) -> Result<()> {
                ctx.accounts.config.recipient = ctx.accounts.recipient.key();
                Ok(())
            }

            #[account]
            pub struct Config {
                pub recipient: Pubkey,
            }
        "#,
        );

        let rule = MissingOwnerCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(
            findings.is_empty(),
            "mut identity-only must not be SW002: {findings:?}"
        );
    }

    #[test]
    fn does_not_flag_seed_only_account() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct CreatePda<'info> {
                /// CHECK: only used as PDA seed
                pub to_owner: UncheckedAccount<'info>,
                #[account(
                    init,
                    payer = payer,
                    space = 8,
                    seeds = [b"pos", to_owner.key().as_ref()],
                    bump
                )]
                pub position: Account<'info, Position>,
                #[account(mut)]
                pub payer: Signer<'info>,
                pub system_program: Program<'info, System>,
            }

            pub fn create(ctx: Context<CreatePda>) -> Result<()> {
                Ok(())
            }

            #[account]
            pub struct Position {}
        "#,
        );

        let rule = MissingOwnerCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(
            findings.is_empty(),
            "seed-only UncheckedAccount must not be SW002: {findings:?}"
        );
    }

    #[test]
    fn still_flags_mut_data_use_without_owner() {
        // ZK-bound recipient that is actually read as data still needs a visible check
        // for SW002 — proof binding is out of scope for AST.
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;

            #[derive(Accounts)]
            pub struct Withdraw<'info> {
                /// CHECK: bound in Groth16 public inputs (not visible to AST)
                #[account(mut)]
                pub recipient: UncheckedAccount<'info>,
            }

            pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
                let _data = ctx.accounts.recipient.try_borrow_data()?;
                Ok(())
            }
        "#,
        );

        let rule = MissingOwnerCheckRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(
            findings.len(),
            1,
            "data use without owner must still flag: {findings:?}"
        );
    }

    // ─── native / pinocchio layer ───────────────────────────────────────────

    fn run(file: &ParsedFile) -> Vec<RuleMatch> {
        MissingOwnerCheckRule.match_file(
            file,
            &RuleContext {
                files: std::slice::from_ref(file),
            },
        )
    }

    #[test]
    fn native_flags_deserialization_without_owner_check() {
        // Transpiler alias shape: `let counter_account = counter;` then
        // deserialize through the alias — the owner check is absent.
        let file = parse_file(
            r#"
            pub fn increment(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
                let counter = &accounts[0];
                let authority = &accounts[1];
                if !authority.is_signer() {
                    return Err(ProgramError::MissingRequiredSignature);
                }
                let counter_account = counter;
                let mut counter = CounterAccount::from_account_info(counter_account)?;
                counter.count += 1;
                CounterAccount::save(counter_account, &counter)?;
                Ok(())
            }
            "#,
        );
        let findings = run(&file);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`counter`"));
    }

    #[test]
    fn native_does_not_flag_owner_checked_account() {
        let file = parse_file(
            r#"
            pub fn increment(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
                let counter = &accounts[0];
                if counter.owner() != program_id {
                    return Err(ProgramError::IncorrectProgramId);
                }
                let counter_account = counter;
                let mut counter = CounterAccount::from_account_info(counter_account)?;
                counter.count += 1;
                Ok(())
            }
            "#,
        );
        assert!(run(&file).is_empty());
    }

    #[test]
    fn native_does_not_flag_is_owned_by_pinocchio_form() {
        let file = parse_file(
            r#"
            pub fn increment(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
                let [counter] = accounts else { return Err(ProgramError::NotEnoughAccountKeys); };
                if !counter.is_owned_by(program_id) {
                    return Err(ProgramError::IncorrectProgramId);
                }
                let state = CounterAccount::from_account_info(counter)?;
                Ok(())
            }
            "#,
        );
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
                create_program_account(counter, payer, 16, program_id, &[])?;
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
    fn native_does_not_flag_accounts_without_data_reads() {
        let file = parse_file(
            r#"
            pub fn transfer(accounts: &[AccountInfo]) -> ProgramResult {
                let [payer, recipient] = accounts else { return Err(ProgramError::NotEnoughAccountKeys); };
                if !payer.is_signer() {
                    return Err(ProgramError::MissingRequiredSignature);
                }
                Ok(())
            }
            "#,
        );
        assert!(run(&file).is_empty());
    }

    #[test]
    fn native_does_not_flag_pda_derivation_checked_account() {
        let file = parse_file(
            r#"
            pub fn read_state(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
                let [vault] = accounts else { return Err(ProgramError::NotEnoughAccountKeys); };
                let (expected, _bump) = find_program_address(&[b"vault"], program_id);
                if vault.key() != &expected {
                    return Err(ProgramError::InvalidSeeds);
                }
                let state = Vault::from_account_info(vault)?;
                Ok(())
            }
            "#,
        );
        assert!(run(&file).is_empty());
    }
}
