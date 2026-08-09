use crate::finding::SourceLocation;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::ExprCall;

#[derive(Debug, Default)]
pub struct TypeCosplayRule;

impl Rule for TypeCosplayRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW006",
            title: "Type cosplay — missing discriminator check",
            severity: RuleSeverity::Critical,
            description: "Detects try_from_slice calls that do not skip the 8-byte Anchor \
                discriminator prefix. An attacker can supply an account of a different type with \
                the same byte layout, causing the program to operate on crafted data.",
            fix_guidance: "Skip the discriminator with &data[8..], or use Account<'info, T> so \
                Anchor verifies the discriminator automatically on every instruction.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let mut collector = TypeCosplayCollector {
            findings: Vec::new(),
        };
        visit::visit_file(&mut collector, &file.syntax);

        collector
            .findings
            .extend(native_deserializer_findings(file, ctx));

        collector
            .findings
            .into_iter()
            .map(|(message, line, column)| RuleMatch {
                rule_id: "SW006",
                severity: RuleSeverity::Critical,
                message,
                location: SourceLocation {
                    path: file.path.display().to_string(),
                    line,
                    column,
                },
                help: Some(
                    "Use Account<'info, T> (Anchor checks the discriminator for you), or \
                    pass &account.data.borrow()[8..] to skip the discriminator bytes manually."
                        .to_string(),
                ),
            })
            .collect()
    }
}

struct TypeCosplayCollector {
    findings: Vec<(String, usize, usize)>,
}

impl<'ast> Visit<'ast> for TypeCosplayCollector {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        let func = compact(&node.func.to_token_stream().to_string());

        if is_try_from_slice(&func) {
            let args_safe = node.args.iter().any(|arg| {
                let s = compact(&arg.to_token_stream().to_string());
                // Safe if the argument slices off the first 8 bytes or references the discriminator.
                s.contains("8..") || s.contains("discriminator")
            });

            if !args_safe {
                let loc = node.func.span().start();
                self.findings.push((
                    format!(
                        "`{func}` called without skipping the 8-byte discriminator; \
                        an attacker can pass an account of a different type with the same byte layout"
                    ),
                    loc.line,
                    loc.column + 1,
                ));
            }
        }

        visit::visit_expr_call(self, node);
    }
}

fn is_try_from_slice(func: &str) -> bool {
    func.ends_with("::try_from_slice") || func == "try_from_slice"
}

fn compact(s: &str) -> String {
    s.split_whitespace().collect()
}

/// Native / pinocchio layer: calls to PROJECT-LOCAL deserializers
/// (`CounterAccount::from_account_info(acc)`, `T::read(&data)`, ...) whose
/// resolved bodies never verify a discriminator. The resolution is
/// cross-file (RuleContext): an impl fn is safe when its body compares the
/// leading 8 bytes / references a DISCRIMINATOR const, directly or through
/// another fn of the same scan (from_account_info → Self::read). Calls that
/// resolve to nothing visible (external crates like spl's `unpack`, which
/// carry their own validation) are never flagged — the rule only judges
/// code it can see.
fn native_deserializer_findings(
    file: &ParsedFile,
    ctx: &RuleContext<'_>,
) -> Vec<(String, usize, usize)> {
    use std::collections::HashMap;

    const DESERIALIZER_METHODS: [&str; 6] = [
        "from_account_info",
        "from_bytes",
        "try_from_bytes",
        "read",
        "load",
        "unpack",
    ];

    // 1. Collect every impl fn body across the scan: (type, fn) → body text.
    let mut impl_fns: HashMap<(String, String), String> = HashMap::new();
    for scanned in ctx.files {
        collect_impl_fn_bodies(&scanned.syntax, &mut impl_fns);
    }

    // 2. Safety fixpoint: a fn is safe if its body shows discriminator
    //    evidence, or it calls a safe deserializer fn (two passes cover the
    //    from_account_info → read hop).
    let mut safe: HashMap<(String, String), bool> = impl_fns
        .iter()
        .map(|(k, body)| (k.clone(), body_has_discriminator_evidence(body)))
        .collect();
    for _ in 0..2 {
        let snapshot = safe.clone();
        for (key, body) in &impl_fns {
            if safe[key] {
                continue;
            }
            let inherits = snapshot.iter().any(|((ty, method), is_safe)| {
                *is_safe
                    && (body.contains(&format!("{ty}::{method}("))
                        || body.contains(&format!("Self::{method}(")) && *ty == key.0)
            });
            if inherits {
                safe.insert(key.clone(), true);
            }
        }
    }

    // 3. Flag call sites in THIS file resolving to a visible, unsafe
    //    deserializer.
    struct CallVisitor<'a> {
        safe: &'a std::collections::HashMap<(String, String), bool>,
        findings: Vec<(String, usize, usize)>,
    }

    impl<'ast> Visit<'ast> for CallVisitor<'_> {
        fn visit_expr_call(&mut self, node: &'ast ExprCall) {
            if let syn::Expr::Path(p) = &*node.func {
                let segs: Vec<String> = p
                    .path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect();
                if segs.len() >= 2 {
                    let method = segs[segs.len() - 1].clone();
                    let ty = segs[segs.len() - 2].clone();
                    if DESERIALIZER_METHODS.contains(&method.as_str()) && ty != "Self" {
                        if let Some(false) = self.safe.get(&(ty.clone(), method.clone())) {
                            let loc = node.func.span().start();
                            self.findings.push((
                                format!(
                                    "`{ty}::{method}` deserializes account data without any \
                                     discriminator check (resolved body has none); an attacker \
                                     can pass an account of a different type with the same layout"
                                ),
                                loc.line,
                                loc.column + 1,
                            ));
                        }
                    }
                }
            }
            visit::visit_expr_call(self, node);
        }
    }

    let mut visitor = CallVisitor {
        safe: &safe,
        findings: Vec::new(),
    };
    visitor.visit_file(&file.syntax);
    visitor.findings
}

fn collect_impl_fn_bodies(
    file: &syn::File,
    out: &mut std::collections::HashMap<(String, String), String>,
) {
    struct ImplVisitor<'a> {
        out: &'a mut std::collections::HashMap<(String, String), String>,
    }

    impl<'ast> Visit<'ast> for ImplVisitor<'_> {
        fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
            let ty = node.self_ty.to_token_stream().to_string().replace(' ', "");
            // Strip generics / path prefixes: `state::CounterAccount<'a>` → `CounterAccount`.
            let ty = ty
                .split('<')
                .next()
                .unwrap_or("")
                .rsplit("::")
                .next()
                .unwrap_or("")
                .to_string();
            for item in &node.items {
                if let syn::ImplItem::Fn(f) = item {
                    self.out.insert(
                        (ty.clone(), f.sig.ident.to_string()),
                        f.block.to_token_stream().to_string().replace(' ', ""),
                    );
                }
            }
            visit::visit_item_impl(self, node);
        }
    }

    ImplVisitor { out }.visit_file(file);
}

fn body_has_discriminator_evidence(body: &str) -> bool {
    body.contains("[..8]")
        || body.contains("[0..8]")
        || body.to_ascii_lowercase().contains("discriminator")
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
    fn flags_try_from_slice_without_discriminator_skip() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Process>) -> Result<()> {
                let data = VaultData::try_from_slice(&ctx.accounts.raw.data.borrow())?;
                Ok(())
            }
        "#,
        );
        let rule = TypeCosplayRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW006");
    }

    #[test]
    fn does_not_flag_try_from_slice_with_discriminator_skip() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Process>) -> Result<()> {
                let data = VaultData::try_from_slice(&ctx.accounts.raw.data.borrow()[8..])?;
                Ok(())
            }
        "#,
        );
        let rule = TypeCosplayRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_typed_account_with_no_manual_deserialization() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            #[derive(Accounts)]
            pub struct Process<'info> {
                pub vault: Account<'info, VaultData>,
                pub authority: Signer<'info>,
            }
            pub fn handler(ctx: Context<Process>) -> Result<()> {
                msg!("{}", ctx.accounts.vault.balance);
                Ok(())
            }
        "#,
        );
        let rule = TypeCosplayRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn does_not_flag_anchor_try_deserialize() {
        let file = parse_file(
            r#"
            use anchor_lang::prelude::*;
            pub fn handler(ctx: Context<Process>) -> Result<()> {
                let mut data: &[u8] = &ctx.accounts.raw.data.borrow();
                let account = VaultData::try_deserialize(&mut data)?;
                Ok(())
            }
        "#,
        );
        let rule = TypeCosplayRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    // ─── native / pinocchio deserializer layer ──────────────────────────────

    fn parse_named(path: &str, source: &str) -> ParsedFile {
        ParsedFile {
            path: PathBuf::from(path),
            source: source.to_string(),
            syntax: syn::parse_file(source).expect("source should parse"),
        }
    }

    const HANDLER: &str = r#"
        pub fn increment(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
            let [counter] = accounts else { return Err(ProgramError::NotEnoughAccountKeys); };
            if !counter.is_owned_by(program_id) {
                return Err(ProgramError::IncorrectProgramId);
            }
            let mut state = CounterAccount::from_account_info(counter)?;
            state.count += 1;
            CounterAccount::save(counter, &state)?;
            Ok(())
        }
    "#;

    fn state_file(with_disc_check: bool) -> String {
        let check = if with_disc_check {
            r#"
                if data[..8] != Self::DISCRIMINATOR {
                    return Err(ProgramError::InvalidAccountData);
                }
            "#
        } else {
            ""
        };
        format!(
            r#"
            impl CounterAccount {{
                pub const DISCRIMINATOR2: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
                pub fn read(data: &[u8]) -> Result<Self, ProgramError> {{
                    if data.len() < 16 {{
                        return Err(ProgramError::InvalidAccountData);
                    }}
                    {check}
                    let count = u64::from_le_bytes(data[8..16].try_into().unwrap());
                    Ok(Self {{ count }})
                }}
                pub fn from_account_info(account: &AccountInfo) -> Result<Self, ProgramError> {{
                    let data = unsafe {{ account.borrow_data_unchecked() }};
                    Self::read(&data)
                }}
            }}
            "#
        )
    }

    #[test]
    fn native_flags_deserializer_without_discriminator_check() {
        // The state impl is visible in the scan and its read() has no
        // discriminator compare — flag the handler's call site.
        let handler = parse_named("src/instructions/increment.rs", HANDLER);
        // Deliberately name the const DISCRIMINATOR2 and strip the check so
        // no textual evidence leaks in.
        let state_src = state_file(false).replace("DISCRIMINATOR2", "MAGIC2");
        let state = parse_named("src/state.rs", &state_src);
        let files = vec![handler, state];
        let findings = TypeCosplayRule.match_file(&files[0], &RuleContext { files: &files });
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(findings[0]
            .message
            .contains("CounterAccount::from_account_info"));
    }

    #[test]
    fn native_does_not_flag_deserializer_with_discriminator_check() {
        // Anvil-generated shape: from_account_info → Self::read, and read()
        // verifies data[..8] — safety propagates through the hop.
        let handler = parse_named("src/instructions/increment.rs", HANDLER);
        let state = parse_named("src/state.rs", &state_file(true));
        let files = vec![handler, state];
        let findings = TypeCosplayRule.match_file(&files[0], &RuleContext { files: &files });
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn native_does_not_flag_unresolved_external_deserializer() {
        // spl-style Account::unpack — impl not in the scan; the rule only
        // judges code it can see.
        let handler = parse_named(
            "src/instructions/check_balance.rs",
            r#"
            pub fn check_balance(accounts: &[AccountInfo]) -> ProgramResult {
                let [token_account] = accounts else { return Err(ProgramError::NotEnoughAccountKeys); };
                let acc = spl_token::state::Account::unpack(&token_account.try_borrow_data()?)?;
                Ok(())
            }
            "#,
        );
        let files = vec![handler];
        let findings = TypeCosplayRule.match_file(&files[0], &RuleContext { files: &files });
        assert!(findings.is_empty(), "{findings:?}");
    }
}
