use crate::finding::SourceLocation;
use crate::rules::{Rule, RuleContext, RuleMatch, RuleMetadata, RuleSeverity};
use crate::syntax::ParsedFile;
use quote::ToTokens;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::ExprCall;

#[derive(Debug, Default)]
pub struct CreateProgramAddressRule;

impl Rule for CreateProgramAddressRule {
    fn metadata(&self) -> &RuleMetadata {
        static METADATA: RuleMetadata = RuleMetadata {
            id: "SW026",
            title: "create_program_address used instead of find_program_address",
            severity: RuleSeverity::High,
            description: "Detects use of create_program_address, which accepts a caller-supplied \
                          bump and does not verify it is canonical. An attacker can provide a \
                          non-canonical bump to derive a different valid PDA, bypassing address \
                          derivation assumptions. find_program_address always returns the \
                          canonical (highest valid) bump.",
            fix_guidance: "Use Pubkey::find_program_address to derive canonical PDAs, or in \
                           Anchor use the seeds + bump constraint which enforces canonicality \
                           automatically.",
        };
        &METADATA
    }

    fn match_file(&self, file: &ParsedFile, _ctx: &RuleContext<'_>) -> Vec<RuleMatch> {
        let mut collector = CreateProgramAddressCollector {
            findings: Vec::new(),
            canonical_search_depth: 0,
        };
        visit::visit_file(&mut collector, &file.syntax);

        collector
            .findings
            .into_iter()
            .map(|(message, line, column)| RuleMatch {
                rule_id: "SW026",
                severity: RuleSeverity::High,
                message,
                location: SourceLocation {
                    path: file.path.display().to_string(),
                    line,
                    column,
                },
                help: Some(
                    "Replace with Pubkey::find_program_address(&seeds, program_id) which \
                     returns the canonical bump, or use Anchor's seeds + bump constraint."
                        .to_string(),
                ),
            })
            .collect()
    }
}

struct CreateProgramAddressCollector {
    findings: Vec<(String, usize, usize)>,
    /// Depth of enclosing exhaustive descending bump loops (`for b in (0..=255).rev()`).
    /// Inside such a loop the bump is not caller-supplied — the loop enumerates every
    /// bump from 255 down, which is what find_program_address does internally, so a
    /// create_program_address there is a canonical search, not an unchecked derive.
    canonical_search_depth: usize,
}

/// Returns true when a for-loop iterator enumerates the full bump space in
/// descending order: a `.rev()` over a range ending at 255 (inclusive) or 256
/// (exclusive), e.g. `(0..=255u8).rev()` or `(0..256).rev()`. Descending order
/// is required — the first match of a 255→0 sweep is the canonical bump, while
/// an ascending sweep would accept the lowest valid bump, which is not.
fn is_canonical_bump_iterator(expr: &syn::Expr) -> bool {
    let compact = expr.to_token_stream().to_string().replace(' ', "");
    if !compact.contains(".rev()") {
        return false;
    }
    compact.contains("..=255") || compact.contains("..256")
}

impl<'ast> Visit<'ast> for CreateProgramAddressCollector {
    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        let canonical = is_canonical_bump_iterator(&node.expr);
        if canonical {
            self.canonical_search_depth += 1;
        }
        visit::visit_expr_for_loop(self, node);
        if canonical {
            self.canonical_search_depth -= 1;
        }
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        let callee = node.func.to_token_stream().to_string().replace(' ', "");
        if callee.contains("create_program_address") && self.canonical_search_depth == 0 {
            let loc = node.span().start();
            self.findings.push((
                "create_program_address accepts a caller-supplied bump and does not enforce \
                 canonical derivation; use find_program_address instead"
                    .to_string(),
                loc.line,
                loc.column + 1,
            ));
        }
        visit::visit_expr_call(self, node);
    }
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
    fn flags_create_program_address() {
        let file = parse_file(
            r#"
            use solana_program::pubkey::Pubkey;
            pub fn derive(seeds: &[&[u8]], program_id: &Pubkey, bump: u8) -> Pubkey {
                let seeds_with_bump: Vec<&[u8]> = seeds.iter().copied()
                    .chain(std::iter::once(&[bump][..]))
                    .collect();
                Pubkey::create_program_address(&seeds_with_bump, program_id).unwrap()
            }
            "#,
        );
        let rule = CreateProgramAddressRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SW026");
    }

    #[test]
    fn does_not_flag_canonical_descending_bump_search() {
        // Hand-rolled find_program_address: exhaustive 255→0 sweep verified
        // against an expected key. The bump is loop-enumerated, not
        // caller-supplied, so the canonical-bump premise of SW026 does not
        // apply. This shape is emitted by transpilers (e.g. Anvil) and
        // appears in native programs that avoid the find_program_address
        // syscall wrapper.
        let file = parse_file(
            r#"
            pub fn bump_seed(
                program_id: &Pubkey,
                seeds: &[&[u8]],
                expected: &Pubkey,
            ) -> Result<u8, ProgramError> {
                for bump in (0..=255u8).rev() {
                    let mut seeds_with_bump: [&[u8]; 16] = [&[]; 16];
                    let len = seeds.len().min(15);
                    seeds_with_bump[..len].copy_from_slice(&seeds[..len]);
                    let bump_slice = &[bump];
                    seeds_with_bump[len] = bump_slice;
                    if let Ok(derived) = pinocchio::pubkey::create_program_address(&seeds_with_bump[..len + 1], program_id) {
                        if &derived == expected {
                            return Ok(bump);
                        }
                    }
                }
                Err(ProgramError::InvalidSeeds)
            }
            "#,
        );
        let rule = CreateProgramAddressRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn still_flags_ascending_bump_loop() {
        // An ascending sweep accepts the LOWEST valid bump — not canonical —
        // so the exemption must require .rev().
        let file = parse_file(
            r#"
            pub fn first_valid_bump(program_id: &Pubkey, seeds: &[&[u8]], expected: &Pubkey) -> Option<u8> {
                for bump in 0..=255u8 {
                    if let Ok(derived) = Pubkey::create_program_address(&[seeds[0], &[bump]], program_id) {
                        if &derived == expected {
                            return Some(bump);
                        }
                    }
                }
                None
            }
            "#,
        );
        let rule = CreateProgramAddressRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn still_flags_create_program_address_after_canonical_loop() {
        // A canonical loop elsewhere in the fn must not exempt a separate
        // call outside the loop body.
        let file = parse_file(
            r#"
            pub fn mixed(program_id: &Pubkey, seeds: &[&[u8]], expected: &Pubkey, user_bump: u8) -> Option<Pubkey> {
                for bump in (0..=255u8).rev() {
                    let _ = Pubkey::create_program_address(&[seeds[0], &[bump]], program_id);
                }
                Pubkey::create_program_address(&[seeds[0], &[user_bump]], program_id).ok()
            }
            "#,
        );
        let rule = CreateProgramAddressRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn does_not_flag_find_program_address() {
        let file = parse_file(
            r#"
            use solana_program::pubkey::Pubkey;
            pub fn derive(seeds: &[&[u8]], program_id: &Pubkey) -> (Pubkey, u8) {
                Pubkey::find_program_address(seeds, program_id)
            }
            "#,
        );
        let rule = CreateProgramAddressRule;
        let findings = rule.match_file(
            &file,
            &RuleContext {
                files: std::slice::from_ref(&file),
            },
        );
        assert!(findings.is_empty());
    }
}
