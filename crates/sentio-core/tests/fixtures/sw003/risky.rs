use anchor_lang::prelude::*;
use solana_program::program::invoke;

#[derive(Accounts)]
pub struct ExecuteCpi<'info> {
    pub target_program: AccountInfo<'info>,
    pub authority: Signer<'info>,
}

pub fn handler(ctx: Context<ExecuteCpi>, data: Vec<u8>) -> Result<()> {
    let ix = solana_program::instruction::Instruction {
        program_id: *ctx.accounts.target_program.key,
        accounts: vec![],
        data,
    };
    invoke(&ix, &[ctx.accounts.target_program.clone()])?;
    Ok(())
}

/// Confused deputy: unvalidated "royalty" program + buyer signer in CPI metas.
#[derive(Accounts)]
pub struct BuyWithRoyalty<'info> {
    pub buyer: Signer<'info>,
    /// CHECK: attacker-controlled program
    pub royalty_program: AccountInfo<'info>,
    #[account(mut)]
    pub buyer_ata: AccountInfo<'info>,
}

pub fn buy_with_fake_royalty(ctx: Context<BuyWithRoyalty>) -> Result<()> {
    let ix = solana_program::instruction::Instruction {
        program_id: *ctx.accounts.royalty_program.key,
        accounts: vec![],
        data: vec![],
    };
    invoke(
        &ix,
        &[
            ctx.accounts.buyer.to_account_info(),
            ctx.accounts.buyer_ata.to_account_info(),
            ctx.accounts.royalty_program.to_account_info(),
        ],
    )?;
    Ok(())
}
