use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct UpdateVault<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

pub fn update_vault(ctx: Context<UpdateVault>, new_value: u64) -> Result<()> {
    ctx.accounts.vault.value = new_value;
    emit!(VaultUpdated { value: new_value });
    Ok(())
}

/// Safe: structured program log as observability (no Anchor emit!).
pub fn init_vault(ctx: Context<UpdateVault>) -> Result<()> {
    ctx.accounts.vault.value = 0;
    msg!("conf-vault-init:{}", ctx.accounts.vault.key());
    Ok(())
}

#[event]
pub struct VaultUpdated {
    pub value: u64,
}

#[account]
pub struct Vault {
    pub value: u64,
}
