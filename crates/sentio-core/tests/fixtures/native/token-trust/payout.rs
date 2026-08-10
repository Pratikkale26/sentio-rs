pub fn payout(program_id: &Pubkey, accounts: &[AccountInfo], _data: &[u8]) -> ProgramResult {
    let [vault, authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let vault_balance = token_account_amount(vault)?;
    msg!("balance read");
    let _ = vault_balance;
    Ok(())
}
