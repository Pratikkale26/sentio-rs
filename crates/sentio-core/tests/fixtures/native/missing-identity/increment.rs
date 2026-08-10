pub fn increment(program_id: &Pubkey, accounts: &[AccountInfo], _data: &[u8]) -> ProgramResult {
    let [counter, authority] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !counter.is_owned_by(program_id) {
        return Err(ProgramError::IncorrectProgramId);
    }
    let counter_account = counter;
    let mut counter = CounterAccount::from_account_info(counter_account)?;
    counter.count = counter.count.checked_add(1).ok_or(ProgramError::InvalidAccountData)?;
    msg!("count updated");
    CounterAccount::save(counter_account, &counter)?;
    Ok(())
}
