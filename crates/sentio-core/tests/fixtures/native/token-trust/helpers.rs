pub fn token_account_amount(account: &AccountInfo) -> Result<u64, ProgramError> {
    let data = unsafe { account.borrow_data_unchecked() };
    if data.len() < 72 {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(u64::from_le_bytes(data[64..72].try_into().map_err(|_| ProgramError::InvalidAccountData)?))
}
