pub struct CounterAccount {
    pub authority: [u8; 32],
    pub count: u64,
}

impl CounterAccount {
    pub const DISCRIMINATOR: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    pub fn read(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < 48 {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[..8] != Self::DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        let authority: [u8; 32] = data[8..40].try_into().map_err(|_| ProgramError::InvalidAccountData)?;
        let count = u64::from_le_bytes(data[40..48].try_into().map_err(|_| ProgramError::InvalidAccountData)?);
        Ok(Self { authority, count })
    }

    pub fn from_account_info(account: &AccountInfo) -> Result<Self, ProgramError> {
        let data = account.try_borrow_data()?;
        Self::read(&data)
    }

    pub fn save(_account: &AccountInfo, _value: &Self) -> ProgramResult {
        Ok(())
    }
}
