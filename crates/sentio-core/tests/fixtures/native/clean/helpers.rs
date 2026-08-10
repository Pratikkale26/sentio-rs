pub fn bump_seed(program_id: &Pubkey, seeds: &[&[u8]], expected: &Pubkey) -> Result<u8, ProgramError> {
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
