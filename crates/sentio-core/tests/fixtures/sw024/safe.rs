use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct CalcFee<'info> {
    pub config: Account<'info, Config>,
}

pub fn calc_fee(ctx: Context<CalcFee>, amount: u64) -> Result<u64> {
    let rate = ctx.accounts.config.rate;
    require!(rate != 0, ErrorCode::InvalidRate);
    let fee = amount.checked_div(rate).ok_or(ErrorCode::InvalidRate)?;
    Ok(fee)
}

/// Safe: divisor is a non-zero compile-time const (incl. cast).
pub const ROOT_RING_SIZE: usize = 30;

pub fn advance_root_ring(head: u32) -> u32 {
    (head + 1) % ROOT_RING_SIZE as u32
}

#[account]
pub struct Config {
    pub rate: u64,
}

#[error_code]
pub enum ErrorCode {
    InvalidRate,
}
