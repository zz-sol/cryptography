//! `InitializePool`.
//!
//! Accounts: `[pool (s, w)]`. Data:
//! `custodian (32) ‖ issuer (32) ‖ mint_key (32) ‖ burn_key (32)`.
//!
//! The pool account is created by the client (system `CreateAccount` with
//! this program as owner and [`POOL_ACCOUNT_LEN`] bytes) and must sign here,
//! so only whoever holds its key can initialize it. `mint_key` and
//! `burn_key` are the verifier's content-addressed key accounts for `C_mint`
//! and `C_burn`; pinning them pins the circuits.

use {
    super::{expect_owned_by, expect_signer, expect_writable, take},
    crate::state::{Pool, POOL_ACCOUNT_LEN},
    pinocchio::{error::ProgramError, AccountView, Address, ProgramResult},
};

pub fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [pool] = accounts else {
        return Err(ProgramError::InvalidArgument);
    };
    expect_owned_by(pool, program_id)?;
    expect_signer(pool)?;
    expect_writable(pool)?;
    if pool.data_len() != POOL_ACCOUNT_LEN {
        return Err(ProgramError::InvalidAccountData);
    }

    let (custodian, rest) = take::<32>(payload)?;
    let (issuer, rest) = take::<32>(rest)?;
    let (mint_key, rest) = take::<32>(rest)?;
    let (burn_key, rest) = take::<32>(rest)?;
    if !rest.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut data = pool.try_borrow_mut()?;
    Pool::initialize(
        &mut data,
        &Address::new_from_array(*custodian),
        &Address::new_from_array(*issuer),
        &Address::new_from_array(*mint_key),
        &Address::new_from_array(*burn_key),
    )?;
    Ok(())
}
