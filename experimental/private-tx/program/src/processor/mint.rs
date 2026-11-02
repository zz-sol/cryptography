//! `Mint`: issue one note with a public amount.
//!
//! Accounts: `[pool (w), issuer (s), verifier program, mint key]`.
//! Data: `proof (256) ‖ commitment (32) ‖ value (u64 LE)`.
//!
//! The proof is `C_mint` with public inputs `(commitment, value)`. After the
//! verifier accepts it the commitment is appended to the tree and `value`
//! added to the supply. Who may mint is the issuer's signature, not the
//! circuit's business.

use {
    super::{expect_owned_by, expect_signer, expect_verifier, expect_writable, take, verify_proof},
    crate::state::{u64_to_field, Pool},
    pinocchio::{error::ProgramError, AccountView, Address, ProgramResult},
    solana_groth16_verify::constants::PROOF_SIZE,
};

pub fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [pool, issuer, verifier, key] = accounts else {
        return Err(ProgramError::InvalidArgument);
    };
    expect_owned_by(pool, program_id)?;
    expect_writable(pool)?;
    expect_signer(issuer)?;

    let (proof, rest) = take::<PROOF_SIZE>(payload)?;
    let (commitment, rest) = take::<32>(rest)?;
    let (value, rest) = take::<8>(rest)?;
    if !rest.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let value = u64::from_le_bytes(*value);

    {
        let mut data = pool.try_borrow_mut()?;
        let p = Pool::from_bytes(&mut data)?;
        if issuer.address().as_ref() != p.issuer() {
            return Err(ProgramError::MissingRequiredSignature);
        }
        expect_verifier(verifier, key, p.mint_key())?;
    }

    verify_proof(key, proof, &[*commitment, u64_to_field(value)])?;

    let mut data = pool.try_borrow_mut()?;
    let mut p = Pool::from_bytes(&mut data)?;
    p.append(commitment)?;
    p.add_supply(value)
}
