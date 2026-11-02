//! `Burn`: remove one note with a public amount, as its owner (unshield) or
//! as the custodian (forfeiture).
//!
//! Accounts: `[pool (w), payer (s, w), nullifier PDA (w), system program,
//! verifier program, burn key, custodian]`.
//! Data: `proof (256) ‖ root (32) ‖ nullifier (32) ‖ value (u64 LE) ‖ forced (1) ‖ destination (32)`.
//!
//! The proof is `C_burn` with public inputs `(root, nullifier, value,
//! forced, sighash)`, where `sighash = Poseidon(pool, destination,
//! nullifier, value)` is recomputed here from the instruction. For an
//! unshield the circuit checked the owner's signature over that sighash, so
//! the proof is only good for this pool and this destination: a copy with
//! another destination fails verification. The root must be in the pool's
//! history; the nullifier PDA (`["nullifier", pool, nullifier]`) must not
//! exist yet and is created here, which is what records the spend;
//! `forced = 1` additionally needs the custodian's signature, since the
//! circuit then checks no owner signature. `value` leaves the supply; with
//! no vault in this milestone, `destination` is recorded in the statement
//! but nothing is transferred to it yet.

use {
    super::{expect_owned_by, expect_signer, expect_verifier, expect_writable, take, verify_proof},
    crate::{
        error::PoolError,
        state::{
            burn_sighash, u64_to_field, Pool, NULLIFIER_ACCOUNT_LEN, NULLIFIER_DISCRIMINATOR,
            NULLIFIER_SEED,
        },
    },
    pinocchio::{
        cpi::{Seed, Signer},
        error::ProgramError,
        AccountView, Address, ProgramResult,
    },
    pinocchio_system::instructions::CreateAccount,
    solana_groth16_verify::constants::{PROOF_SIZE, SYSTEM_PROGRAM_ID},
};

pub fn process(
    program_id: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [pool, payer, nullifier_account, system_program, verifier, key, custodian] = accounts
    else {
        return Err(ProgramError::InvalidArgument);
    };
    expect_owned_by(pool, program_id)?;
    expect_writable(pool)?;
    expect_signer(payer)?;
    expect_writable(payer)?;
    expect_writable(nullifier_account)?;
    if system_program.address() != &SYSTEM_PROGRAM_ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    let (proof, rest) = take::<PROOF_SIZE>(payload)?;
    let (root, rest) = take::<32>(rest)?;
    let (nullifier, rest) = take::<32>(rest)?;
    let (value, rest) = take::<8>(rest)?;
    let (forced, rest) = take::<1>(rest)?;
    let (destination, rest) = take::<32>(rest)?;
    if !rest.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let value = u64::from_le_bytes(*value);
    let forced = match forced[0] {
        0 => false,
        1 => true,
        _ => return Err(PoolError::InvalidForcedFlag.into()),
    };

    {
        let mut data = pool.try_borrow_mut()?;
        let p = Pool::from_bytes(&mut data)?;
        expect_verifier(verifier, key, p.burn_key())?;
        if forced {
            if custodian.address().as_ref() != p.custodian() {
                return Err(ProgramError::MissingRequiredSignature);
            }
            expect_signer(custodian)?;
        }
        if !p.knows_root(root) {
            return Err(PoolError::UnknownRoot.into());
        }
    }

    // The nullifier account must be the PDA and must not exist yet.
    let (expected, bump) = Address::find_program_address(
        &[NULLIFIER_SEED, pool.address().as_ref(), nullifier],
        program_id,
    );
    if nullifier_account.address() != &expected {
        return Err(PoolError::NullifierAddressMismatch.into());
    }
    if nullifier_account.lamports() != 0
        || nullifier_account.data_len() != 0
        || !nullifier_account.owned_by(&SYSTEM_PROGRAM_ID)
    {
        return Err(PoolError::NullifierAlreadySpent.into());
    }

    let sighash = burn_sighash(pool.address().as_array(), destination, nullifier, value)?;
    verify_proof(
        key,
        proof,
        &[
            *root,
            *nullifier,
            u64_to_field(value),
            u64_to_field(forced as u64),
            sighash,
        ],
    )?;

    // Record the spend: creating the PDA is what makes a second burn fail.
    let bump = [bump];
    let seeds = [
        Seed::from(NULLIFIER_SEED),
        Seed::from(pool.address().as_ref()),
        Seed::from(nullifier.as_slice()),
        Seed::from(&bump),
    ];
    CreateAccount::with_minimum_balance(
        payer,
        nullifier_account,
        NULLIFIER_ACCOUNT_LEN as u64,
        program_id,
        None,
    )?
    .invoke_signed(&[Signer::from(&seeds)])?;
    nullifier_account.try_borrow_mut()?[0] = NULLIFIER_DISCRIMINATOR;

    let mut data = pool.try_borrow_mut()?;
    let mut p = Pool::from_bytes(&mut data)?;
    p.sub_supply(value)
}
