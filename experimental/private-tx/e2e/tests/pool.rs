//! The pool program end to end, under Mollusk with both SBF artifacts: a
//! pool is created with the fixture's `C_mint` and `C_burn` keys, every note
//! of the pool fixture is minted through a verified proof, the on-chain root
//! then equals the fixture's root and a light-poseidon tree over the same
//! leaves, and the two burns (owner unshield, custodian forfeiture) go
//! through with every misuse rejected: replayed nullifier, unknown root,
//! forfeiture without the custodian, swapped destination (the mempool
//! replay the sighash exists for), tampered public inputs.
//!
//! Skips unless both `solana_groth16_program.so` (`SBF_OUT_DIR`) and
//! `private_tx_pool.so` (`POOL_SBF_OUT_DIR`, default
//! `../program/target/deploy`) exist.

mod sbf;

use {
    mollusk_svm::{
        program::{create_program_account_loader_v3, keyed_account_for_system_program},
        result::{InstructionResult, ProgramResult},
    },
    private_tx_e2e::{burn_sighash, bytes_from_hex, PoolBurn, PoolFixture},
    private_tx_pool::{
        error::PoolError,
        instruction as pool_ix,
        state::{
            Pool, NULLIFIER_ACCOUNT_LEN, NULLIFIER_DISCRIMINATOR, POOL_ACCOUNT_LEN, ROOTS_OFFSET,
        },
    },
    solana_account::Account,
    solana_address::Address,
    solana_groth16_verify::constants::{PROOF_SIZE, SYSTEM_PROGRAM_ID},
    solana_instruction::Instruction,
    solana_program_error::ProgramError,
};

const FIXTURE: &str = "pool";

/// Account state carried from one instruction to the next.
struct World {
    h: sbf::Harness,
    accounts: Vec<(Address, Account)>,
}

impl World {
    fn get(&self, a: &Address) -> &Account {
        &self
            .accounts
            .iter()
            .find(|(k, _)| k == a)
            .expect("account")
            .1
    }

    /// Runs one instruction against the current state and, on success,
    /// adopts the resulting accounts. Accounts not seen before start empty,
    /// except the verifier program, which gets an executable program account.
    fn run(&mut self, ix: &Instruction) -> InstructionResult {
        for m in &ix.accounts {
            if self.accounts.iter().any(|(k, _)| *k == m.pubkey) {
                continue;
            }
            let account = if m.pubkey == private_tx_pool::VERIFIER_ID {
                create_program_account_loader_v3(&m.pubkey)
            } else {
                Account::default()
            };
            self.accounts.push((m.pubkey, account));
        }
        let r = self.h.mollusk.process_instruction(ix, &self.accounts);
        if r.program_result.is_ok() {
            self.accounts = r.resulting_accounts.clone();
        }
        r
    }
}

fn funded() -> Account {
    Account {
        lamports: 10_000_000_000,
        data: vec![],
        owner: SYSTEM_PROGRAM_ID,
        executable: false,
        rent_epoch: 0,
    }
}

fn proof_bytes(p: &[u8]) -> &[u8; PROOF_SIZE] {
    p.try_into().unwrap()
}

fn assert_pool_error(r: &InstructionResult, e: PoolError) {
    sbf::assert_custom_error(r, e as u32);
}

fn assert_missing_signature(r: &InstructionResult) {
    assert_eq!(
        r.program_result,
        ProgramResult::Failure(ProgramError::MissingRequiredSignature)
    );
}

/// Reads the pool account through the program's own view.
fn with_pool<T>(w: &World, pool: &Address, f: impl FnOnce(&Pool) -> T) -> T {
    let mut data = w.get(pool).data.clone();
    f(&Pool::from_bytes(&mut data).expect("pool account"))
}

struct Setup {
    w: World,
    f: PoolFixture,
    pool: Address,
    payer: Address,
    issuer: Address,
    custodian: Address,
    mint_key: Address,
    burn_key: Address,
}

/// Registers both keys, creates and initializes a pool.
fn setup() -> Option<Setup> {
    let h = sbf::Harness::with_pool()?;
    let f = PoolFixture::load(FIXTURE);
    let mint_key = h.register(&f.mint_proof(FIXTURE, 0).key);
    let burn_key = h.register(&f.burn_proof(FIXTURE, &f.burns[0]).key);

    let payer = Address::new_unique();
    let issuer = Address::new_unique();
    let custodian = Address::new_unique();
    // The fixture's burns were signed for this pool address.
    let pool = Address::new_from_array(bytes_from_hex(&f.pool));
    let mut w = World {
        accounts: vec![
            (payer, funded()),
            (issuer, funded()),
            (custodian, funded()),
            (pool, Account::default()),
            mint_key.clone(),
            burn_key.clone(),
            keyed_account_for_system_program(),
        ],
        h,
    };

    let lamports = w.h.rent_exempt(POOL_ACCOUNT_LEN);
    let [create, init] = pool_ix::create_pool(
        &payer,
        &pool,
        lamports,
        &custodian,
        &issuer,
        &mint_key.0,
        &burn_key.0,
    );
    sbf::assert_success(&w.run(&create));
    let r = w.run(&init);
    sbf::assert_success(&r);
    println!("InitializePool: {} CUs", r.compute_units_consumed);

    // A second initialization of the same account is refused.
    assert_pool_error(&w.run(&init), PoolError::AlreadyInitialized);

    Some(Setup {
        w,
        f,
        pool,
        payer,
        issuer,
        custodian,
        mint_key: mint_key.0,
        burn_key: burn_key.0,
    })
}

fn mint_ix(s: &Setup, i: usize) -> Instruction {
    let g = s.f.mint_proof(FIXTURE, i);
    let note = &s.f.notes[i];
    assert_eq!(g.public_inputs[0], note.commitment_bytes());
    pool_ix::mint(
        &s.pool,
        &s.issuer,
        &s.mint_key,
        proof_bytes(&g.proof.0),
        &note.commitment_bytes(),
        note.value,
    )
}

/// Mints every note of the fixture, checking the tree and supply as it goes.
fn mint_all(s: &mut Setup) {
    let empty_root = with_pool(&s.w, &s.pool, |p| *p.current_root());
    assert_eq!(
        empty_root,
        private_tx_e2e::merkle_root(&[], s.f.depth),
        "empty root on-chain disagrees with light-poseidon"
    );

    let mut expected_supply = 0u64;
    for i in 0..s.f.notes.len() {
        let ix = mint_ix(s, i);
        let r = s.w.run(&ix);
        sbf::assert_success(&r);
        println!("Mint #{i}: {} CUs", r.compute_units_consumed);
        expected_supply += s.f.notes[i].value;
        with_pool(&s.w, &s.pool, |p| {
            assert_eq!(p.next_index(), i as u64 + 1);
            assert_eq!(p.supply(), expected_supply);
        });
    }
    let root = with_pool(&s.w, &s.pool, |p| *p.current_root());
    assert_eq!(root, bytes_from_hex(&s.f.root), "pool.json root");
    assert_eq!(
        root,
        s.f.poseidon_root(),
        "on-chain tree disagrees with a light-poseidon tree over the leaves"
    );
    with_pool(&s.w, &s.pool, |p| assert!(p.knows_root(&root)));
}

fn burn_ix(s: &Setup, b: &PoolBurn, custodian_signs: bool) -> Instruction {
    let g = s.f.burn_proof(FIXTURE, b);
    let note = &s.f.notes[b.index as usize];
    let nullifier = bytes_from_hex(&b.nullifier);
    let destination = Address::new_from_array(bytes_from_hex(&b.destination));
    assert_eq!(g.public_inputs[0], bytes_from_hex(&s.f.root));
    assert_eq!(g.public_inputs[1], nullifier);
    assert_eq!(
        nullifier,
        private_tx_e2e::nullifier(&bytes_from_hex(&b.nk), &note.commitment_bytes(), b.index),
        "fixture nullifier is not Poseidon(nk, cm, index)"
    );
    assert_eq!(
        g.public_inputs[4],
        burn_sighash(
            s.pool.as_array(),
            destination.as_array(),
            &nullifier,
            note.value
        ),
        "fixture sighash is not Poseidon(pool, destination, nullifier, value)"
    );
    let mut ix = pool_ix::burn(
        &s.pool,
        &s.payer,
        &s.custodian,
        &s.burn_key,
        proof_bytes(&g.proof.0),
        &bytes_from_hex(&s.f.root),
        &nullifier,
        note.value,
        b.forced,
        &destination,
    );
    ix.accounts[6].is_signer = custodian_signs;
    ix
}

fn find_burn(s: &Setup, forced: bool) -> PoolBurn {
    s.f.burns
        .iter()
        .find(|b| b.forced == forced)
        .expect("burn in fixture")
        .clone()
}

#[test]
fn mint_builds_the_fixture_tree() {
    let Some(mut s) = setup() else { return };
    mint_all(&mut s);
}

#[test]
fn mint_rejects_wrong_issuer_key_and_tampered_inputs() {
    let Some(mut s) = setup() else { return };

    // Not the issuer.
    let mut ix = mint_ix(&s, 0);
    ix.accounts[1].pubkey = s.custodian;
    assert_missing_signature(&s.w.run(&ix));

    // The burn key is not the mint key.
    let mut ix = mint_ix(&s, 0);
    ix.accounts[3].pubkey = s.burn_key;
    assert_pool_error(&s.w.run(&ix), PoolError::WrongVerifyingKey);

    // Another value than the proof opens to: the verifier's rejection
    // propagates through the CPI.
    let mut ix = mint_ix(&s, 0);
    let n = ix.data.len();
    ix.data[n - 8] ^= 1;
    sbf::assert_custom_error(&s.w.run(&ix), sbf::code::PROOF_INVALID);

    // Nothing was appended.
    with_pool(&s.w, &s.pool, |p| {
        assert_eq!(p.next_index(), 0);
        assert_eq!(p.supply(), 0);
    });
}

#[test]
fn burn_unshield_and_forfeit() {
    let Some(mut s) = setup() else { return };
    mint_all(&mut s);
    let total: u64 = s.f.notes.iter().map(|n| n.value).sum();
    let unshield = find_burn(&s, false);
    let forfeit = find_burn(&s, true);

    // Owner unshield: anyone may submit it, no custodian signature.
    let ix = burn_ix(&s, &unshield, false);
    let r = s.w.run(&ix);
    sbf::assert_success(&r);
    println!("Burn (unshield): {} CUs", r.compute_units_consumed);
    let nf_account =
        pool_ix::find_nullifier_address(&s.pool, &bytes_from_hex(&unshield.nullifier)).0;
    let nf = s.w.get(&nf_account);
    assert_eq!(nf.owner, private_tx_pool::ID);
    assert_eq!(
        nf.data,
        vec![NULLIFIER_DISCRIMINATOR; NULLIFIER_ACCOUNT_LEN]
    );
    let after_unshield = total - s.f.notes[unshield.index as usize].value;
    with_pool(&s.w, &s.pool, |p| assert_eq!(p.supply(), after_unshield));

    // Replaying the same burn: the nullifier account exists.
    assert_pool_error(&s.w.run(&ix), PoolError::NullifierAlreadySpent);

    // Forfeiture needs the custodian's signature...
    let ix = burn_ix(&s, &forfeit, false);
    assert_missing_signature(&s.w.run(&ix));
    // ...from the custodian, not just anyone.
    let mut ix = burn_ix(&s, &forfeit, true);
    ix.accounts[6].pubkey = s.issuer;
    assert_missing_signature(&s.w.run(&ix));
    // With it, the custodian removes the note without the owner's key.
    let ix = burn_ix(&s, &forfeit, true);
    let r = s.w.run(&ix);
    sbf::assert_success(&r);
    println!("Burn (forfeit): {} CUs", r.compute_units_consumed);
    let after_forfeit = after_unshield - s.f.notes[forfeit.index as usize].value;
    with_pool(&s.w, &s.pool, |p| assert_eq!(p.supply(), after_forfeit));
}

#[test]
fn burn_rejects_unknown_root_and_tampered_inputs() {
    let Some(mut s) = setup() else { return };
    mint_all(&mut s);
    let unshield = find_burn(&s, false);
    let root_off = 1 + PROOF_SIZE;

    // A root the pool never had.
    let mut ix = burn_ix(&s, &unshield, false);
    ix.data[root_off + 31] ^= 1;
    assert_pool_error(&s.w.run(&ix), PoolError::UnknownRoot);

    // The zero word is never a root, even though unused history slots are zero.
    let mut ix = burn_ix(&s, &unshield, false);
    ix.data[root_off..root_off + 32].fill(0);
    assert_pool_error(&s.w.run(&ix), PoolError::UnknownRoot);

    // A root the pool did have (the empty tree's, first in the history), but
    // not the one the proof was made for.
    let mut ix = burn_ix(&s, &unshield, false);
    let old_root = s.w.get(&s.pool).data[ROOTS_OFFSET..ROOTS_OFFSET + 32].to_vec();
    assert_ne!(old_root, bytes_from_hex(&s.f.root));
    ix.data[root_off..root_off + 32].copy_from_slice(&old_root);
    sbf::assert_custom_error(&s.w.run(&ix), sbf::code::PROOF_INVALID);

    // Another nullifier, value or flag than the proof opens to.
    for (what, off) in [
        ("nullifier", root_off + 32 + 31),
        ("value", root_off + 64),
        ("forced", root_off + 72),
    ] {
        let mut ix = burn_ix(&s, &unshield, false);
        ix.data[off] ^= 1;
        if what == "nullifier" {
            // The PDA in the accounts has to match the data for the program to
            // get as far as the proof.
            let nf: [u8; 32] = ix.data[root_off + 32..root_off + 64].try_into().unwrap();
            ix.accounts[2].pubkey = pool_ix::find_nullifier_address(&s.pool, &nf).0;
        }
        if what == "forced" {
            // Flipping the flag makes it a forfeiture, so sign as custodian
            // to get as far as the proof.
            ix.accounts[6].is_signer = true;
        }
        let r = s.w.run(&ix);
        sbf::assert_custom_error(&r, sbf::code::PROOF_INVALID);
        assert!(r.program_result.is_err(), "wrong {what} accepted");
    }

    // The mempool replay: same proof, another destination. The program
    // recomputes the sighash from the new destination and the proof, made
    // over the owner's signature of the old one, no longer verifies.
    let mut ix = burn_ix(&s, &unshield, false);
    let dest_off = root_off + 73;
    ix.data[dest_off..dest_off + 32].copy_from_slice(Address::new_unique().as_array());
    sbf::assert_custom_error(&s.w.run(&ix), sbf::code::PROOF_INVALID);

    // The nullifier account must be the PDA for the published nullifier.
    let mut ix = burn_ix(&s, &unshield, false);
    ix.accounts[2].pubkey = Address::new_unique();
    assert_pool_error(&s.w.run(&ix), PoolError::NullifierAddressMismatch);

    // forced ∉ {0, 1}.
    let mut ix = burn_ix(&s, &unshield, false);
    ix.data[root_off + 72] = 2;
    assert_pool_error(&s.w.run(&ix), PoolError::InvalidForcedFlag);

    // Nothing changed.
    let total: u64 = s.f.notes.iter().map(|n| n.value).sum();
    with_pool(&s.w, &s.pool, |p| assert_eq!(p.supply(), total));
}
