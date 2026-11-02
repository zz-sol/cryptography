//! The pool account: layout, a zero-copy view, and the incremental Merkle
//! tree it carries.
//!
//! ```text
//! [0    ..    1]  discriminator (1 = pool)
//! [1    ..    8]  reserved
//! [8    ..   40]  custodian        signs forced burns (forfeiture)
//! [40   ..   72]  issuer           signs mints
//! [72   ..  104]  mint_key         verifier key account of C_mint
//! [104  ..  136]  burn_key         verifier key account of C_burn
//! [136  ..  144]  supply           u64 LE, minted minus burned
//! [144  ..  152]  next_index       u64 LE, leaves appended so far
//! [152  ..  160]  root_pos         u64 LE, next root-history slot
//! [160  .. 1184]  filled[32]       rightmost filled node per height
//! [1184 .. 2208]  zeros[32]        empty subtree per height (zeros[0] = 0)
//! [2208 .. 4256]  roots[64]        ring of recent roots, BE field elements
//! ```
//!
//! Field elements are 32-byte big-endian, as the verifier takes public inputs
//! and the Poseidon syscall takes inputs with `Endianness::BigEndian`. Every
//! Poseidon call is domain-separated by a tag as its first input ([`domain`]).
//!
//! The tree is the standard append-only construction: `filled[h]` is the
//! left sibling an append at height `h` would need when the new node is a
//! right child, and `zeros[h]` the right sibling when it is a left child.
//! Leaf index bit `h` picks the side at height `h`, exactly as
//! `circuits/merkle` defines the path, so the roots agree with the gadget.

use {
    crate::error::PoolError,
    pinocchio::{error::ProgramError, Address},
    solana_poseidon::{hashv, Endianness, Parameters},
};

pub const DEPTH: usize = 32;
pub const ROOT_HISTORY: usize = 64;
pub const FIELD_SIZE: usize = 32;

pub const POOL_DISCRIMINATOR: u8 = 1;
pub const NULLIFIER_DISCRIMINATOR: u8 = 2;

pub const DISCRIMINATOR_OFFSET: usize = 0;
pub const CUSTODIAN_OFFSET: usize = 8;
pub const ISSUER_OFFSET: usize = CUSTODIAN_OFFSET + 32;
pub const MINT_KEY_OFFSET: usize = ISSUER_OFFSET + 32;
pub const BURN_KEY_OFFSET: usize = MINT_KEY_OFFSET + 32;
pub const SUPPLY_OFFSET: usize = BURN_KEY_OFFSET + 32;
pub const NEXT_INDEX_OFFSET: usize = SUPPLY_OFFSET + 8;
pub const ROOT_POS_OFFSET: usize = NEXT_INDEX_OFFSET + 8;
pub const FILLED_OFFSET: usize = ROOT_POS_OFFSET + 8;
pub const ZEROS_OFFSET: usize = FILLED_OFFSET + DEPTH * FIELD_SIZE;
pub const ROOTS_OFFSET: usize = ZEROS_OFFSET + DEPTH * FIELD_SIZE;
pub const POOL_ACCOUNT_LEN: usize = ROOTS_OFFSET + ROOT_HISTORY * FIELD_SIZE;

/// A nullifier account holds its discriminator and nothing else.
pub const NULLIFIER_ACCOUNT_LEN: usize = 1;
/// PDA seeds: `[NULLIFIER_SEED, pool address, nullifier]`.
pub const NULLIFIER_SEED: &[u8] = b"nullifier";

/// Mutable view over a pool account's data.
pub struct Pool<'a> {
    data: &'a mut [u8],
}

impl<'a> Pool<'a> {
    /// Wraps initialized pool data, checking length and discriminator.
    pub fn from_bytes(data: &'a mut [u8]) -> Result<Self, ProgramError> {
        if data.len() != POOL_ACCOUNT_LEN || data[DISCRIMINATOR_OFFSET] != POOL_DISCRIMINATOR {
            return Err(PoolError::InvalidPoolAccount.into());
        }
        Ok(Self { data })
    }

    /// Initializes zeroed pool data: authorities, keys, the empty tree and
    /// its root as the first history entry. Costs `DEPTH` Poseidon calls.
    pub fn initialize(
        data: &'a mut [u8],
        custodian: &Address,
        issuer: &Address,
        mint_key: &Address,
        burn_key: &Address,
    ) -> Result<Self, ProgramError> {
        if data.len() != POOL_ACCOUNT_LEN {
            return Err(PoolError::InvalidPoolAccount.into());
        }
        if data[DISCRIMINATOR_OFFSET] != 0 {
            return Err(PoolError::AlreadyInitialized.into());
        }
        data[DISCRIMINATOR_OFFSET] = POOL_DISCRIMINATOR;
        data[CUSTODIAN_OFFSET..CUSTODIAN_OFFSET + 32].copy_from_slice(custodian.as_ref());
        data[ISSUER_OFFSET..ISSUER_OFFSET + 32].copy_from_slice(issuer.as_ref());
        data[MINT_KEY_OFFSET..MINT_KEY_OFFSET + 32].copy_from_slice(mint_key.as_ref());
        data[BURN_KEY_OFFSET..BURN_KEY_OFFSET + 32].copy_from_slice(burn_key.as_ref());

        let mut pool = Self { data };
        // zeros[0] is the empty leaf, 0, already there. Each height hashes the
        // one below with itself; the last one is the empty tree's root.
        let mut z = [0u8; FIELD_SIZE];
        for h in 1..DEPTH {
            z = hash2(&z, &z)?;
            pool.field_mut(ZEROS_OFFSET, h).copy_from_slice(&z);
        }
        let empty_root = hash2(&z, &z)?;
        pool.push_root(&empty_root);
        Ok(pool)
    }

    pub fn custodian(&self) -> &[u8; 32] {
        self.addr(CUSTODIAN_OFFSET)
    }
    pub fn issuer(&self) -> &[u8; 32] {
        self.addr(ISSUER_OFFSET)
    }
    pub fn mint_key(&self) -> &[u8; 32] {
        self.addr(MINT_KEY_OFFSET)
    }
    pub fn burn_key(&self) -> &[u8; 32] {
        self.addr(BURN_KEY_OFFSET)
    }
    pub fn supply(&self) -> u64 {
        self.u64_at(SUPPLY_OFFSET)
    }
    pub fn next_index(&self) -> u64 {
        self.u64_at(NEXT_INDEX_OFFSET)
    }
    pub fn root_pos(&self) -> u64 {
        self.u64_at(ROOT_POS_OFFSET)
    }

    /// The most recently pushed root.
    pub fn current_root(&self) -> &[u8; 32] {
        let last = (self.root_pos() as usize + ROOT_HISTORY - 1) % ROOT_HISTORY;
        self.field(ROOTS_OFFSET, last)
    }

    /// Whether `root` is one of the last `ROOT_HISTORY` roots.
    pub fn knows_root(&self, root: &[u8; 32]) -> bool {
        // Unused slots are zero, and zero is not a root of this tree (the
        // empty root is a Poseidon output), so one comparison serves.
        if root.iter().all(|b| *b == 0) {
            return false;
        }
        (0..ROOT_HISTORY).any(|i| self.field(ROOTS_OFFSET, i) == root)
    }

    pub fn add_supply(&mut self, value: u64) -> Result<(), ProgramError> {
        let s = self
            .supply()
            .checked_add(value)
            .ok_or(PoolError::SupplyOutOfRange)?;
        self.set_u64(SUPPLY_OFFSET, s);
        Ok(())
    }

    pub fn sub_supply(&mut self, value: u64) -> Result<(), ProgramError> {
        let s = self
            .supply()
            .checked_sub(value)
            .ok_or(PoolError::SupplyOutOfRange)?;
        self.set_u64(SUPPLY_OFFSET, s);
        Ok(())
    }

    /// Appends a leaf, pushes the new root, and returns its leaf index.
    /// Costs `DEPTH` Poseidon calls.
    pub fn append(&mut self, leaf: &[u8; 32]) -> Result<u64, ProgramError> {
        let index = self.next_index();
        if index >= 1u64 << DEPTH {
            return Err(PoolError::TreeFull.into());
        }
        let mut cur = *leaf;
        let mut i = index;
        for h in 0..DEPTH {
            if i & 1 == 0 {
                self.field_mut(FILLED_OFFSET, h).copy_from_slice(&cur);
                let zero = *self.field(ZEROS_OFFSET, h);
                cur = hash2(&cur, &zero)?;
            } else {
                let left = *self.field(FILLED_OFFSET, h);
                cur = hash2(&left, &cur)?;
            }
            i >>= 1;
        }
        self.push_root(&cur);
        self.set_u64(NEXT_INDEX_OFFSET, index + 1);
        Ok(index)
    }

    fn push_root(&mut self, root: &[u8; 32]) {
        let pos = self.root_pos() as usize % ROOT_HISTORY;
        self.field_mut(ROOTS_OFFSET, pos).copy_from_slice(root);
        self.set_u64(ROOT_POS_OFFSET, ((pos + 1) % ROOT_HISTORY) as u64);
    }

    fn addr(&self, offset: usize) -> &[u8; 32] {
        self.data[offset..offset + 32].try_into().unwrap()
    }

    fn field(&self, base: usize, i: usize) -> &[u8; 32] {
        let o = base + i * FIELD_SIZE;
        self.data[o..o + FIELD_SIZE].try_into().unwrap()
    }

    fn field_mut(&mut self, base: usize, i: usize) -> &mut [u8; 32] {
        let o = base + i * FIELD_SIZE;
        (&mut self.data[o..o + FIELD_SIZE]).try_into().unwrap()
    }

    fn u64_at(&self, offset: usize) -> u64 {
        u64::from_le_bytes(self.data[offset..offset + 8].try_into().unwrap())
    }

    fn set_u64(&mut self, offset: usize, v: u64) {
        self.data[offset..offset + 8].copy_from_slice(&v.to_le_bytes());
    }
}

/// Poseidon domain tags (`circuits/domain`): a short ASCII name as a
/// big-endian field element, the first input of every hash. Only the two
/// hashes this program computes are needed here.
pub mod domain {
    /// Commitment tree node: `Poseidon(NODE, left, right)`.
    pub const NODE: [u8; 32] = tag(b"privtx/node");
    /// Burn sighash: `Poseidon(SIGHASH, pool halves, destination halves, nullifier, value)`.
    pub const SIGHASH: [u8; 32] = tag(b"privtx/sighash");

    /// The name right-aligned in 32 bytes: its big-endian integer.
    pub const fn tag<const N: usize>(name: &[u8; N]) -> [u8; 32] {
        assert!(N < 32);
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < N {
            out[32 - N + i] = name[i];
            i += 1;
        }
        out
    }
}

/// `Poseidon(NODE, left, right)` with the circom parameters, big-endian in
/// and out: the commitment tree's node hash (`circuits/merkle`).
pub fn hash2(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    hashv(
        Parameters::Bn254X5,
        Endianness::BigEndian,
        &[&domain::NODE, left, right],
    )
    .map(|h| h.to_bytes())
    .map_err(|_| PoolError::PoseidonFailed.into())
}

/// A `u64` as the 32-byte big-endian field element the circuits publish.
pub fn u64_to_field(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

/// A 32-byte address as two field elements, its 128-bit big-endian halves:
/// addresses do not fit one BN254 scalar.
pub fn address_halves(a: &[u8; 32]) -> [[u8; 32]; 2] {
    let mut hi = [0u8; 32];
    let mut lo = [0u8; 32];
    hi[16..].copy_from_slice(&a[..16]);
    lo[16..].copy_from_slice(&a[16..]);
    [hi, lo]
}

/// The burn sighash the owner signs and `C_burn` takes as its last public
/// input (`circuits/burn.SigHash`):
///
/// ```text
/// Poseidon(SIGHASH, pool[0:16], pool[16:32], destination[0:16], destination[16:32], nullifier, value)
/// ```
pub fn burn_sighash(
    pool: &[u8; 32],
    destination: &[u8; 32],
    nullifier: &[u8; 32],
    value: u64,
) -> Result<[u8; 32], ProgramError> {
    let [p0, p1] = address_halves(pool);
    let [d0, d1] = address_halves(destination);
    let v = u64_to_field(value);
    hashv(
        Parameters::Bn254X5,
        Endianness::BigEndian,
        &[&domain::SIGHASH, &p0, &p1, &d0, &d1, nullifier, &v],
    )
    .map(|h| h.to_bytes())
    .map_err(|_| PoolError::PoseidonFailed.into())
}
