//! Loads the circuit fixtures under `../fixtures/` and converts them to the
//! verifier program's on-chain format.
//!
//! Each fixture directory holds gnark's native encodings (`vk.bin`,
//! `proof.bin`, `public.bin`) written by `privtx`, plus any circuit-specific
//! witness file. The note commitment, nullifier and Merkle tree are
//! recomputed here with light-poseidon so every in-circuit hash is checked
//! against the Poseidon the Solana syscall implements.

use {
    ark_bn254::Fr,
    ark_ff::{BigInteger, PrimeField},
    groth16_convert::{arkworks, gnark, OnChainKey, OnChainProof},
    light_poseidon::{Poseidon, PoseidonHasher},
    std::path::PathBuf,
};

/// Path of `<fixture>/<name>`.
pub fn fixture_path(fixture: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../fixtures")
        .join(fixture)
        .join(name)
}

/// Reads `<fixture>/<name>`, panicking with the path on failure.
pub fn read_fixture(fixture: &str, name: &str) -> Vec<u8> {
    let path = fixture_path(fixture, name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// A proof and key in on-chain form, with public inputs as 32-byte big-endian
/// canonical scalars in circuit order.
pub struct Groth16Fixture {
    pub key: OnChainKey,
    pub proof: OnChainProof,
    pub public_inputs: Vec<[u8; 32]>,
}

/// Parses and converts `vk.bin`, `proof.bin`, `public.bin`.
pub fn load_groth16(fixture: &str) -> Groth16Fixture {
    load_groth16_files(fixture, "vk.bin", "proof.bin", "public.bin")
}

/// Parses and converts a key, proof and public witness by file name under
/// `<fixture>/`, for fixtures holding several proofs of one key.
pub fn load_groth16_files(fixture: &str, vk: &str, proof: &str, public: &str) -> Groth16Fixture {
    let key = gnark::parse_verifying_key(&read_fixture(fixture, vk)).expect(vk);
    let proof = gnark::parse_proof(&read_fixture(fixture, proof)).expect(proof);
    let inputs = gnark::parse_public_witness(&read_fixture(fixture, public)).expect(public);
    Groth16Fixture {
        key,
        proof,
        public_inputs: arkworks::public_inputs(&inputs),
    }
}

/// Circom-parameter Poseidon of 1..12 field elements, via light-poseidon: the
/// reference the Solana `sol_poseidon` syscall and `syscall/solana-bn254`
/// derive their constants from. Circuits that hash in-circuit are checked
/// against this.
pub fn poseidon(inputs: &[Fr]) -> [u8; 32] {
    let mut hasher = Poseidon::<Fr>::new_circom(inputs.len()).expect("supported width");
    fr_to_bytes(&hasher.hash(inputs).expect("hash"))
}

/// Decodes a 0x-prefixed big-endian 32-byte hex string.
pub fn bytes_from_hex(s: &str) -> [u8; 32] {
    let raw = hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("hex");
    raw.try_into().expect("32 bytes")
}

/// Decodes a canonical field element from 0x-prefixed big-endian hex.
pub fn fr_from_hex(s: &str) -> Fr {
    let bytes = bytes_from_hex(s);
    let e = Fr::from_be_bytes_mod_order(&bytes);
    assert_eq!(fr_to_bytes(&e), bytes, "non-canonical field element {s}");
    e
}

/// Big-endian canonical encoding, as the verifier expects public inputs.
pub fn fr_to_bytes(e: &Fr) -> [u8; 32] {
    e.into_bigint().to_bytes_be().try_into().unwrap()
}

/// `value` as a 32-byte big-endian scalar.
pub fn u64_to_bytes(value: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

/// The opened note behind the mint fixture (`note.json`), as written by
/// `privtx mint-fixture`: field elements are 0x-prefixed big-endian hex.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct NoteOpening {
    pub value: u64,
    pub owner_pk: String,
    pub rho: String,
    pub r: String,
    pub commitment: String,
}

impl NoteOpening {
    pub fn load(fixture: &str) -> Self {
        serde_json::from_slice(&read_fixture(fixture, "note.json")).expect("note.json")
    }

    /// `Poseidon(value, owner_pk, rho, r)` under the circom parameters.
    pub fn poseidon_commitment(&self) -> [u8; 32] {
        poseidon(&[
            Fr::from(self.value),
            fr_from_hex(&self.owner_pk),
            fr_from_hex(&self.rho),
            fr_from_hex(&self.r),
        ])
    }

    pub fn commitment_bytes(&self) -> [u8; 32] {
        bytes_from_hex(&self.commitment)
    }

    /// `Poseidon(owner_pk, rho)`, the note's nullifier.
    pub fn poseidon_nullifier(&self) -> [u8; 32] {
        poseidon(&[fr_from_hex(&self.owner_pk), fr_from_hex(&self.rho)])
    }
}

/// Root of the commitment tree holding `leaves` (in order) at `depth`: binary,
/// `Poseidon(left, right)` nodes, empty leaf 0 and empty subtrees hashed up
/// from it. Mirrors `circuits/merkle`.
pub fn merkle_root(leaves: &[Fr], depth: usize) -> [u8; 32] {
    let mut level: Vec<Fr> = leaves.to_vec();
    let mut empty = Fr::from(0u64);
    for _ in 0..depth {
        level = level
            .chunks(2)
            .map(|pair| {
                let right = pair.get(1).copied().unwrap_or(empty);
                hash2(pair[0], right)
            })
            .collect();
        empty = hash2(empty, empty);
    }
    fr_to_bytes(&level.first().copied().unwrap_or(empty))
}

fn hash2(a: Fr, b: Fr) -> Fr {
    let mut hasher = Poseidon::<Fr>::new_circom(2).expect("width 3");
    hasher.hash(&[a, b]).expect("hash")
}

/// The burn fixture's witness (`burn.json`), as written by
/// `privtx burn-fixture`: the tree's leaves in order, the burned note and its
/// index, the root and nullifier the circuit published, and whether it was a
/// forced burn (forfeiture) or the owner's unshield.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct BurnFixture {
    pub depth: usize,
    pub leaves: Vec<String>,
    pub index: u64,
    pub note: NoteOpening,
    pub root: String,
    pub nullifier: String,
    pub forced: bool,
}

impl BurnFixture {
    pub fn load(fixture: &str) -> Self {
        serde_json::from_slice(&read_fixture(fixture, "burn.json")).expect("burn.json")
    }

    /// The tree root recomputed from the leaves.
    pub fn poseidon_root(&self) -> [u8; 32] {
        let leaves: Vec<Fr> = self.leaves.iter().map(|l| fr_from_hex(l)).collect();
        merkle_root(&leaves, self.depth)
    }
}

/// The pool fixture (`pool.json`), as written by `privtx pool-fixture`: the
/// notes in leaf order, the root once all are minted, and the burns proved
/// against that root. Proofs live in `mint/` (one per note, sharing
/// `mint/vk.bin`) and `burn/` (one per burn, sharing `burn/vk.bin`).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PoolFixture {
    pub depth: usize,
    pub notes: Vec<NoteOpening>,
    pub root: String,
    pub burns: Vec<PoolBurn>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct PoolBurn {
    pub name: String,
    pub index: u64,
    pub nullifier: String,
    pub forced: bool,
}

impl PoolFixture {
    pub fn load(fixture: &str) -> Self {
        serde_json::from_slice(&read_fixture(fixture, "pool.json")).expect("pool.json")
    }

    /// The `C_mint` proof of note `i`.
    pub fn mint_proof(&self, fixture: &str, i: usize) -> Groth16Fixture {
        load_groth16_files(
            fixture,
            "mint/vk.bin",
            &format!("mint/proof-{i}.bin"),
            &format!("mint/public-{i}.bin"),
        )
    }

    /// The `C_burn` proof named by `burn.name`.
    pub fn burn_proof(&self, fixture: &str, burn: &PoolBurn) -> Groth16Fixture {
        load_groth16_files(
            fixture,
            "burn/vk.bin",
            &format!("burn/proof-{}.bin", burn.name),
            &format!("burn/public-{}.bin", burn.name),
        )
    }

    /// The tree root recomputed from the notes' commitments.
    pub fn poseidon_root(&self) -> [u8; 32] {
        let leaves: Vec<Fr> = self
            .notes
            .iter()
            .map(|n| fr_from_hex(&n.commitment))
            .collect();
        merkle_root(&leaves, self.depth)
    }
}
