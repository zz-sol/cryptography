# Private transactions

Per-institution shielded pools on Solana: Groth16 over BN254, Poseidon
commitments, gnark circuits, verified on-chain by the generic
[Groth16 verifier program](https://github.com/solana-program/groth16-verifier-program).
Tracker: [anza-xyz/cryptography#123](https://github.com/anza-xyz/cryptography/issues/123).

Status: milestone 1. The framework (Go module, Poseidon library choice,
fixture tooling, Rust end-to-end harness against the verifier program, CI) is
in place, `C_mint` and `C_burn` are implemented, and a first pool program
consumes their proofs: under Mollusk, a pool is created, notes are minted
into its on-chain commitment tree through verified proofs, and burned by
their owner or forfeited by the custodian, with the nullifier recorded.

## Layout

| Path | What |
| --- | --- |
| `circuits/` | Go module (gnark): circuits, gadgets, fixture CLI |
| `circuits/poseidon/` | thin adapter over third-party circom-compatible Poseidon (native and gadget) |
| `circuits/smoke/` | trivial `A·B = C` circuit that exercises the pipeline end to end |
| `circuits/note/` | note format, commitment and nullifier |
| `circuits/merkle/` | commitment tree: native tree and membership gadget |
| `circuits/mint/` | `C_mint` |
| `circuits/burn/` | `C_burn` (owner unshield and custodian forfeiture) |
| `circuits/export/` | writes gnark's native `vk.bin` / `proof.bin` / `public.bin` |
| `circuits/cmd/privtx/` | `privtx <circuit>-fixture`: setup, prove, export |
| `fixtures/<circuit>/` | a key, proof and public witness per circuit, consumed by `e2e/` |
| `fixtures/pool/` | a whole pool lifecycle: one `C_mint` proof per note and two `C_burn` proofs against the resulting tree |
| `program/` | Rust crate (own workspace): the pool program, Pinocchio SBF, with host-side instruction builders behind the `instruction` feature |
| `e2e/` | Rust crate (own workspace): fixture → on-chain format → verifier host path, verifier SBF program, and the pool program under Mollusk |

## Poseidon

All hashing is the circom Poseidon over BN254 Fr: `x^5` S-box, 8 full rounds,
width-dependent partial rounds, capacity element 0, digest `state[0]`. These
are the parameters of circomlib, light-poseidon, Solana's `sol_poseidon`
syscall and `syscall/solana-bn254` in this repository, so a pool program can
recompute any in-circuit hash with one syscall.

No Poseidon is implemented here. gnark's own `std/hash` ships MiMC and
Poseidon2 but not the original Poseidon with circomlib's parameters, which is
what the syscall computes, so the circuits use two public libraries instead:

- in-circuit: `github.com/vocdoni/gnark-crypto-primitives/hash/native/bn254/poseidon`,
  a gnark port of circomlib's `poseidon.circom`;
- native (witness side): `github.com/iden3/go-iden3-crypto/poseidon`, the
  reference implementation by circom's authors.

Both libraries absorb up to 16 inputs in one permutation; the adapter in
`circuits/poseidon/` caps hashes at the 12 inputs `sol_poseidon` supports, so
an on-chain program can always recompute them.

Compatibility is pinned by tests rather than assumed: the Go tests check both
against circomlib's published vectors and against each other on random inputs
for 1 to 5 inputs, and the Rust e2e crate exposes light-poseidon (the source
`syscall/solana-bn254` generates its constants from) for circuits to check
their in-circuit hashes against.

## Keys and notes

The key hierarchy is Sapling's with Poseidon for every hash and PRF, and
gnark-crypto's twisted Edwards curve over BN254 Fr as the embedded group
(Baby Jubjub in `a = -1` form: same prime-order subgroup, cofactor 8).

```
sk                                spending key, a field element
ask = KeyGen(Poseidon(ASK, sk))   spend authorizing key (EdDSA secret)
ak  = [ask]G                      spend authorizing public key
nk  = Poseidon(NK, sk)            nullifier key
fvk = (ak, nk)                    full viewing key
ivk = Poseidon(IVK, ak.x, ak.y, nk)    incoming viewing key, used as a scalar
g_d = GroupHash(d)                diversifier base, d an 11-byte diversifier
pk_d = [ivk]·g_d                  diversified transmission key
address = (d, pk_d)
```

- Spending needs `ask` (to sign) and `nk` (to derive the nullifier).
  Seeing a note, and forfeiting it through the custodian, needs `fvk` only.
  Institutions register their clients' `fvk`; that is what makes the
  custodian able to audit and forfeit (§C_burn).
- One key has as many addresses as diversifiers; without `ivk` two of them
  are unlinkable (`pk_d = [ivk]g_d` with independent bases).
- `GroupHash(d)`: `x = Poseidon(GD, d, counter)` for the first counter that
  gives a curve point, smaller `y`, cofactor cleared. The circuits never
  compute it; `g_d` is a witness checked to be on the curve and not of small
  order, so `pk_d = [ivk]g_d` binds `ivk` modulo the full subgroup order.

```
note = (value, d, pk_d, r)
cm   = Poseidon(CM, value, g_d.x, g_d.y, pk_d.x, pk_d.y, r)     // width 8
nf   = Poseidon(NF, nk, cm, leaf index)                         // width 5
```

- `value`: `u64`. No asset field: the pool fixes the asset.
- `r`: commitment randomness.
- The nullifier takes the note's position, as Sapling's does (`rho = cm +
  [position]J` there): two notes with the same opening are different leaves
  with different nullifiers, so a sender cannot hand out notes that collide
  ("Faerie Gold"). Only the holder of `nk` can derive a nullifier, so a
  note's creator cannot tell when it is spent.

Every Poseidon call is domain-separated: its first input is a constant tag,
the ASCII of a short name (`privtx/cm`, `privtx/nf`, `privtx/nk`,
`privtx/ask`, `privtx/ivk`, `privtx/gd`, `privtx/node`, `privtx/sighash`)
read as a big-endian integer. `circuits/domain/` lists them; the pool
program and the e2e crate spell the same strings.

## Commitment tree

```
leaf          = commitment
node          = Poseidon(NODE, left, right)     // width 4
empty leaf    = 0, empty subtrees hashed up from it
depth         = 32                              // provisional, spec decides
```

Leaves are appended left to right; bit `i` of the leaf index picks the right
child at height `i`. `circuits/merkle/` has the native tree (witness side)
and the membership gadget, with the native path and the gadget cross-checked
in its tests; the e2e crate rebuilds the fixture tree with light-poseidon to
pin the gadget against the Solana syscall's Poseidon. The pool program keeps
the same tree on-chain.

## C_mint

Issuance of one note with a public amount. The issuer proves the published
commitment opens to a well-formed note carrying exactly the published value,
so the pool program can account for minted supply (and match a vault deposit
for a wrapped asset) while the recipient stays hidden. Who may mint is the
pool program's business (issuer authority), not the circuit's.

| | |
| --- | --- |
| public inputs | `commitment`, `value` (in that order) |
| witness | `g_d`, `pk_d`, `r` |
| constraints | `value ∈ [0, 2^64)` by bit decomposition; `g_d` on the curve and not of small order, `pk_d` on the curve; `commitment = Poseidon(CM, value, g_d, pk_d, r)` |
| size | 468 R1CS constraints (pinned by `TestVerifyingKeyShape`) |

A confidential-issuance variant (hidden amount) is the same circuit with
`Value` moved to the private witness. The point checks are Sapling's
Output checks: without them a note could be created whose owner relation
`pk_d = [ivk]g_d` binds only a few bits of `ivk`.

The circuit touches neither Merkle tree. The commitment is a public input, so
the pool program appends it to the commitment tree itself after verifying the
proof; proving the insertion in-circuit would only repeat work the program
does in the clear. Membership in the tree is proved when a note is spent, by
`C_transfer` and `C_burn`. The nullifier set is untouched because a mint
spends nothing. The on-chain mint flow is therefore: verify the proof,
check issuer authority, add `value` to minted supply, append `commitment`.

## C_burn

Removal of one note from the pool with a public amount: the owner's unshield
and the custodian's forfeiture are the same relation, so they are one circuit
with a public flag saying which authorization applies. The prover shows the
note is in the commitment tree and publishes its nullifier and value; the
pool program records the nullifier, so the note cannot be spent again, and
releases the amount (vault withdrawal, supply decrease).

| | |
| --- | --- |
| public inputs | `root`, `nullifier`, `value`, `forced`, `sighash` (in that order) |
| witness | `ak`, `nk`, `g_d`, `pk_d`, `r`, signature `(R, S)`, leaf index, 32 Merkle siblings |
| constraints | `forced ∈ {0, 1}`; `ivk = Poseidon(IVK, ak, nk)`; `g_d` not of small order; `pk_d = [ivk]g_d`; `forced ∨ EdDSA.Verify(ak, sighash, (R, S))`; `cm = Poseidon(CM, value, g_d, pk_d, r)`; `root = MerkleRoot(cm, index, siblings)`; `nullifier = Poseidon(NF, nk, cm, index)` |
| size | 20919 R1CS constraints (pinned by `TestVerifyingKeyShape`) |

The owner relation `pk_d = [ivk]g_d` is checked in both modes. It is what
ties `nk`, and so the published nullifier, to this note: a forfeiture with a
made-up `nk` would publish a nullifier that leaves the real one unspent,
and the note could be spent again after its value had been released. The
scalar multiplication is gnark's complete double-and-add, not its faster
lattice path, whose range checks are commitment-based under Groth16.

Authorization follows Zcash. Spending is a **spend authorization signature**
by the owner's key over a **sighash** of the transaction, not knowledge of a
secret inside the proof. The sighash is

```
sighash = Poseidon(SIGHASH, pool[0:16], pool[16:32], destination[0:16], destination[16:32], nullifier, value)
```

(Solana addresses are 256 bits, so each is two 128-bit halves.) The pool
program recomputes it from the instruction it is executing and passes it as
the last public input, so a proof is good for exactly one pool and one
destination: a copy fished out of the mempool with the recipient swapped
fails verification. Root and `forced` are public inputs of the same proof,
so the hash need not repeat them.

One deviation from Zcash: the signature is verified **inside the circuit**,
not on-chain. Zcash publishes a re-randomized key `rk` and checks the
signature in the transaction; Solana has no syscall for Baby Jubjub, so that
check would cost on the order of a million compute units in software, more
than ten proof verifications. In-circuit it costs about 7,800 constraints
(gnark's `std/signature/eddsa` with its MiMC challenge hash, which never
needs to match anything on-chain), and nothing about the key, not even a
re-randomization, is ever published. What Zcash's split buys is kept: the
prover needs the full viewing key and the signature, never `ask`, so proving
and signing can run on different machines (an HSM signs, a prover box
proves).
What is lost is proving before the transaction is final, since the sighash is
a public input.

- `forced = 0`, unshield: the proof carries the owner's signature over this
  transaction, so the program accepts it from anyone.
- `forced = 1`, forfeiture: no signature check, the "alternative
  nullifier-authorization path" the design left open. The custodian holds
  the owner's registered full viewing key and learns the opening from the
  audit ciphertext, and removes the note without `ask`; the witness carries
  a well-formed dummy signature the circuit ignores. The program must
  require the custodian's signature whenever the flag is set; the circuit
  only tells it which case it is in.

No range check on `value`: it is bound to a leaf, and every leaf was
range-checked by the circuit that created it. The root is checked by the
program against its root history. `C_transfer`'s spend side is this relation
with `forced = 0` and the output notes in place of `destination`.

Two spec items this depends on: the audit ciphertext must carry the full
opening (`d`, `pk_d`, `r`), not only the value, and clients must register
their full viewing keys with the custodian, for forfeiture to work.

## Pool program

`program/` is one shielded pool over one SPL Token mint as a Solana
program, written with Pinocchio like the verifier. It holds no proof logic:
every `Mint` and `Burn` CPIs the Groth16 verifier program's `Verify` with
the circuit's content-addressed verifying-key account, whose address the
pool pins at initialization. The program decides which public inputs the
proof must open to and what to do with them: move tokens between the
depositor, the vault and the destination, append to the tree, record the
nullifier.

One pool account (4,352 bytes):

| field | what |
| --- | --- |
| `custodian`, `issuer` | signers of forced burns and of mints |
| `mint_key`, `burn_key` | the verifier key accounts of `C_mint` and `C_burn` |
| `token_program`, `token_mint`, `vault` | the asset and the token account holding its backing, owned by the vault authority PDA `["vault", pool]` |
| `supply` | minted minus burned; equals the vault balance |
| `next_index`, `filled[32]`, `zeros[32]` | the incremental Merkle tree (depth 32, `Poseidon(NODE, left, right)` via `sol_poseidon`), the same tree `circuits/merkle` defines |
| `roots[64]` | ring of recent roots a burn may prove against |

Nullifiers are one PDA each, `["nullifier", pool, nullifier]`, created by
`Burn`; a second burn of the same note fails because the account exists.

| instruction | accounts | data | effect |
| --- | --- | --- | --- |
| `InitializePool` | pool (s, w), vault, token program | custodian, issuer, mint_key, burn_key, token_mint | checks the vault is an initialized token account of the mint owned by the vault authority; fills the empty tree (32 Poseidon calls), pushes the empty root |
| `Mint` (shield) | pool (w), issuer (s), verifier, mint key, source token account (w), source owner (s), vault (w), token program | proof, commitment, value | verify `(commitment, value)`; transfer `value` source → vault (source owner's authority); append; `supply += value` |
| `Burn` (unshield / forfeit) | pool (w), payer (s, w), nullifier PDA (w), system, verifier, burn key, custodian (s iff forced), vault (w), destination token account (w), vault authority, token program | proof, root, nullifier, value, forced | root ∈ history; `sighash = Poseidon(SIGHASH, pool, destination, nullifier, value)` with the destination account's address; verify `(root, nullifier, value, forced, sighash)`; create the PDA; transfer `value` vault → destination (PDA authority); `supply -= value` |

The destination of a burn is a token account named in the instruction, and
the sighash the owner signed names it too, so the vault can only ever pay
the account the proof was made for. The issuer co-signs every shield: who
may bring assets into an institution's pool is the institution's business,
and the deposit itself is the depositor's own token transfer, so the issuer
cannot shield someone else's funds.

Compute units under Mollusk (SBF v2, local): `InitializePool` 39.3k; `Mint`
123k, of which 82.8k is the verifier CPI and the rest is mostly the 32
Poseidon syscalls of the append plus the token transfer; `Burn` 103k
(unshield or forfeit), five public inputs plus the sighash syscall and the
token transfer.

What it does not do yet: `Transfer` (waits for `C_transfer`); Token-2022
extensions are untested (the layout check and `Transfer` are the same, but
transfer fees or hooks would break the supply/vault equality); the program
id is a placeholder.

The e2e test `e2e/tests/pool.rs` replays `fixtures/pool/`: it registers both
keys, creates a pool, mints every note and checks the on-chain root against
the fixture's and against a light-poseidon tree over the same leaves, then
burns one note as its owner and forfeits another as the custodian, with
the vault and the destination token account's balances checked after every
step, and checks every rejection (replayed nullifier, unknown root,
forfeiture without the custodian, the same proof with another destination,
wrong vault or token program, a depositor who cannot cover the note,
tampered public inputs, wrong key, wrong PDA).

## Circuit rules

- Plain Groth16 only. No `std/rangecheck` or anything else built on
  `api.Commit`: under Groth16 those add commitment keys to the verifying key
  and a Pedersen commitment to the proof, which the on-chain verifier (and its
  `groth16-convert` parser) rejects. Range checks use `api.ToBinary`.
- Public inputs are in struct field order; document the order in the circuit
  package and assert it in the e2e test.
- Each circuit ships a fixture under `fixtures/<circuit>/` and an e2e test
  under `e2e/tests/` that verifies it on the host path and on the SBF program.

## Running

```bash
make lint           # gofmt + go vet; cargo fmt + clippy for e2e
make test-go        # Go: Poseidon vectors, gadget == native, Merkle tree, C_mint / C_burn prove/verify
make test-e2e       # Rust (release): host-path verification of the fixtures
make verifier-sbf   # clone + build the verifier program (needs cargo build-sbf 4.1+ for SBF v3; SBF_ARCH=v2 for older)
make pool-sbf       # build the pool program
make test-e2e       # now also verifies the proofs inside the SBF program and runs the pool lifecycle
make fixtures       # regenerate fixtures (random setup: bytes change)
```

The e2e and program crates are standalone Cargo workspaces: Mollusk brings
in the SVM runtime, which would otherwise bloat the root lockfile and every
build in the repository. Both pin the verifier repository to one git revision
(in their `Cargo.toml` and the `Makefile`); the fixture encodings are gnark's
native `WriteTo` / `MarshalBinary` forms, which that revision's
`groth16-convert` parses. The Groth16 setup in `privtx` is for development
only.

CI (`.github/workflows/private-tx.yml`, run only when this directory or the
workflow changes) lints and tests the Go side, builds the verifier and pool
programs, regenerates the fixtures, and runs the e2e crate with the SBF
tests enabled.

## Dependency pins

`vocdoni/gnark-crypto-primitives` v0.0.6 requires commits of gnark, gnark-crypto
and go-iden3-crypto that are newer than the releases it was built against, so
Go's minimum version selection carries those commits into `go.mod`. gnark and
gnark-crypto are raised to tagged releases that satisfy it; go-iden3-crypto has
no tag newer than the required commit, so it stays on that commit.

## Next

- `C_transfer`: spend side = `C_burn` with `forced = 0`; 2-in/2-out
  conservation, auditor ciphertexts (Baby Jubjub ElGamal gadget), and note
  encryption to the recipient, without which a transfer cannot be received.
- Outgoing viewing keys and note encryption to the recipient and the
  auditor (the key hierarchy above already gives `ivk` for the key
  agreement).
- Pool program: `Transfer` once `C_transfer` exists, a real program id,
  Token-2022 coverage.
- Client glue: Merkle path tracking from chain state, proving, transaction
  assembly (Epic 4).
