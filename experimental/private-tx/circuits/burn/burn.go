// Package burn is C_burn: removal of one note from the pool with a public
// amount, either by its owner (unshield) or by the custodian (forfeiture).
//
// Both are the same relation: the note is in the commitment tree, its
// nullifier is published so it cannot be spent again, and its amount is
// published so the pool program can release the backing (vault withdrawal,
// supply decrease). They differ only in who authorizes:
//
//   - forced = 0, unshield: the witness carries the owner's spend
//     authorization, an EdDSA signature by the key behind the note's owner_pk
//     over sighash, and the circuit verifies it. This is Zcash's spend
//     authorization signature with the verification moved into the proof:
//     Solana has no syscall for the embedded curve, so checking it on-chain
//     would cost far more than the proof itself, while in-circuit it costs a
//     few thousand constraints and, as a bonus, never reveals the owner's key
//     or a re-randomization of it. The prover needs ak and the signature, not
//     the spending key, so proving and signing can live on different
//     machines, as in Zcash.
//   - forced = 1, forfeiture: no signature check. The custodian, who learns
//     the opening (including ak) from the audit ciphertext, removes the note
//     without the owner's key. The program must require the custodian's
//     signature when this flag is set; the circuit only tells it which case
//     it is in.
//
// sighash is the message the owner signs, Zcash's SIGHASH for this one
// spend: it binds the transaction's destination and pool to the proof, so a
// proof fished out of the mempool cannot be replayed with another recipient.
// The program recomputes it from the instruction and passes it as a public
// input (see SigHash).
//
// Public inputs, in order:
//
//	0  root        a commitment tree root the program accepts
//	1  nullifier   Poseidon(owner_pk, rho), see package note
//	2  value       the note amount
//	3  forced      0 or 1
//	4  sighash     Poseidon(pool, destination, nullifier, value), see SigHash
//
// Private witness: ak (owner_pk preimage), rho, r, the signature (R, S;
// ignored when forced), leaf index, Merkle siblings.
//
// The value needs no range check here: it is bound to a leaf of the tree,
// and every leaf was range-checked by the circuit that created it.
package burn

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/merkle"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/note"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/poseidon"
)

// Circuit is the burn relation. Field order fixes the public input order.
type Circuit struct {
	Root      frontend.Variable `gnark:",public"`
	Nullifier frontend.Variable `gnark:",public"`
	Value     frontend.Variable `gnark:",public"`
	Forced    frontend.Variable `gnark:",public"`
	SigHash   frontend.Variable `gnark:",public"`

	Owner     eddsa.PublicKey
	Rho       frontend.Variable
	R         frontend.Variable
	Signature eddsa.Signature
	Path      merkle.PathVars
}

// Define constrains forced ∈ {0, 1}, owner_pk = Poseidon(ak),
// forced ∨ EdDSA.Verify(ak, sighash, signature),
// root = MerkleRoot(Poseidon(value, owner_pk, rho, r), path) and
// nullifier = Poseidon(owner_pk, rho).
func (c *Circuit) Define(api frontend.API) error {
	api.AssertIsBoolean(c.Forced)
	ownerPK, err := note.OwnerPKGadget(api, c.Owner)
	if err != nil {
		return err
	}

	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	ok, err := eddsa.IsValid(curve, c.Signature, c.SigHash, c.Owner, &h)
	if err != nil {
		return err
	}
	// (1 - forced) · (1 - ok) = 0: a valid signature unless forced.
	api.AssertIsEqual(api.Mul(api.Sub(1, c.Forced), api.Sub(1, ok)), 0)

	cm, err := note.CommitmentGadget(api, c.Value, ownerPK, c.Rho, c.R)
	if err != nil {
		return err
	}
	root, err := merkle.RootGadget(api, cm, c.Path)
	if err != nil {
		return err
	}
	api.AssertIsEqual(root, c.Root)

	nf, err := note.NullifierGadget(api, ownerPK, c.Rho)
	if err != nil {
		return err
	}
	api.AssertIsEqual(nf, c.Nullifier)
	return nil
}

// SigHash is the message a burn's owner signs and the program recomputes:
//
//	Poseidon(pool[0:16], pool[16:32], destination[0:16], destination[16:32], nullifier, value)
//
// Solana addresses are 256 bits and do not fit one field element, so each is
// split into two 128-bit big-endian halves. The nullifier identifies the
// note; the value is what the destination receives. Root and forced are
// already public inputs of the same proof, so the hash need not repeat them.
func SigHash(pool, destination [32]byte, nullifier fr.Element, value uint64) fr.Element {
	var v fr.Element
	v.SetUint64(value)
	return poseidon.MustHash(half(pool, 0), half(pool, 16), half(destination, 0), half(destination, 16), nullifier, v)
}

func half(b [32]byte, from int) fr.Element {
	var e fr.Element
	e.SetBytes(b[from : from+16])
	return e
}

// Unshield builds the owner's witness for burning n, which sits in the tree
// at path, to destination, with spending key k.
func Unshield(n *note.Note, path *merkle.Path, k note.SpendingKey, pool, destination [32]byte) (*Circuit, error) {
	c := assignment(n, path, pool, destination)
	sig, err := k.Sign(c.SigHash.(fr.Element))
	if err != nil {
		return nil, err
	}
	c.Forced = 0
	c.Signature = sig.Vars()
	return c, nil
}

// Forfeit builds the custodian's witness for burning n without the owner's
// key.
func Forfeit(n *note.Note, path *merkle.Path, pool, destination [32]byte) *Circuit {
	c := assignment(n, path, pool, destination)
	c.Forced = 1
	d := note.Dummy()
	c.Signature = d.Vars()
	return c
}

func assignment(n *note.Note, path *merkle.Path, pool, destination [32]byte) *Circuit {
	return &Circuit{
		Root:      path.Root(n.Commitment()),
		Nullifier: n.Nullifier(),
		Value:     n.Value,
		SigHash:   SigHash(pool, destination, n.Nullifier(), n.Value),
		Owner:     note.OwnerVars(&n.Owner),
		Rho:       n.Rho,
		R:         n.R,
		Path:      path.Vars(),
	}
}

// Compile builds the R1CS over BN254.
func Compile() (constraint.ConstraintSystem, error) {
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
}
