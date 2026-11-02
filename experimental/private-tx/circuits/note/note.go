// Package note defines the shielded-pool note, its Poseidon commitment, and
// the owner's key.
//
// A note is (value, owner_pk, rho, r). Its commitment is
//
//	cm = Poseidon(value, owner_pk, rho, r)
//
// with the circom-compatible Poseidon of package poseidon (width 5). Each pool
// holds a single asset, so a note carries no asset field.
//
//   - value:    the amount, an unsigned 64-bit integer.
//   - owner_pk: Poseidon(ak.x, ak.y), the hash of the owner's spend
//     authorizing key ak, a point of the twisted Edwards curve over BN254 Fr
//     (Baby Jubjub, in gnark-crypto's a = -1 form). Spending a note means
//     signing with the key behind ak, Zcash's spend authorization; the
//     signature is checked in-circuit against ak (see package burn), so
//     neither ak nor the signature is ever published.
//   - rho:      per-note uniqueness; the nullifier input.
//   - r:        commitment randomness, hides the other fields.
//
// Spending or forfeiting a note publishes its nullifier
//
//	nf = Poseidon(owner_pk, rho)
//
// Sapling's PRF_nk(rho) with the public key in place of the secret nullifier
// key: anyone holding the opening can derive it. That is what lets the
// custodian, who learns openings through the audit ciphertexts, forfeit a
// note without the owner's key (C_burn, forced); the price is that the note's
// creator can also recognize the nullifier when the note is spent. The
// derivation is provisional (key hierarchy, Epic 1) and lives only here, so
// every circuit that emits a nullifier changes together.
//
// Keys: SpendingKey is gnark-crypto's EdDSA private key on that curve; its
// public key is ak. The EdDSA challenge hash is MiMC (gnark's native pairing
// of signer and gadget), which need not match anything on-chain since the
// signature only ever meets the circuit.
package note

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	gadgeteddsa "github.com/consensys/gnark/std/signature/eddsa"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/poseidon"
)

// Note is an opened note. Owner is ak, the owner's spend authorizing key;
// the committed owner_pk is OwnerPK().
type Note struct {
	Value uint64
	Owner twistededwards.PointAffine
	Rho   fr.Element
	R     fr.Element
}

// OwnerPK returns Poseidon(ak.x, ak.y).
func (n *Note) OwnerPK() fr.Element {
	return OwnerPKOf(&n.Owner)
}

// Commitment returns Poseidon(value, owner_pk, rho, r).
func (n *Note) Commitment() fr.Element {
	var v fr.Element
	v.SetUint64(n.Value)
	return poseidon.MustHash(v, n.OwnerPK(), n.Rho, n.R)
}

// Nullifier returns Poseidon(owner_pk, rho).
func (n *Note) Nullifier() fr.Element {
	return poseidon.MustHash(n.OwnerPK(), n.Rho)
}

// OwnerPKOf returns Poseidon(ak.x, ak.y).
func OwnerPKOf(ak *twistededwards.PointAffine) fr.Element {
	return poseidon.MustHash(ak.X, ak.Y)
}

// CommitmentGadget constrains and returns Poseidon(value, owner_pk, rho, r).
func CommitmentGadget(api frontend.API, value, ownerPK, rho, r frontend.Variable) (frontend.Variable, error) {
	return poseidon.HashGadget(api, value, ownerPK, rho, r)
}

// NullifierGadget constrains and returns Poseidon(owner_pk, rho).
func NullifierGadget(api frontend.API, ownerPK, rho frontend.Variable) (frontend.Variable, error) {
	return poseidon.HashGadget(api, ownerPK, rho)
}

// OwnerPKGadget constrains and returns Poseidon(ak.x, ak.y).
func OwnerPKGadget(api frontend.API, ak gadgeteddsa.PublicKey) (frontend.Variable, error) {
	return poseidon.HashGadget(api, ak.A.X, ak.A.Y)
}

// SpendingKey authorizes spends of the notes owned by its public key.
type SpendingKey struct {
	priv *eddsa.PrivateKey
}

// GenerateSpendingKey draws a key from rng.
func GenerateSpendingKey(rng io.Reader) (SpendingKey, error) {
	priv, err := eddsa.GenerateKey(rng)
	if err != nil {
		return SpendingKey{}, err
	}
	return SpendingKey{priv: priv}, nil
}

// Owner returns ak, the public key.
func (k SpendingKey) Owner() twistededwards.PointAffine {
	return k.priv.PublicKey.A
}

// Signature is a spend authorization: an EdDSA signature by the owner's key
// over a message field element.
type Signature struct {
	R twistededwards.PointAffine
	S fr.Element
}

// Sign signs msg (a field element, big-endian) with the MiMC challenge hash.
func (k SpendingKey) Sign(msg fr.Element) (Signature, error) {
	m := msg.Bytes()
	raw, err := k.priv.Sign(m[:], hash.MIMC_BN254.New())
	if err != nil {
		return Signature{}, err
	}
	var sig eddsa.Signature
	if _, err := sig.SetBytes(raw); err != nil {
		return Signature{}, err
	}
	var s fr.Element
	// S is reduced modulo the curve order, which is below r, so canonical.
	if err := s.SetBytesCanonical(sig.S[:]); err != nil {
		return Signature{}, err
	}
	return Signature{R: sig.R, S: s}, nil
}

// Vars converts the signature to circuit variables.
func (s *Signature) Vars() gadgeteddsa.Signature {
	var v gadgeteddsa.Signature
	v.R.X, v.R.Y, v.S = s.R.X, s.R.Y, s.S
	return v
}

// Dummy is a placeholder signature for witnesses that are not checked
// (forced burns): the base point and S = 0, both well-formed so the gadget's
// own range and curve assertions pass.
func Dummy() Signature {
	return Signature{R: twistededwards.GetEdwardsCurve().Base}
}

// OwnerVars converts ak to circuit variables.
func OwnerVars(ak *twistededwards.PointAffine) gadgeteddsa.PublicKey {
	var v gadgeteddsa.PublicKey
	v.A.X, v.A.Y = ak.X, ak.Y
	return v
}

// Random returns a note of the given value for owner ak with fresh rho and r.
func Random(rng io.Reader, value uint64, ak twistededwards.PointAffine) (Note, error) {
	n := Note{Value: value, Owner: ak}
	if err := randomElement(rng, &n.Rho); err != nil {
		return Note{}, err
	}
	if err := randomElement(rng, &n.R); err != nil {
		return Note{}, err
	}
	return n, nil
}

func randomElement(rng io.Reader, out *fr.Element) error {
	var buf [64]byte
	if _, err := io.ReadFull(rng, buf[:]); err != nil {
		return err
	}
	out.SetBytes(buf[:]) // reduces mod r; 512 bits of entropy keeps it uniform
	return nil
}

// FromSeed derives a note deterministically from a seed, for reproducible
// fixtures: rho and r are SHA-256(seed ‖ label) reduced into the field, and
// the owner is SpendingKeyFromSeed(seed).
func FromSeed(seed []byte, value uint64) Note {
	return Note{
		Value: value,
		Owner: SpendingKeyFromSeed(seed).Owner(),
		Rho:   deriveFromSeed(seed, "rho"),
		R:     deriveFromSeed(seed, "r"),
	}
}

// SpendingKeyFromSeed is the spending key of the notes FromSeed derives from
// seed: the key generator run on SHA-256(seed ‖ "spending-key").
func SpendingKeyFromSeed(seed []byte) SpendingKey {
	h := sha256.New()
	h.Write(seed)
	h.Write([]byte("spending-key"))
	k, err := GenerateSpendingKey(bytes.NewReader(h.Sum(nil)))
	if err != nil {
		panic(err) // the reader always has the 32 bytes the generator reads
	}
	return k
}

func deriveFromSeed(seed []byte, label string) fr.Element {
	h := sha256.New()
	h.Write(seed)
	h.Write([]byte(label))
	var e fr.Element
	e.SetBytes(h.Sum(nil))
	return e
}

// Opening is the JSON form of a note together with its commitment; field
// elements are 0x-prefixed big-endian hex, exactly 32 bytes, canonical
// (below the field modulus). That is the only form FromOpening accepts.
// owner_pk is redundant with owner_ak_{x,y} and checked against them.
type Opening struct {
	Value      uint64 `json:"value"`
	OwnerAKX   string `json:"owner_ak_x"`
	OwnerAKY   string `json:"owner_ak_y"`
	OwnerPK    string `json:"owner_pk"`
	Rho        string `json:"rho"`
	R          string `json:"r"`
	Commitment string `json:"commitment"`
}

// ToOpening serializes the note and its commitment.
func (n *Note) ToOpening() Opening {
	cm, pk := n.Commitment(), n.OwnerPK()
	return Opening{
		Value:      n.Value,
		OwnerAKX:   Hex32(&n.Owner.X),
		OwnerAKY:   Hex32(&n.Owner.Y),
		OwnerPK:    Hex32(&pk),
		Rho:        Hex32(&n.Rho),
		R:          Hex32(&n.R),
		Commitment: Hex32(&cm),
	}
}

// FromOpening parses an Opening and checks its owner_pk and commitment.
func FromOpening(o Opening) (Note, error) {
	n := Note{Value: o.Value}
	for _, f := range []struct {
		name string
		src  string
		dst  *fr.Element
	}{
		{"owner_ak_x", o.OwnerAKX, &n.Owner.X},
		{"owner_ak_y", o.OwnerAKY, &n.Owner.Y},
		{"rho", o.Rho, &n.Rho},
		{"r", o.R, &n.R},
	} {
		if err := ParseHex32(f.src, f.dst); err != nil {
			return Note{}, fmt.Errorf("note: %s: %w", f.name, err)
		}
	}
	if !n.Owner.IsOnCurve() {
		return Note{}, fmt.Errorf("note: owner_ak is not on the curve")
	}
	var pk, cm fr.Element
	if err := ParseHex32(o.OwnerPK, &pk); err != nil {
		return Note{}, fmt.Errorf("note: owner_pk: %w", err)
	}
	if got := n.OwnerPK(); !got.Equal(&pk) {
		return Note{}, fmt.Errorf("note: owner_pk mismatch: got %s", Hex32(&got))
	}
	if err := ParseHex32(o.Commitment, &cm); err != nil {
		return Note{}, fmt.Errorf("note: commitment: %w", err)
	}
	if got := n.Commitment(); !got.Equal(&cm) {
		return Note{}, fmt.Errorf("note: commitment mismatch: got %s", Hex32(&got))
	}
	return n, nil
}

// MarshalJSON writes the Opening form.
func (n Note) MarshalJSON() ([]byte, error) {
	return json.Marshal(n.ToOpening())
}

// UnmarshalJSON reads the Opening form and checks the commitment.
func (n *Note) UnmarshalJSON(data []byte) error {
	var o Opening
	if err := json.Unmarshal(data, &o); err != nil {
		return err
	}
	parsed, err := FromOpening(o)
	if err != nil {
		return err
	}
	*n = parsed
	return nil
}

// Hex32 encodes e as 0x-prefixed big-endian hex, 32 bytes (66 characters).
func Hex32(e *fr.Element) string {
	b := e.Bytes() // big-endian, 32 bytes
	return "0x" + hex.EncodeToString(b[:])
}

// HexBytes32 encodes 32 raw bytes as 0x-prefixed hex.
func HexBytes32(b *[32]byte) string {
	return "0x" + hex.EncodeToString(b[:])
}

// ParseHex32 is the strict inverse of Hex32: it rejects anything but a
// 0x-prefixed 64-digit hex string holding a canonical field element, so a
// value another parser (e.g. the Rust e2e crate) would refuse cannot slip
// through reduced.
func ParseHex32(s string, out *fr.Element) error {
	if len(s) != 2+2*fr.Bytes || s[:2] != "0x" {
		return fmt.Errorf("want 0x-prefixed %d-byte hex, got %q", fr.Bytes, s)
	}
	var b [fr.Bytes]byte
	if _, err := hex.Decode(b[:], []byte(s[2:])); err != nil {
		return err
	}
	if err := out.SetBytesCanonical(b[:]); err != nil {
		return fmt.Errorf("%w: %q", err, s)
	}
	return nil
}
