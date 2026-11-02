// privtx builds circuits, keys and proofs for the private-tx protocol.
//
//	privtx smoke-fixture   [-out DIR]
//	privtx mint-fixture    [-out DIR] [-value N] [-seed STRING]
//	privtx burn-fixture    [-out DIR] [-notes N] [-index I] [-forced] [-seed STRING]
//	privtx pool-fixture    [-out DIR] [-notes N] [-unshield I] [-forfeit J] [-seed STRING]
//
// Each subcommand compiles its circuit, runs a (development) Groth16 setup,
// proves a fixed witness, self-verifies, and writes vk.bin, proof.bin and
// public.bin in gnark's native encodings into DIR for the Rust e2e tests.
// smoke-fixture proves 3·5 = 15; mint-fixture proves a deterministic note
// derived from -seed and also writes note.json (the opening);
// burn-fixture fills a tree with N deterministic notes, burns the one at
// index I (as its owner, or as the custodian with -forced) to a fixed
// destination from a fixed pool address, and also writes burn.json (the
// leaves, the opening, root, nullifier, flag, pool, destination and sighash)
// so the e2e crate can recompute the tree and the sighash. pool-fixture is a whole pool lifecycle for
// the pool program's e2e test: one C_mint proof per note (N notes, one key),
// then two C_burn proofs against the resulting tree, the owner's unshield of
// note I and the custodian's forfeiture of note J, with pool.json describing
// it all.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"crypto/sha256"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/burn"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/export"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/merkle"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/mint"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/note"
	"github.com/anza-xyz/cryptography/experimental/private-tx/circuits/smoke"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "smoke-fixture":
		err = smokeFixture(os.Args[2:])
	case "mint-fixture":
		err = mintFixture(os.Args[2:])
	case "burn-fixture":
		err = burnFixture(os.Args[2:])
	case "pool-fixture":
		err = poolFixture(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: privtx smoke-fixture [-out DIR]")
	fmt.Fprintln(os.Stderr, "       privtx mint-fixture [-out DIR] [-value N] [-seed STRING]")
	fmt.Fprintln(os.Stderr, "       privtx burn-fixture [-out DIR] [-notes N] [-index I] [-forced] [-seed STRING]")
	fmt.Fprintln(os.Stderr, "       privtx pool-fixture [-out DIR] [-notes N] [-unshield I] [-forfeit J] [-seed STRING]")
	os.Exit(2)
}

func smokeFixture(args []string) error {
	fs := flag.NewFlagSet("smoke-fixture", flag.ExitOnError)
	out := fs.String("out", "../fixtures/smoke", "output directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ccs, err := smoke.Compile()
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	return proveAndWrite("smoke", ccs, smoke.Assignment(3, 5), *out)
}

func mintFixture(args []string) error {
	fs := flag.NewFlagSet("mint-fixture", flag.ExitOnError)
	out := fs.String("out", "../fixtures/mint", "output directory")
	value := fs.Uint64("value", 1_000_000, "note value")
	seed := fs.String("seed", "private-tx mint fixture", "seed for the deterministic note")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ccs, err := mint.Compile()
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	n := note.FromSeed([]byte(*seed), *value)
	if err := proveAndWrite("C_mint", ccs, mint.Assignment(&n), *out); err != nil {
		return err
	}
	opening := n.ToOpening()
	data, err := json.MarshalIndent(opening, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	path := filepath.Join(*out, "note.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes)\n", path, len(data))
	fmt.Printf("commitment %s\n", opening.Commitment)
	return nil
}

// burnFixtureFile is burn.json: enough for the e2e crate to rebuild the tree
// and the nullifier with its own Poseidon.
type burnFixtureFile struct {
	Depth       int          `json:"depth"`
	Leaves      []string     `json:"leaves"`
	Index       uint64       `json:"index"`
	Note        note.Opening `json:"note"`
	Root        string       `json:"root"`
	Nullifier   string       `json:"nullifier"`
	Forced      bool         `json:"forced"`
	Pool        string       `json:"pool"`
	Destination string       `json:"destination"`
	SigHash     string       `json:"sighash"`
}

// Fixture addresses: the pool account and the burn destination are fixed so
// the signed sighash is reproducible; the e2e test uses these addresses.
var (
	fixturePool        = fixtureAddress("private-tx fixture: pool")
	fixtureDestination = fixtureAddress("private-tx fixture: destination")
)

func fixtureAddress(label string) [32]byte {
	return sha256.Sum256([]byte(label))
}

func burnFixture(args []string) error {
	fs := flag.NewFlagSet("burn-fixture", flag.ExitOnError)
	out := fs.String("out", "../fixtures/burn", "output directory")
	count := fs.Uint("notes", 5, "number of notes in the tree")
	index := fs.Uint64("index", 2, "leaf index of the note to burn")
	forced := fs.Bool("forced", false, "burn as the custodian (forfeiture) instead of the owner")
	seed := fs.String("seed", "private-tx burn fixture", "seed for the deterministic notes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *index >= uint64(*count) {
		return fmt.Errorf("index %d out of range (%d notes)", *index, *count)
	}
	ccs, err := burn.Compile()
	if err != nil {
		return fmt.Errorf("compile: %w", err)
	}
	var tr merkle.Tree
	notes := make([]note.Note, *count)
	seeds := make([][]byte, *count)
	file := burnFixtureFile{Depth: merkle.Depth, Index: *index, Forced: *forced}
	for i := range notes {
		seeds[i] = []byte(fmt.Sprintf("%s/%d", *seed, i))
		notes[i] = note.FromSeed(seeds[i], 1_000_000*uint64(i+1))
		cm := notes[i].Commitment()
		if _, err := tr.Append(cm); err != nil {
			return err
		}
		file.Leaves = append(file.Leaves, note.Hex32(&cm))
	}
	path, err := tr.Path(*index)
	if err != nil {
		return err
	}
	n := notes[*index]
	var witness *burn.Circuit
	if *forced {
		witness = burn.Forfeit(&n, &path, fixturePool, fixtureDestination)
	} else {
		witness, err = burn.Unshield(&n, &path, note.SpendingKeyFromSeed(seeds[*index]), fixturePool, fixtureDestination)
		if err != nil {
			return err
		}
	}
	if err := proveAndWrite("C_burn", ccs, witness, *out); err != nil {
		return err
	}
	root, nf := tr.Root(), n.Nullifier()
	sh := burn.SigHash(fixturePool, fixtureDestination, nf, n.Value)
	file.Note, file.Root, file.Nullifier = n.ToOpening(), note.Hex32(&root), note.Hex32(&nf)
	file.Pool, file.Destination, file.SigHash = note.HexBytes32(&fixturePool), note.HexBytes32(&fixtureDestination), note.Hex32(&sh)
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	p := filepath.Join(*out, "burn.json")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes)\n", p, len(data))
	fmt.Printf("root %s\nnullifier %s\nforced %v\n", file.Root, file.Nullifier, *forced)
	return nil
}

// poolFixtureFile is pool.json: the notes in leaf order, the root after all
// of them are minted, and the burns proved against that root. Proof files sit
// next to it: mint/vk.bin with mint/proof-<i>.bin, mint/public-<i>.bin per
// note, and burn/vk.bin with burn/proof-<name>.bin, burn/public-<name>.bin
// per burn.
type poolFixtureFile struct {
	Depth int            `json:"depth"`
	Pool  string         `json:"pool"`
	Notes []note.Opening `json:"notes"`
	Root  string         `json:"root"`
	Burns []poolBurn     `json:"burns"`
}

type poolBurn struct {
	Name        string `json:"name"`
	Index       uint64 `json:"index"`
	Nullifier   string `json:"nullifier"`
	Forced      bool   `json:"forced"`
	Destination string `json:"destination"`
	SigHash     string `json:"sighash"`
}

func poolFixture(args []string) error {
	fs := flag.NewFlagSet("pool-fixture", flag.ExitOnError)
	out := fs.String("out", "../fixtures/pool", "output directory")
	count := fs.Uint("notes", 5, "number of notes to mint")
	unshield := fs.Uint64("unshield", 2, "leaf index the owner unshields")
	forfeit := fs.Uint64("forfeit", 4, "leaf index the custodian forfeits")
	seed := fs.String("seed", "private-tx pool fixture", "seed for the deterministic notes")
	if err := fs.Parse(args); err != nil {
		return err
	}
	for _, i := range []uint64{*unshield, *forfeit} {
		if i >= uint64(*count) {
			return fmt.Errorf("index %d out of range (%d notes)", i, *count)
		}
	}
	if *unshield == *forfeit {
		return fmt.Errorf("unshield and forfeit must name different notes")
	}

	mintProver, err := newProver("C_mint", mint.Compile)
	if err != nil {
		return err
	}
	burnProver, err := newProver("C_burn", burn.Compile)
	if err != nil {
		return err
	}
	if err := mintProver.writeVK(filepath.Join(*out, "mint")); err != nil {
		return err
	}
	if err := burnProver.writeVK(filepath.Join(*out, "burn")); err != nil {
		return err
	}

	var tr merkle.Tree
	notes := make([]note.Note, *count)
	seeds := make([][]byte, *count)
	file := poolFixtureFile{Depth: merkle.Depth, Pool: note.HexBytes32(&fixturePool)}
	for i := range notes {
		seeds[i] = []byte(fmt.Sprintf("%s/%d", *seed, i))
		notes[i] = note.FromSeed(seeds[i], 1_000_000*uint64(i+1))
		if _, err := tr.Append(notes[i].Commitment()); err != nil {
			return err
		}
		file.Notes = append(file.Notes, notes[i].ToOpening())
		if err := mintProver.writeProof(filepath.Join(*out, "mint"), fmt.Sprint(i), mint.Assignment(&notes[i])); err != nil {
			return err
		}
	}
	root := tr.Root()
	file.Root = note.Hex32(&root)

	burns := []struct {
		name   string
		index  uint64
		forced bool
	}{{"unshield", *unshield, false}, {"forfeit", *forfeit, true}}
	for _, b := range burns {
		path, err := tr.Path(b.index)
		if err != nil {
			return err
		}
		n := notes[b.index]
		var witness *burn.Circuit
		if b.forced {
			witness = burn.Forfeit(&n, &path, fixturePool, fixtureDestination)
		} else {
			witness, err = burn.Unshield(&n, &path, note.SpendingKeyFromSeed(seeds[b.index]), fixturePool, fixtureDestination)
			if err != nil {
				return err
			}
		}
		if err := burnProver.writeProof(filepath.Join(*out, "burn"), b.name, witness); err != nil {
			return err
		}
		nf := n.Nullifier()
		sh := burn.SigHash(fixturePool, fixtureDestination, nf, n.Value)
		file.Burns = append(file.Burns, poolBurn{
			Name: b.name, Index: b.index, Nullifier: note.Hex32(&nf), Forced: b.forced,
			Destination: note.HexBytes32(&fixtureDestination), SigHash: note.Hex32(&sh),
		})
	}

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	p := filepath.Join(*out, "pool.json")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d bytes)\n", p, len(data))
	fmt.Printf("root %s\n", file.Root)
	return nil
}

// prover holds a compiled circuit and a development Groth16 key pair, so one
// setup can serve several proofs. A real deployment needs an MPC ceremony.
type prover struct {
	name string
	ccs  constraint.ConstraintSystem
	pk   groth16.ProvingKey
	vk   groth16.VerifyingKey
}

func newProver(name string, compile func() (constraint.ConstraintSystem, error)) (*prover, error) {
	ccs, err := compile()
	if err != nil {
		return nil, fmt.Errorf("%s: compile: %w", name, err)
	}
	fmt.Printf("%s: %d constraints, %d public inputs\n", name, ccs.GetNbConstraints(), ccs.GetNbPublicVariables()-1)
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, fmt.Errorf("%s: setup: %w", name, err)
	}
	return &prover{name: name, ccs: ccs, pk: pk, vk: vk}, nil
}

// prove proves assignment and self-verifies.
func (p *prover) prove(assignment frontend.Circuit) (groth16.Proof, witness.Witness, error) {
	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, fmt.Errorf("%s: witness: %w", p.name, err)
	}
	public, err := full.Public()
	if err != nil {
		return nil, nil, fmt.Errorf("%s: public witness: %w", p.name, err)
	}
	proof, err := groth16.Prove(p.ccs, p.pk, full)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: prove: %w", p.name, err)
	}
	if err := groth16.Verify(proof, p.vk, public); err != nil {
		return nil, nil, fmt.Errorf("%s: self-verify: %w", p.name, err)
	}
	return proof, public, nil
}

func (p *prover) writeVK(dir string) error {
	sizes, err := export.WriteVK(dir, "vk.bin", p.vk)
	if err != nil {
		return err
	}
	report(dir, sizes)
	return nil
}

// writeProof proves assignment and writes proof-<tag>.bin and public-<tag>.bin.
func (p *prover) writeProof(dir, tag string, assignment frontend.Circuit) error {
	proof, public, err := p.prove(assignment)
	if err != nil {
		return err
	}
	sizes, err := export.WriteProof(dir, "proof-"+tag+".bin", "public-"+tag+".bin", proof, public)
	if err != nil {
		return err
	}
	report(dir, sizes)
	return nil
}

// proveAndWrite runs a development setup, proves assignment, self-verifies
// and writes vk.bin, proof.bin and public.bin.
func proveAndWrite(name string, ccs constraint.ConstraintSystem, assignment frontend.Circuit, out string) error {
	p, err := newProver(name, func() (constraint.ConstraintSystem, error) { return ccs, nil })
	if err != nil {
		return err
	}
	proof, public, err := p.prove(assignment)
	if err != nil {
		return err
	}
	sizes, err := export.Write(out, export.Artifacts{VK: p.vk, Proof: proof, Public: public})
	if err != nil {
		return err
	}
	report(out, sizes)
	return nil
}

func report(dir string, sizes map[string]int) {
	names := make([]string, 0, len(sizes))
	for n := range sizes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Printf("wrote %s (%d bytes)\n", filepath.Join(dir, n), sizes[n])
	}
}
