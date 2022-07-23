package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"

	"filippo.io/edwards25519"
)

func ed25519SfromSK(sk ed25519.PrivateKey) *edwards25519.Scalar {
	// derieve secret from ed25519 secret key
	if l := len(sk); l != ed25519.PrivateKeySize {
		panic("ed25519: bad private key length")
	}

	seed := sk[:ed25519.SeedSize]

	h := sha512.Sum512(seed)
	s, err := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	if err != nil {
		panic("ed25519: internal error: setting scalar failed")
	}
	return s
}

type ed25519Prover struct {
	r  *edwards25519.Scalar
	pf ed25519Proof
	sk ed25519.PrivateKey
	pk ed25519.PublicKey
}

type ed25519Proof struct {
	A *edwards25519.Point
	Z *edwards25519.Scalar
}

func (pf ed25519Proof) Marshal() []byte {
	out := pf.A.Bytes()
	out = append(out, pf.Z.Bytes()...)
	return out
}

func (pf *ed25519Proof) Unmarshal(b []byte) error {
	if len(b) != 64 {
		return errors.New("ed25519 proof should be 64 bytes")
	}

	A, err := (&edwards25519.Point{}).SetBytes(b[:32])
	if err != nil {
		return err
	}

	Z, err := (&edwards25519.Scalar{}).SetCanonicalBytes(b[32:])
	if err != nil {
		return err
	}

	pf.A = A
	pf.Z = Z
	return nil
}

type Ed25519Challenge struct {
	c edwards25519.Scalar
}

func (chal *Ed25519Challenge) Set(bytes []byte) {
	var c_bytes [32]byte
	copy(c_bytes[:], bytes[:16])
	chal.c.SetCanonicalBytes(c_bytes[:])
}

func ed25519RandomScalar() *edwards25519.Scalar {
	var r_bytes [64]byte
	if _, err := rand.Read(r_bytes[:]); err != nil {
		panic(err)
	}

	r, err := (&edwards25519.Scalar{}).SetUniformBytes(r_bytes[:])
	if err != nil {
		panic(err)
	}
	return r
}

func ed25519Challenge(chal Challenge) *edwards25519.Scalar {
	// interpret challenge as 128-bit scalar
	c, err := (&edwards25519.Scalar{}).SetCanonicalBytes(chal.TakeZero(16, 32))
	if err != nil {
		panic(err)
	}
	return c
}

func (pf ed25519Proof) Commit(tx *Transcript) {
	tx.Append([]byte("ed25519 proof"))
	tx.Append(pf.A.Bytes())
}

func (pf ed25519Proof) Verify(pk interface{}, chal Challenge) bool {
	if pf.A == nil || pf.Z == nil {
		return false
	}
	A := pf.computeA(pk.(ed25519.PublicKey), chal)
	return A.Equal(pf.A) == 1
}

func (pf ed25519Proof) computeA(pk ed25519.PublicKey, chal Challenge) *edwards25519.Point {
	x, err := (&edwards25519.Point{}).SetBytes(pk)
	if err != nil {
		panic(err)
	}

	c := ed25519Challenge(chal)
	g := edwards25519.NewGeneratorPoint()

	l := (&edwards25519.Point{}).ScalarMult(pf.Z, g)
	r := (&edwards25519.Point{}).ScalarMult(c, x)
	r = r.Negate(r)

	return (&edwards25519.Point{}).Add(l, r)
}

func ed25519Sim(pk ed25519.PublicKey, chal Challenge) *ed25519Proof {
	// [z] * g = [c] * x + a
	// [z] * g - [c] * x = a

	var pf ed25519Proof
	pf.Z = ed25519RandomScalar()
	pf.A = pf.computeA(pk, chal)
	return &pf
}

func (p ed25519Prover) Pf() Proof {
	return &p.pf
}

func (p *ed25519Prover) Finish(chal Challenge) {

	s := ed25519SfromSK(p.sk)
	c := ed25519Challenge(chal)

	p.pf.Z = (&edwards25519.Scalar{}).MultiplyAdd(c, s, p.r)
	p.r = nil

	if p.pf.Verify(p.pk, chal) == false {
		panic("ed25519 proof does not verify")
	}
}

// Schorr proof
func proveEd25519(sk ed25519.PrivateKey) *ed25519Prover {

	// generate a commitment message

	var pf ed25519Proof

	g := edwards25519.NewGeneratorPoint()
	r := ed25519RandomScalar()

	pf.A = (&edwards25519.Point{}).ScalarMult(r, g)

	return &ed25519Prover{
		pk: sk.Public().(ed25519.PublicKey),
		pf: pf,
		sk: sk,
		r:  r,
	}
}
