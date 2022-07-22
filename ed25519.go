package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"

	"filippo.io/edwards25519"
)

func sFromEd25519Sk(sk ed25519.PrivateKey) *edwards25519.Scalar {
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

type Ed25519Gen struct {
	a  edwards25519.Point
	r  edwards25519.Scalar
	s  edwards25519.Scalar
	pk ed25519.PublicKey
}

type Ed25519MsgZ struct {
	z edwards25519.Scalar
}

type Ed25519Challenge struct {
	c edwards25519.Scalar
}

func (chal *Ed25519Challenge) Set(bytes []byte) {
	var c_bytes [32]byte
	copy(c_bytes[:], bytes[:16])
	chal.c.SetCanonicalBytes(c_bytes[:])
}

func (pf *Ed25519Gen) Hash() []byte {
	tx := sha512.New()
	tx.Write(pf.pk)
	tx.Write(pf.a.Bytes())
	return tx.Sum([]byte{})
}

func (pf *Ed25519Gen) Finish(chal Challenge) {
	// interpret challenge as 128-bit scalar
	var c edwards25519.Scalar
	c.SetCanonicalBytes(chal.TakeZero(16, 32))

	// compute response
	c.MultiplyAdd(&c, &pf.s, &pf.r)
}

// Schorr proof
func genEd25519(sk ed25519.PrivateKey) Ed25519Gen {
	pk := sk.Public().(ed25519.PublicKey)
	s := sFromEd25519Sk(sk)

	// generate random scalar
	var r edwards25519.Scalar
	var r_bytes [64]byte
	if _, err := rand.Read(r_bytes[:]); err != nil {
		panic(err)
	}
	r.SetUniformBytes(r_bytes[:])

	// generate a commitment message
	var a edwards25519.Point
	g := edwards25519.NewGeneratorPoint()
	a.ScalarMult(&r, g)

	return Ed25519Gen{
		a:  a,
		r:  r,
		s:  *s,
		pk: pk,
	}
}
