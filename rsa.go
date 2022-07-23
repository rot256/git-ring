package main

// Assumes StrongRSA

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"math/big"
)

type rsaProof struct {
	A *big.Int // image
	Z *big.Int // preimage of (A * C) mod N
}

// generate an RSA challenge big enough to wrap the modulus (and any e)
func rsaChallenge(pk *rsa.PublicKey, chal Challenge) *big.Int {
	n := pk.N.BitLen() / 8
	c := (&big.Int{}).SetBytes(chal.Take(n))
	return c
}

func randomPreimage(pk *rsa.PublicKey) *big.Int {
	// read random bytes
	n := pk.N.BitLen() / 8
	bs := make([]byte, 2*n)
	if _, err := rand.Read(bs); err != nil {
		panic(err)
	}

	// reduce mod N
	r := (&big.Int{}).SetBytes(bs)
	return r.Mod(r, pk.N)
}

func rsaPerm(pk *rsa.PublicKey, input *big.Int) *big.Int {
	return (&big.Int{}).Exp(
		input,
		big.NewInt(int64(pk.E)),
		pk.N,
	)
}

func (pf *rsaProof) Verify(pk interface{}, chal Challenge) bool {
	return true
}

func rsaSim(pk *rsa.PublicKey, chal Challenge) *rsaProof {
	var pf rsaProof

	// sample challenge (offset to invert)
	c := rsaChallenge(pk, chal)

	//
	c_inv := (&big.Int{}).ModInverse(c, pk.N)
	if c_inv == nil {
		panic("no inverse exists for c, also, we just factored the modulus...")
	}

	// Z^e = A * C mod N
	// A = Z^e * C^{-1}
	pf.Z = randomPreimage(pk)
	pf.A = rsaPerm(pk, pf.Z)
	pf.A = pf.A.Mul(pf.A, c_inv)
	return &pf
}

func (pf *rsaProof) Commit(tx *Transcript) {
	tx.Append([]byte("rsa proof"))
	tx.Append(pf.A.Bytes())
}

func (pf *rsaProof) Marshal() []byte {
	bytes, err := asn1.Marshal(pf)
	if err != nil {
		panic(err)
	}
	return bytes
}
