package main

// Assumes StrongRSA
// Note: not technically a PoK (and therefore not a sigma protocol) for the secret key:
// there is no reduction from inverting the RSA permutation to recoving the order of the group
// (equiv. the factorization of the modulus)
//
// Instead it demonstrates that the prover can invert the permutation.
// The proof is however SHVZK.

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

type rsaProver struct {
	pf rsaProof
	sk *rsa.PrivateKey
}

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

func (pf *rsaProof) Verify(pki interface{}, chal Challenge) bool {
	pk := pki.(*rsa.PublicKey)

	// strict encoding: all numbers in \ZZ_N canonical
	if pk.N.Cmp(pf.A) != 1 || pk.N.Cmp(pf.Z) != 1 {
		fmt.Println(pk.N, pf.A)
		return false
	}

	// compute challenge
	c := rsaChallenge(pk, chal)

	// v1 = z^e
	v1 := rsaPerm(pk, pf.Z)

	// v2 = A*c
	v2 := (&big.Int{}).Mul(pf.A, c)
	v2 = v2.Mod(v2, pk.N)

	return v1.Cmp(v2) == 0
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
	pf.A = pf.A.Mod(pf.A, pk.N)

	if pf.Verify(pk, chal) == false {
		panic("rsa proof does not verify")
	}

	return &pf
}

func (pf *rsaProof) Commit(tx *Transcript) {
	tx.Append([]byte("rsa proof"))
	tx.Append(pf.A.Bytes())
}

func (pf *rsaProof) Unmarshal(b []byte) error {
	rest, err := asn1.Unmarshal(b, pf)
	if err != nil {
		return err
	}
	if len(rest) != 0 || pf.A == nil || pf.Z == nil {
		return errors.New("rsa proofs contains additional junk")
	}
	return nil
}

func (pf *rsaProof) Marshal() []byte {
	bytes, err := asn1.Marshal(*pf)
	if err != nil {
		panic(err)
	}
	return bytes
}

func proveRSA(sk *rsa.PrivateKey) *rsaProver {
	// just sample a random image
	var pf rsaProof
	r := randomPreimage(&sk.PublicKey)
	pf.A = rsaPerm(&sk.PublicKey, r)

	return &rsaProver{pf: pf, sk: sk}
}

func (p *rsaProver) Finish(chal Challenge) {
	// sample challeng
	c := rsaChallenge(&p.sk.PublicKey, chal)

	// compute challenge image (product of c and A)
	img := (&big.Int{}).Mul(c, p.pf.A)
	img = img.Mod(img, p.sk.PublicKey.N)

	// invert challenge
	p.pf.Z = img.Exp(img, p.sk.D, p.sk.N)

	// check if verify
	if p.pf.Verify(&p.sk.PublicKey, chal) == false {
		panic("generated RSA proof does not verify")
	}
}

func (p *rsaProver) Pf() Proof {
	return &p.pf
}
