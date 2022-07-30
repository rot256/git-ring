package ring

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
	"math/big"
)

type rsaProver struct {
	pf rsaProof
	sk *rsa.PrivateKey
}

type rsaProof struct {
	A *big.Int // image
	Z *big.Int // preimage of (a + c) mod N
}

func rsaChallenge(pk *rsa.PublicKey, chal challenge) *big.Int {
	return chal.Int("rsa-challenge", pk.N)
}

func randomZnElem(pk *rsa.PublicKey) *big.Int {
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

func (pf *rsaProof) Verify(pki interface{}, chal challenge) error {
	pk := pki.(*rsa.PublicKey)

	// strict encoding: all numbers in \ZZ_N canonical
	if pk.N.Cmp(pf.A) != 1 {
		return errors.New("field A is not canonically encoded in ZZ_N")
	}
	if pk.N.Cmp(pf.Z) != 1 {
		return errors.New("field Z is not canonically encoded in ZZ_N")
	}

	// compute challenge
	c := rsaChallenge(pk, chal)

	// img = a + c (image)
	img := (&big.Int{}).Add(pf.A, c)
	img = img.Mod(img, pk.N)

	// check that \phi(z) = a + c
	if rsaPerm(pk, pf.Z).Cmp(img) != 0 {
		return errors.New("challenge is not inverted correctly")
	}

	return nil
}

func rsaSim(pk *rsa.PublicKey, chal challenge) *rsaProof {
	var pf rsaProof

	// convert challenge to element in Z_N
	c := rsaChallenge(pk, chal)

	// z <- Z_N
	pf.Z = randomZnElem(pk)

	// phi(z) = a + c mod N
	// a = phi(z) - c mod N
	pf.A = rsaPerm(pk, pf.Z)
	pf.A = pf.A.Sub(pf.A, c)
	pf.A = pf.A.Mod(pf.A, pk.N)

	return &pf
}

func (pf *rsaProof) Commit(tx *transcript) {
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

func rsaProve(sk *rsa.PrivateKey) *rsaProver {
	// sample random Zn elem
	// (might not be in the range of \phi with negl. prob)
	var pf rsaProof
	pf.A = randomZnElem(&sk.PublicKey)
	return &rsaProver{pf: pf, sk: sk}
}

func (p *rsaProver) Finish(chal challenge) {
	// sample challeng
	c := rsaChallenge(&p.sk.PublicKey, chal)

	// compute challenge image (product of c and A)
	img := (&big.Int{}).Add(c, p.pf.A)
	img = img.Mod(img, p.sk.PublicKey.N)

	// invert challenge
	p.pf.Z = img.Exp(img, p.sk.D, p.sk.N)
}

func (p *rsaProver) Pf() proof {
	return &p.pf
}
