package ring

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"math/big"
)

// almost forgot how much the ECC fucking sucks in Go...
// a frigin arsenal of footguns, shit looks like 90ties crypto code.
// sucks to have a weak type-system I guess...

type ecdsaProver struct {
	sk *ecdsa.PrivateKey
	pf ecdsaProof
	r  *big.Int
}

type ecdsaProof struct {
	Ax *big.Int
	Ay *big.Int
	Z  *big.Int
}

func (pf ecdsaProof) Marshal() []byte {
	b, err := asn1.Marshal(pf)
	if err != nil {
		panic(err)
	}
	return b
}

func (pf *ecdsaProof) Unmarshal(b []byte) error {
	rest, err := asn1.Unmarshal(b, pf)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("ECDSA proof contains junk")
	}
	if pf.Ax == nil || pf.Ay == nil {
		return errors.New("ECDSA proof missing A point")
	}
	if pf.Z == nil {
		return errors.New("ECDSA proof missing Z scalar")
	}
	return nil
}

func ecdsaRandomScalar(pk *ecdsa.PublicKey) *big.Int {
	// generate enough random bits to avoid statistical bias (or make it negl.)
	n := pk.Curve.Params().N.BitLen()
	rBytes := make([]byte, n/8*2)
	if _, err := rand.Read(rBytes[:]); err != nil {
		panic(err)
	}

	// reduce modulo the order of the curve
	r := (&big.Int{}).SetBytes(rBytes)
	return r.Mod(r, pk.Curve.Params().N)
}

func ecdsaNewChallenge(pk *ecdsa.PublicKey, chal challenge) *big.Int {
	return (&big.Int{}).SetBytes(chal.Take(16))
}

func (pf ecdsaProof) Commit(tx *transcript) {
	tx.Append([]byte("ecdsa proof"))
	tx.Append(pf.Ax.Bytes())
	tx.Append(pf.Ay.Bytes())
}

func (pf ecdsaProof) Verify(key interface{}, chal challenge) error {
	pk := key.(*ecdsa.PublicKey)

	if pf.Ax == nil || pf.Ay == nil || !pk.Curve.IsOnCurve(pf.Ax, pf.Ay) {
		return errors.New("invalid A point")
	}

	if pf.Z == nil || pk.Curve.Params().N.Cmp(pf.Z) != 1 {
		return errors.New("invalid Z scalar")
	}

	c := ecdsaNewChallenge(pk, chal)

	zx, zy := pk.Curve.ScalarBaseMult(pf.Z.Bytes())
	rx, ry := pk.Curve.ScalarMult(pk.X, pk.Y, c.Bytes())
	lx, ly := pk.Curve.Add(rx, ry, pf.Ax, pf.Ay)

	if lx.Cmp(zx) != 0 || ly.Cmp(zy) != 0 {
		return errors.New("failed final check: [c] * pk + A != [z] * G")
	}

	return nil
}

func ecdsaSim(pk *ecdsa.PublicKey, chal challenge) *ecdsaProof {
	if !pk.Curve.IsOnCurve(pk.X, pk.Y) {
		panic("the point must be on the curve")
	}

	Z := ecdsaRandomScalar(pk)
	c := ecdsaNewChallenge(pk, chal)

	lx, ly := pk.Curve.ScalarBaseMult(Z.Bytes())
	rx, ry := pk.Curve.ScalarMult(pk.X, pk.Y, c.Bytes())

	// invert the point (there is not method to do this, wtf?)
	// yea for leaky "abstractions"
	ry = ry.Neg(ry)
	ry = ry.Mod(ry, pk.Params().P)

	// sanity check
	if !pk.Curve.IsOnCurve(rx, ry) {
		panic("failed inversion")
	}

	Ax, Ay := pk.Curve.Add(lx, ly, rx, ry)

	return &ecdsaProof{
		Ax: Ax,
		Ay: Ay,
		Z:  Z,
	}
}

func (p ecdsaProver) Pf() proof {
	return &p.pf
}

func (p *ecdsaProver) Finish(chal challenge) {

	c := ecdsaNewChallenge(&p.sk.PublicKey, chal)

	p.pf.Z = (&big.Int{}).Mul(c, p.sk.D)
	p.pf.Z = (&big.Int{}).Add(p.pf.Z, p.r)
	p.pf.Z = (&big.Int{}).Mod(p.pf.Z, p.sk.Curve.Params().N)

	// to protect against mistakes erase the blinding
	p.r = nil
}

// Schorr proof
func ecdsaProve(sk *ecdsa.PrivateKey) *ecdsaProver {
	// sample random blinding
	var p ecdsaProver
	p.r = ecdsaRandomScalar(&sk.PublicKey)
	p.sk = sk

	// compute commitment
	Ax, Ay := sk.PublicKey.Curve.ScalarBaseMult(p.r.Bytes())
	p.pf.Ax = Ax
	p.pf.Ay = Ay

	return &p
}
