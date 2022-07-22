package main

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
)

type Ed25519Proof struct {
	c Challenge
	z []byte
}

func (p Ed25519Proof) Simulate() []byte {
	return nil
}

func ringSign(pair KeyPair, pks []PublicKey) {
	// compute challenge size (depending on RSA moduli)
	challenge_size := 128

	index := len(pks)
	for i := range pks {
		if pair.pk.Equals(pks[i]) {
			index = i
		}
	}

	// generate random challenges for in-active clauses
	challenges := make([]Challenge, len(pks))
	for i, chal := range challenges {
		if i != index {
			chal.Random(challenge_size)
			println(i, len(chal.bytes))
		}
	}

	// simulate in-active clauses
	tx := NewTranscript()

	// squeeze challenge
	challenges[index] = tx.Challenge(challenge_size)

	// compute challenge for active clause
	// (challenges and tx.Challenge sums to 0)
	for i, chal := range challenges {
		if i != index {
			println(i, len(chal.bytes))
			challenges[index].Add(chal)
		}
	}

	// finish transcript for active clause
	ckey := pair.sk.(crypto.PrivateKey)

	func() {
		sk, ok := ckey.(*ed25519.PrivateKey)
		if ok {
			fmt.Println("ed25519 key", sk)
			genEd25519(*sk)
		}
	}()

	return

}
