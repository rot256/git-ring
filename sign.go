package main

import (
	"crypto"
	"crypto/ed25519"
	"fmt"
)

type Challenge = [16]byte

type Ed25519Proof struct {
	c Challenge
	z []byte
}

func (p Ed25519Proof) Simulate() []byte {
	return nil
}

func ringSign(pair KeyPair, pks []PublicKey) {
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
