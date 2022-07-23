package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"log"

	"golang.org/x/crypto/ssh"
)

func ringSign(pair KeyPair, pks []PublicKey) {
	// compute challenge size (depending on RSA moduli)
	challengeSize := 512

	index := len(pks)
	for i := range pks {
		if pair.pk.Equals(pks[i]) {
			index = i
		}
	}

	// sanity check
	if index == len(pks) {
		panic("public keys does not contain pair, this is a bug.")
	}

	// generate random challenges for in-active clauses
	challenges := make([]Challenge, len(pks))
	for i := range challenges {
		if i != index {
			challenges[i].Random(challengeSize)
		}
	}

	// commit to statement (list of public key)
	tx := NewTranscript()
	for _, pk := range pks {
		tx.Append(pk.pk.Marshal())
	}

	pfs := make([]Proof, len(pks))

	var prover Prover

	skCkey := pair.sk.(crypto.PrivateKey)
	sk := skCkey.(*ed25519.PrivateKey)

	prover = ProveEd25519(*sk)

	pfs[index] = prover.Pf()

	// simulate in-active clauses
	for i, pk := range pks {
		if i == index {
			continue
		}

		ckey := pk.pk.(ssh.CryptoPublicKey).CryptoPublicKey()
		chal := challenges[i]

		switch pk.pk.Type() {
		case ssh.KeyAlgoED25519:
			pfs[i] = ed25519Sim(ckey.(ed25519.PublicKey), chal)
		case ssh.KeyAlgoRSA:
			pfs[i] = rsaSim(ckey.(*rsa.PublicKey), chal)

		default:
			log.Fatalln("Unsupported key type:", pk.pk.Type())
		}
	}

	// commit to first round messages
	for _, pf := range pfs {
		pf.Commit(&tx)
	}

	// squeeze challenge
	challenges[index] = tx.Challenge(challengeSize)

	// compute challenge for active clause
	// (challenges and tx.Challenge sums to 0)
	for i, chal := range challenges {
		if i != index {
			challenges[index].Add(chal)
		}
	}

	// finish transcript for active clause
	prover.Finish(challenges[index])

	return

}
