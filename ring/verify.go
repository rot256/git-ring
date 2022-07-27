package ring

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

func (sig *Signature) Verify(pks []PublicKey) ([]byte, error) {
	// index by fingerprints
	keyMap := make(map[string]PublicKey)
	for _, pk := range pks {
		keyMap[pk.FP()] = pk
	}

	// lookup subset of keys included in the signature
	// (the signature might be for a smaller ring, e.g. keys may have been added later)
	selectPks := make([]PublicKey, 0, len(sig.Fingerprints))
	for _, fp := range sig.Fingerprints {
		if pk, ok := keyMap[fp]; ok {
			selectPks = append(selectPks, pk)
		} else {
			return nil, errors.New("the ring is not a subset of the public keys used to verify")
		}
	}

	return sig.VerifyExact(selectPks)
}

func (sig *Signature) VerifyExact(pks []PublicKey) ([]byte, error) {
	// commit to statement (list of public key)
	tx := setupTranscript(pks, sig.Msg)

	// basic checks
	if len(sig.Proofs) != len(pks) {
		return nil, errors.New("incorrect number of proofs")
	}
	if len(sig.Challenges) != len(pks) {
		return nil, errors.New("incorrect number of challenges")
	}
	if len(sig.Fingerprints) != len(pks) {
		return nil, errors.New("incorrect number of fingerprints")
	}
	if sig.Version != version {
		return nil, errors.New("supported signature version")
	}

	// verify every proof
	for i, pk := range pks {
		// check fingerprint hint included in signature
		if pk.FP() != sig.Fingerprints[i] {
			return nil, errors.New("fingerprint does not match public key")
		}

		// pick proof type (based on public key)
		var pf proof
		switch pk.pk.Type() {
		case ssh.KeyAlgoED25519, ssh.KeyAlgoSKED25519:
			pf = &ed25519Proof{}
		case ssh.KeyAlgoRSA:
			pf = &rsaProof{}
		case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoSKECDSA256:
			pf = &ecdsaProof{}
		default:
			return nil, fmt.Errorf("unsupported key type: %s", pk.pk.Type())
		}

		// unmarshal proof
		if err := pf.Unmarshal(sig.Proofs[i]); err != nil {
			return nil, err
		}

		// check that challenge is right size
		chal := sig.Challenges[i]
		if !chal.IsValid() {
			return nil, errors.New("challenge is invalid (wrong length)")
		}

		// verify proof against challenge
		ckey := toCryptoPublicKey(pk)
		if err := pf.Verify(ckey, chal); err != nil {
			return nil, err
		}
		pf.Commit(tx)
	}

	// final check: challenges sum to zero
	delta := tx.Challenge()
	for _, chal := range sig.Challenges {
		delta.Add(chal)
	}

	if delta.IsZero() {
		return sig.Msg, nil
	} else {
		return nil, errors.New("challenges does not sum to zero")
	}
}
