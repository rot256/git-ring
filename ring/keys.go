package ring

import (
	"strings"

	"golang.org/x/crypto/ssh"
)

type PublicKey struct {
	pk     ssh.PublicKey
	pk_ssh string // this is only used for displaying (the generated signature does not depend on it)
}

func (p *PublicKey) Id() string {
	return p.pk.Type() + "-" + ssh.FingerprintSHA256(p.pk)
}

type EncKeyPair struct {
	PK    PublicKey
	SKPEM string // PEM serialized private key
}

type KeyPair struct {
	PK PublicKey
	SK interface{}
}

func (pk1 PublicKey) Equals(pk2 PublicKey) bool {
	return pk1.Id() == pk2.Id()
}

func (k *PublicKey) FP() string {
	return ssh.FingerprintSHA256(k.pk)
}

func (k *PublicKey) Name() string {
	return k.FP() + " (" + k.pk.Type() + ")"
}

func PublicKeyFromStr(s string) (PublicKey, error) {
	pk_ssh := strings.TrimSpace(s)
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pk_ssh))
	if err != nil {
		return PublicKey{}, err
	}

	return PublicKey{
		pk_ssh: pk_ssh,
		pk:     pk,
	}, nil
}
