package ring

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"errors"
	"reflect"
	"strings"
	"unsafe"

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

func toCryptoPublicKey(pk PublicKey) crypto.PublicKey {
	switch pk.pk.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoRSA, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		return pk.pk.(ssh.CryptoPublicKey).CryptoPublicKey()

	case ssh.KeyAlgoSKECDSA256:
		// use reflection to access the inner (unexported) ecdsa.PublicKey
		rs := reflect.ValueOf(pk.pk)
		rs2 := reflect.New(rs.Type()).Elem()
		rs2.Set(rs)

		// access the second field
		rf := reflect.Indirect(rs2).Field(1)
		rf = reflect.NewAt(rf.Type(), unsafe.Pointer(rf.UnsafeAddr())).Elem()

		// copy the inner value into an ecdsa.PublicKey
		var inner ecdsa.PublicKey
		ri := reflect.ValueOf(&inner).Elem()
		ri.Set(rf)
		return &inner

	case ssh.KeyAlgoSKED25519:
		// use reflection to access the inner (unexported) ed25519.PublicKey
		rs := reflect.ValueOf(pk.pk)
		rs2 := reflect.New(rs.Type()).Elem()
		rs2.Set(rs)

		// access the second field
		rf := reflect.Indirect(rs2).Field(1)
		rf = reflect.NewAt(rf.Type(), unsafe.Pointer(rf.UnsafeAddr())).Elem()

		// copy the inner value into an ecdsa.PublicKey
		var inner ed25519.PublicKey
		ri := reflect.ValueOf(&inner).Elem()
		ri.Set(rf)
		return &inner

	default:
		panic(errors.New("unknown key type"))
	}
}
