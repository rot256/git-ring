package ring

import (
	"crypto/sha512"
	"encoding/binary"
	"hash"

	"golang.org/x/crypto/hkdf"
)

type transcript struct {
	h hash.Hash
}

func NewTranscript() *transcript {
	return &transcript{
		h: sha512.New(),
	}
}

func (tx *transcript) Append(bs []byte) {
	err := binary.Write(tx.h, binary.LittleEndian, uint64(len(bs)))
	if err != nil {
		panic(err)
	}
	tx.h.Write(bs)
}

func (tx *transcript) Challenge() challenge {

	// expand digest using HKDF
	expand := hkdf.New(
		sha512.New,
		tx.h.Sum([]byte{}),
		[]byte{},
		[]byte("transcript-hkdf"),
	)

	var chal challenge
	if err := chal.Read(expand); err != nil {
		panic(err)
	}
	return chal
}
