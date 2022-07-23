package main

import (
	"crypto/sha512"
	"encoding/binary"
	"hash"

	"golang.org/x/crypto/hkdf"
)

type Transcript struct {
	h hash.Hash
}

func NewTranscript() *Transcript {
	return &Transcript{
		h: sha512.New(),
	}
}

func (tx *Transcript) Append(bs []byte) {
	binary.Write(tx.h, binary.LittleEndian, len(bs))
	tx.h.Write(bs)
}

func (tx *Transcript) Challenge() Challenge {

	// expand digest using HKDF
	expand := hkdf.New(
		sha512.New,
		tx.h.Sum([]byte{}),
		[]byte{},
		[]byte("transcript-hkdf"),
	)

	var chal Challenge
	if err := chal.Read(expand); err != nil {
		panic(err)
	}
	return chal
}
