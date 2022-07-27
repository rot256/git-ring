package ring

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
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
	// compute digest
	hsh := tx.h.Sum([]byte{})
	if len(hsh) < challengeSize {
		panic(errors.New("challenge is bigger than digest"))
	}

	// copy hash prefix into challenge
	var chal challenge
	chal.Bytes = make([]byte, challengeSize)
	copy(chal.Bytes, hsh)
	return chal
}
