package main

import (
	"crypto/rand"
	"crypto/sha512"
	"io"

	"golang.org/x/crypto/hkdf"
)

const ChallengeSize = 32

type Challenge struct {
	Bytes []byte
}

func (c *Challenge) Read(r io.Reader) error {
	c.Bytes = make([]byte, ChallengeSize)
	_, err := r.Read(c.Bytes[:])
	return err
}

func (c *Challenge) Random() {
	c.Bytes = make([]byte, ChallengeSize)
	if _, err := rand.Read(c.Bytes[:]); err != nil {
		panic(err)
	}
}

func (c *Challenge) Take(n int) []byte {
	if len(c.Bytes) != ChallengeSize {
		panic("invalid challenge size")
	}

	// if challenge is big enough just return sub-slice
	if n <= len(c.Bytes) {
		return c.Bytes[:n]
	}

	// otherwise expand using HKDF (only used for RSA)
	out := make([]byte, n)
	expand := hkdf.New(
		sha512.New,
		c.Bytes[:],
		[]byte{},
		[]byte("challenge-hkdf"),
	)
	_, err := expand.Read(out)
	if err != nil {
		panic(err)
	}
	return out
}

func (c *Challenge) TakeZero(n int, len int) []byte {
	res := make([]byte, len)
	copy(res, c.Take(n))
	return res
}

func (c *Challenge) IsValid() bool {
	return len(c.Bytes) == ChallengeSize
}

// not constant time: only used in verification
func (c *Challenge) IsZero() bool {
	if len(c.Bytes) != ChallengeSize {
		panic("invalid challenge size")
	}
	for i := 0; i < ChallengeSize; i++ {
		if c.Bytes[i] != 0x00 {
			return false
		}
	}
	return true
}

func (c *Challenge) Add(c1 Challenge) {
	if len(c.Bytes) != ChallengeSize || len(c1.Bytes) != ChallengeSize {
		panic("invalid challenge size")
	}

	for i := range c.Bytes {
		c.Bytes[i] ^= c1.Bytes[i]
	}
}
