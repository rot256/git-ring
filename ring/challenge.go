package ring

import (
	"crypto/rand"
	"crypto/sha512"

	"golang.org/x/crypto/hkdf"
)

const challengeSize = 32

type challenge struct {
	bytes []byte
}

func (c *challenge) Random() {
	c.bytes = make([]byte, challengeSize)
	if _, err := rand.Read(c.bytes[:]); err != nil {
		panic(err)
	}
}

func (c *challenge) Take(n int) []byte {
	if len(c.bytes) != challengeSize {
		panic("invalid challenge size")
	}

	// if challenge is big enough just return sub-slice
	if n <= len(c.bytes) {
		return c.bytes[:n]
	}

	// otherwise expand using HKDF (only used for RSA)
	out := make([]byte, n)
	expand := hkdf.New(
		sha512.New,
		c.bytes[:],
		[]byte{},
		[]byte("challenge-hkdf"),
	)
	_, err := expand.Read(out)
	if err != nil {
		panic(err)
	}
	return out
}

func (c *challenge) TakeZero(n int, len int) []byte {
	res := make([]byte, len)
	copy(res, c.Take(n))
	return res
}

func (c *challenge) IsValid() bool {
	return len(c.bytes) == challengeSize
}

// not constant time: only used in verification
func (c *challenge) IsZero() bool {
	if len(c.bytes) != challengeSize {
		panic("invalid challenge size")
	}
	for i := 0; i < challengeSize; i++ {
		if c.bytes[i] != 0x00 {
			return false
		}
	}
	return true
}

func (c *challenge) Add(c1 challenge) {
	if len(c.bytes) != challengeSize || len(c1.bytes) != challengeSize {
		panic("invalid challenge size")
	}

	for i := range c.bytes {
		c.bytes[i] ^= c1.bytes[i]
	}
}
