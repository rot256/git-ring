package ring

import (
	"crypto/rand"
	"crypto/sha512"
	"math/big"

	"golang.org/x/crypto/hkdf"
)

const challengeSize = 32

type challenge struct {
	Bytes []byte
}

func (c *challenge) Random() {
	c.Bytes = make([]byte, challengeSize)
	if _, err := rand.Read(c.Bytes[:]); err != nil {
		panic(err)
	}
}

func (c *challenge) Int(tag string, mod *big.Int) *big.Int {
	bytes := (mod.BitLen() + 7) / 8
	random := (&big.Int{}).SetBytes(c.Take(tag, bytes*2))
	return random.Mod(random, mod)
}

func (c *challenge) Take(tag string, n int) []byte {
	if len(c.Bytes) != challengeSize {
		panic("invalid challenge size")
	}

	// expand challenge using HKDF
	out := make([]byte, n)
	expand := hkdf.New(
		sha512.New,
		c.Bytes[:],
		[]byte(tag),
		[]byte("challenge-hkdf"),
	)
	_, err := expand.Read(out)
	if err != nil {
		panic(err)
	}
	return out
}

func (c *challenge) IsValid() bool {
	return len(c.Bytes) == challengeSize
}

// not constant time: only used in verification
func (c *challenge) IsZero() bool {
	if len(c.Bytes) != challengeSize {
		panic("invalid challenge size")
	}
	for i := 0; i < challengeSize; i++ {
		if c.Bytes[i] != 0x00 {
			return false
		}
	}
	return true
}

func (c *challenge) Add(c1 challenge) {
	if len(c.Bytes) != challengeSize || len(c1.Bytes) != challengeSize {
		panic("invalid challenge size")
	}

	for i := range c.Bytes {
		c.Bytes[i] ^= c1.Bytes[i]
	}
}
