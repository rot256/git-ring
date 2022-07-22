package main

import "crypto/rand"

type Challenge struct {
	bytes []byte
}

func (c *Challenge) Zero(n int) {
	c.bytes = make([]byte, n)
}

func (c *Challenge) Random(n int) {
	c.bytes = make([]byte, n)
	if _, err := rand.Read(c.bytes); err != nil {
		panic(err)
	}
}

func (c *Challenge) Take(len int) []byte {
	return c.bytes[:len]
}

func (c *Challenge) TakeZero(n int, len int) []byte {
	res := make([]byte, len)
	copy(res, c.Take(n))
	return res
}

func (c *Challenge) Add(c1 Challenge) {
	if len(c.bytes) != len(c1.bytes) {
		println(len(c.bytes), len(c1.bytes))
		panic("length of challenges not the same")
	}
	for i := range c.bytes {
		c.bytes[i] ^= c1.bytes[i]
	}
}
