package main

type Proof interface {
	Marshal() []byte
	Unmarshal([]byte) error
	Commit(*Transcript)
	Verify(interface{}, Challenge) bool
}

type Prover interface {
	Finish(Challenge)
	Pf() Proof
}
