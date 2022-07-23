package main

type Proof interface {
	Marshal() []byte
	Commit(*Transcript)
	Verify(interface{}, Challenge) bool
}

type Prover interface {
	Finish(Challenge)
	Pf() Proof
}
