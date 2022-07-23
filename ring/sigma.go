package ring

type proof interface {
	Marshal() []byte
	Unmarshal([]byte) error
	Commit(*transcript)
	Verify(interface{}, challenge) bool
}

type prover interface {
	Finish(challenge)
	Pf() proof
}
