package strategy

// SingleFlightREALITYStrategy is an opt-in REALITY variant for testing whether
// serialising handshake starts across donor names helps on a specific path.
// Its wire protocol and server requirements are identical to REALITY.
type SingleFlightREALITYStrategy struct {
	*REALITYStrategy
}

func (s *SingleFlightREALITYStrategy) Name() string {
	return "REALITY Single Flight"
}

func (s *SingleFlightREALITYStrategy) ID() string {
	return "reality_singleflight"
}

func (s *SingleFlightREALITYStrategy) Priority() int {
	return 1000 // Experimental; select explicitly with -strategy.
}

func (s *SingleFlightREALITYStrategy) Description() string {
	return "REALITY with one TLS handshake at a time across all donor names"
}
