package dist

import (
	"fmt"
	"math/rand/v2"
)

// MarkovState is a single state of a Markov burst process. The Value is what
// Next returns whenever the chain occupies this state.
type MarkovState struct {
	Name  string
	Value float64
}

// MarkovBurst is a discrete-time Markov chain. Each Next call advances the
// chain by one step using the supplied transition matrix and returns the
// current state's Value.
type MarkovBurst struct {
	states  []MarkovState
	cumRows [][]float64
	current int
	initial int
	seed1   uint64
	seed2   uint64
	pcg     *rand.PCG
	rng     *rand.Rand
}

// NewMarkovBurst constructs a Markov chain. transitions must be a square
// matrix sized len(states)×len(states); each row must sum to 1 (within a small
// tolerance) and have non-negative entries. The chain starts in state 0.
func NewMarkovBurst(states []MarkovState, transitions [][]float64, seed int64) (*MarkovBurst, error) {
	n := len(states)
	if n == 0 {
		return nil, fmt.Errorf("dist: markov requires at least one state")
	}
	if len(transitions) != n {
		return nil, fmt.Errorf("dist: transition matrix has %d rows, want %d", len(transitions), n)
	}

	cum := make([][]float64, n)
	for i, row := range transitions {
		if len(row) != n {
			return nil, fmt.Errorf("dist: row %d has %d entries, want %d", i, len(row), n)
		}
		cumRow := make([]float64, n)
		var sum float64
		for j, p := range row {
			if p < 0 {
				return nil, fmt.Errorf("dist: transitions[%d][%d] is negative", i, j)
			}
			sum += p
			cumRow[j] = sum
		}
		if sum < 0.999 || sum > 1.001 {
			return nil, fmt.Errorf("dist: row %d sums to %v, want 1", i, sum)
		}
		cumRow[n-1] = 1
		cum[i] = cumRow
	}

	statesCopy := make([]MarkovState, n)
	copy(statesCopy, states)

	s1, s2 := splitSeed(seed)
	pcg := rand.NewPCG(s1, s2)
	return &MarkovBurst{
		states:  statesCopy,
		cumRows: cum,
		current: 0,
		initial: 0,
		seed1:   s1,
		seed2:   s2,
		pcg:     pcg,
		rng:     rand.New(pcg),
	}, nil
}

// Next advances the chain by one step and returns the new state's Value.
func (m *MarkovBurst) Next() float64 {
	u := m.rng.Float64()
	row := m.cumRows[m.current]
	next := len(row) - 1
	for j, c := range row {
		if u <= c {
			next = j
			break
		}
	}
	m.current = next
	return m.states[m.current].Value
}

// State returns the name of the current state.
func (m *MarkovBurst) State() string {
	return m.states[m.current].Name
}

// Reset rewinds the RNG and returns the chain to its initial state.
func (m *MarkovBurst) Reset() {
	m.pcg.Seed(m.seed1, m.seed2)
	m.current = m.initial
}
