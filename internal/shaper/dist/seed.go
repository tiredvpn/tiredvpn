package dist

// splitSeed derives two 64-bit seeds from a single int64 input so that PCG
// receives distinct stream identifiers even when the caller passes 0.
func splitSeed(seed int64) (uint64, uint64) {
	s1 := uint64(seed)
	s2 := uint64(seed) ^ 0x9E3779B97F4A7C15
	return s1, s2
}
