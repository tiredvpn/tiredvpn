package detect

import (
	"math"
	"testing"
)

// arbiterVector is one window together with the three distances ndpiReader
// printed for it. These are not hand-computed: they were captured from an
// instrumented nDPI 5.1.0 reading the B1 stand captures
// (/tmp/b1stand/b1-{443,995}-{edge,firefox}.pcap, 2026-08-25), which makes them
// an independent check rather than a restatement of our own arithmetic.
type arbiterVector struct {
	bytes  [4]uint32
	tls12  float64
	tls13  float64
	chrome float64
}

var arbiterVectors = []arbiterVector{
	{[4]uint32{216, 222, 77, 31}, 4.218, 4.465, 5.563},
	{[4]uint32{77, 31, 113, 2232}, 14.898, 5.052, 5.907},
	{[4]uint32{336, 319, 77, 31}, 4.671, 4.062, 5.283},
	{[4]uint32{77, 31, 112, 49507}, 372.086, 15.087, 16.351},
	{[4]uint32{400, 207, 77, 31}, 5.317, 4.005, 5.218},
	{[4]uint32{77, 31, 113, 2262}, 15.116, 5.053, 5.908},
	{[4]uint32{388, 422, 77, 31}, 5.087, 3.864, 5.133},
	{[4]uint32{190, 462, 77, 31}, 4.080, 4.382, 5.503},
	{[4]uint32{419, 407, 77, 31}, 5.426, 3.812, 5.082},
	{[4]uint32{257, 344, 77, 31}, 4.213, 4.256, 5.425},
	{[4]uint32{355, 345, 77, 31}, 4.814, 3.997, 5.234},
	{[4]uint32{477, 485, 77, 31}, 6.091, 3.649, 4.934},
	{[4]uint32{507, 530, 77, 31}, 6.466, 3.570, 4.855},
	{[4]uint32{77, 31, 112, 49499}, 372.026, 15.085, 16.348},
	{[4]uint32{416, 378, 29, 7}, 5.987, 3.847, 5.110},
	{[4]uint32{29, 7, 89, 2214}, 14.862, 5.244, 6.018},
	{[4]uint32{368, 143, 29, 7}, 5.633, 4.128, 5.318},
	{[4]uint32{29, 7, 88, 49307}, 370.520, 15.092, 16.330},
	{[4]uint32{496, 299, 29, 7}, 6.939, 3.778, 5.002},
	{[4]uint32{169, 121, 29, 7}, 4.910, 4.689, 5.711},
	{[4]uint32{272, 427, 29, 7}, 4.858, 4.160, 5.363},
	{[4]uint32{424, 174, 29, 7}, 6.158, 3.992, 5.198},
	{[4]uint32{133, 514, 29, 7}, 4.802, 4.550, 5.603},
	{[4]uint32{270, 416, 29, 7}, 4.855, 4.174, 5.372},
	{[4]uint32{29, 7, 88, 49315}, 370.581, 15.095, 16.332},
	{[4]uint32{119, 231, 29, 7}, 5.019, 4.783, 5.759},
	{[4]uint32{29, 7, 89, 2208}, 14.819, 5.244, 6.018},
	{[4]uint32{491, 176, 29, 7}, 6.923, 3.884, 5.076},
	{[4]uint32{206, 481, 29, 7}, 4.676, 4.324, 5.470},
	{[4]uint32{510, 295, 29, 7}, 7.116, 3.763, 4.979},
	{[4]uint32{329, 501, 29, 7}, 5.150, 3.951, 5.216},
	{[4]uint32{426, 447, 29, 7}, 6.065, 3.774, 5.056},
	{[4]uint32{478, 306, 29, 7}, 6.716, 3.798, 5.031},
	{[4]uint32{521, 125, 29, 7}, 7.317, 3.888, 5.050},
	{[4]uint32{349, 134, 29, 7}, 5.481, 4.177, 5.358},
	{[4]uint32{320, 216, 29, 7}, 5.230, 4.185, 5.372},
	{[4]uint32{252, 129, 29, 7}, 4.947, 4.431, 5.545},
	{[4]uint32{374, 507, 29, 7}, 5.518, 3.837, 5.126},
}

// TestAgreesWithNdpiReader is the trust anchor for this package. The package
// doc says ndpiReader stays the arbiter and that a disagreement is a bug here;
// this is the test that would catch such a bug.
//
// Tolerance is 0.01 because the arbiter prints float32 arithmetic through %f
// while this package computes in float64.
func TestAgreesWithNdpiReader(t *testing.T) {
	const tolerance = 0.01
	byName := map[string]Model{}
	for _, m := range Models() {
		byName[m.Name] = m
	}

	worst := 0.0
	for _, v := range arbiterVectors {
		for name, want := range map[string]float64{
			"tls12": v.tls12, "tls13": v.tls13, "chrome": v.chrome,
		} {
			m, ok := byName[name]
			if !ok {
				t.Fatalf("model %q missing", name)
			}
			got := m.Mahalanobis(v.bytes)
			if d := math.Abs(got - want); d > worst {
				worst = d
			}
			if math.Abs(got-want) > tolerance {
				t.Errorf("%v %s: ours %.4f, ndpiReader %.4f", v.bytes, name, got, want)
			}
		}
	}
	t.Logf("%d vectors checked, worst disagreement %.5f", len(arbiterVectors), worst)
}
