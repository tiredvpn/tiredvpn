package toml

import (
	"strings"
	"testing"
)

func TestShaperValidate_NeitherPresetNorCustom(t *testing.T) {
	s := &ShaperConfig{}
	err := s.validate()
	if err == nil || !strings.Contains(err.Error(), "either preset or custom") {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestShaperValidate_PresetAndCustom(t *testing.T) {
	s := &ShaperConfig{
		Preset: "x",
		Custom: &ShaperCustom{},
	}
	err := s.validate()
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestShaperValidate_RandomizationRange(t *testing.T) {
	for _, r := range []float64{-0.1, 1.0, 1.5} {
		s := &ShaperConfig{Preset: "x", RandomizationRange: r}
		if err := s.validate(); err == nil {
			t.Fatalf("range %v should fail", r)
		}
	}
}

func TestShaperValidate_NilOK(t *testing.T) {
	var s *ShaperConfig
	if err := s.validate(); err != nil {
		t.Fatalf("nil shaper should validate: %v", err)
	}
}

func TestHistogramValidate(t *testing.T) {
	cases := []struct {
		name string
		h    HistogramDist
		want string
	}{
		{"empty", HistogramDist{}, "empty"},
		{"all zero", HistogramDist{Bins: []HistogramBin{{Value: 1, Weight: 0}}}, "positive"},
		{"negative", HistogramDist{Bins: []HistogramBin{{Value: 1, Weight: -1}}}, "negative"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.h.validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want substring %q", err, tc.want)
			}
		})
	}
	ok := HistogramDist{Bins: []HistogramBin{{Value: 1, Weight: 1}}}
	if err := ok.validate(); err != nil {
		t.Fatalf("ok case failed: %v", err)
	}
}

func TestParetoValidate(t *testing.T) {
	if err := (&ParetoDist{Xm: 0, Alpha: 1}).validate(); err == nil {
		t.Fatal("xm=0 should fail")
	}
	if err := (&ParetoDist{Xm: 1, Alpha: 0}).validate(); err == nil {
		t.Fatal("alpha=0 should fail")
	}
	if err := (&ParetoDist{Xm: 1, Alpha: 1}).validate(); err != nil {
		t.Fatalf("ok: %v", err)
	}
}

func TestLogNormalValidate(t *testing.T) {
	if err := (&LogNormalDist{Sigma: -0.1}).validate(); err == nil {
		t.Fatal("negative sigma should fail")
	}
	if err := (&LogNormalDist{Sigma: 0}).validate(); err != nil {
		t.Fatalf("sigma=0 ok: %v", err)
	}
}

func TestMarkovValidate_StochasticMatrix(t *testing.T) {
	good := MarkovDist{
		States:      []MarkovState{{Name: "a", Value: 0}, {Name: "b", Value: 1}},
		Transitions: [][]float64{{0.7, 0.3}, {0.4, 0.6}},
	}
	if err := good.validate(); err != nil {
		t.Fatalf("good failed: %v", err)
	}

	notSquare := MarkovDist{
		States:      []MarkovState{{}, {}},
		Transitions: [][]float64{{0.5, 0.5}},
	}
	if err := notSquare.validate(); err == nil {
		t.Fatal("non-square should fail")
	}

	rowMismatch := MarkovDist{
		States:      []MarkovState{{}, {}},
		Transitions: [][]float64{{0.5, 0.5}, {1.0}},
	}
	if err := rowMismatch.validate(); err == nil {
		t.Fatal("row length mismatch should fail")
	}

	negative := MarkovDist{
		States:      []MarkovState{{}, {}},
		Transitions: [][]float64{{1.1, -0.1}, {0.5, 0.5}},
	}
	if err := negative.validate(); err == nil {
		t.Fatal("negative entry should fail")
	}

	notStochastic := MarkovDist{
		States:      []MarkovState{{}, {}},
		Transitions: [][]float64{{0.5, 0.4}, {0.5, 0.5}},
	}
	if err := notStochastic.validate(); err == nil {
		t.Fatal("row sum 0.9 should fail")
	}

	withinTol := MarkovDist{
		States:      []MarkovState{{}, {}},
		Transitions: [][]float64{{0.5005, 0.4995}, {0.5, 0.5}},
	}
	if err := withinTol.validate(); err != nil {
		t.Fatalf("within tolerance should pass: %v", err)
	}

	empty := MarkovDist{}
	if err := empty.validate(); err == nil {
		t.Fatal("empty should fail")
	}
}

func TestDistConfig_TypeMismatch(t *testing.T) {
	d := DistConfig{Type: DistHistogram}
	if err := d.validate(); err == nil {
		t.Fatal("missing histogram block should fail")
	}
	d = DistConfig{Type: "bogus"}
	if err := d.validate(); err == nil {
		t.Fatal("unknown type should fail")
	}
	d = DistConfig{}
	if err := d.validate(); err == nil {
		t.Fatal("missing type should fail")
	}
}

func TestClientValidate(t *testing.T) {
	c := &ClientConfig{}
	if err := c.Validate(); err == nil {
		t.Fatal("empty client should fail")
	}
	c = &ClientConfig{Server: ClientServer{Address: "x", Port: 0}, Strategy: Strategy{Mode: "x"}}
	if err := c.Validate(); err == nil {
		t.Fatal("port 0 should fail")
	}
	c = &ClientConfig{Server: ClientServer{Address: "x", Port: 80}, Strategy: Strategy{Mode: ""}}
	if err := c.Validate(); err == nil {
		t.Fatal("empty mode should fail")
	}
	c = &ClientConfig{Server: ClientServer{Address: "x", Port: 80}, Strategy: Strategy{Mode: "y"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("ok client failed: %v", err)
	}
}

func TestServerValidate(t *testing.T) {
	good := &ServerConfig{
		Listen:   ServerListen{Address: "0.0.0.0", Port: 443},
		Strategy: Strategy{Mode: "reality"},
		TLS:      ServerTLS{CertFile: "c", KeyFile: "k"},
		Auth:     ServerAuth{Mode: "token"},
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("good failed: %v", err)
	}
	bad := *good
	bad.Listen.Address = ""
	if err := bad.Validate(); err == nil {
		t.Fatal("empty listen.address should fail")
	}
	bad = *good
	bad.TLS.CertFile = ""
	if err := bad.Validate(); err == nil {
		t.Fatal("missing cert should fail")
	}
	bad = *good
	bad.TLS.KeyFile = ""
	if err := bad.Validate(); err == nil {
		t.Fatal("missing key should fail")
	}
	bad = *good
	bad.Auth.Mode = ""
	if err := bad.Validate(); err == nil {
		t.Fatal("missing auth.mode should fail")
	}
	bad = *good
	bad.Listen.Port = 70000
	if err := bad.Validate(); err == nil {
		t.Fatal("port 70000 should fail")
	}
}
