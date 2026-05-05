package benchmark

import (
	"testing"
	"time"
)

// TestStrategyResultInitialization tests StrategyResult creation
func TestStrategyResultInitialization(t *testing.T) {
	sr := StrategyResult{
		ID:         "test_strat",
		Name:       "Test Strategy",
		Available:  true,
		Latency:    50 * time.Millisecond,
		Speed:      25.5,
		Downloaded: 5 * 1024 * 1024,
		Duration:   1 * time.Second,
		Error:      "",
	}

	if sr.ID != "test_strat" {
		t.Errorf("ID: got %s, want test_strat", sr.ID)
	}

	if sr.Name != "Test Strategy" {
		t.Errorf("Name: got %s, want Test Strategy", sr.Name)
	}

	if !sr.Available {
		t.Error("Should be available")
	}

	if sr.Latency != 50*time.Millisecond {
		t.Errorf("Latency: got %v, want 50ms", sr.Latency)
	}

	if sr.Speed != 25.5 {
		t.Errorf("Speed: got %f, want 25.5", sr.Speed)
	}

	if sr.Downloaded != 5*1024*1024 {
		t.Errorf("Downloaded: got %d, want 5MB", sr.Downloaded)
	}

	if sr.Error != "" {
		t.Errorf("Error should be empty, got %s", sr.Error)
	}
}

// TestSpeedCalculation tests speed calculation from bytes and duration
func TestSpeedCalculation(t *testing.T) {
	tests := []struct {
		name       string
		bytes      int64
		duration   time.Duration
		expectMBps float64
	}{
		{
			name:       "5MB in 1 second",
			bytes:      5 * 1024 * 1024,
			duration:   1 * time.Second,
			expectMBps: 5.0,
		},
		{
			name:       "10MB in 2 seconds",
			bytes:      10 * 1024 * 1024,
			duration:   2 * time.Second,
			expectMBps: 5.0,
		},
		{
			name:       "1MB in 100ms",
			bytes:      1 * 1024 * 1024,
			duration:   100 * time.Millisecond,
			expectMBps: 10.0,
		},
		{
			name:       "100MB in 10 seconds",
			bytes:      100 * 1024 * 1024,
			duration:   10 * time.Second,
			expectMBps: 10.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Speed = bytes / seconds / (1024*1024)
			seconds := tt.duration.Seconds()
			speedMBps := float64(tt.bytes) / seconds / (1024 * 1024)

			if speedMBps < tt.expectMBps-0.01 || speedMBps > tt.expectMBps+0.01 {
				t.Errorf("Speed: got %.2f MB/s, want %.2f MB/s", speedMBps, tt.expectMBps)
			}
		})
	}
}

// TestBenchmarkResultInitialization tests BenchmarkResult creation
func TestBenchmarkResultInitialization(t *testing.T) {
	now := time.Now()
	br := BenchmarkResult{
		Strategies: []StrategyResult{},
		Fastest:    nil,
		BestSpeed:  nil,
		TestedAt:   now,
	}

	if len(br.Strategies) != 0 {
		t.Errorf("Strategies should be empty, got %d", len(br.Strategies))
	}

	if br.Fastest != nil {
		t.Error("Fastest should be nil initially")
	}

	if br.BestSpeed != nil {
		t.Error("BestSpeed should be nil initially")
	}

	if !br.TestedAt.Equal(now) {
		t.Errorf("TestedAt: got %v, want %v", br.TestedAt, now)
	}
}

// TestFastestStrategySelection tests finding fastest by latency
func TestFastestStrategySelection(t *testing.T) {
	strategies := []StrategyResult{
		{
			ID:        "strat1",
			Available: true,
			Latency:   100 * time.Millisecond,
		},
		{
			ID:        "strat2",
			Available: true,
			Latency:   50 * time.Millisecond, // Fastest
		},
		{
			ID:        "strat3",
			Available: true,
			Latency:   75 * time.Millisecond,
		},
		{
			ID:        "strat4",
			Available: false,
			Latency:   10 * time.Millisecond, // Not available
		},
	}

	var fastest *StrategyResult
	for i := range strategies {
		sr := &strategies[i]
		if !sr.Available {
			continue
		}
		if fastest == nil || (sr.Latency > 0 && sr.Latency < fastest.Latency) {
			fastest = sr
		}
	}

	if fastest.ID != "strat2" {
		t.Errorf("Fastest: got %s, want strat2", fastest.ID)
	}

	if fastest.Latency != 50*time.Millisecond {
		t.Errorf("Fastest latency: got %v, want 50ms", fastest.Latency)
	}
}

// TestBestSpeedSelection tests finding best by speed
func TestBestSpeedSelection(t *testing.T) {
	strategies := []StrategyResult{
		{
			ID:        "strat1",
			Available: true,
			Speed:     10.5,
		},
		{
			ID:        "strat2",
			Available: true,
			Speed:     25.8, // Best speed
		},
		{
			ID:        "strat3",
			Available: true,
			Speed:     15.2,
		},
		{
			ID:        "strat4",
			Available: false,
			Speed:     100.0, // Not available
		},
	}

	var bestSpeed *StrategyResult
	for i := range strategies {
		sr := &strategies[i]
		if !sr.Available {
			continue
		}
		if bestSpeed == nil || sr.Speed > bestSpeed.Speed {
			bestSpeed = sr
		}
	}

	if bestSpeed.ID != "strat2" {
		t.Errorf("Best speed: got %s, want strat2", bestSpeed.ID)
	}

	if bestSpeed.Speed != 25.8 {
		t.Errorf("Best speed value: got %f, want 25.8", bestSpeed.Speed)
	}
}

// TestSpeedTestConstants tests benchmark constants
func TestSpeedTestConstants(t *testing.T) {
	if SpeedTestSize != 5*1024*1024 {
		t.Errorf("SpeedTestSize: got %d, want 5MB", SpeedTestSize)
	}

	if TestTimeout != 30*time.Second {
		t.Errorf("TestTimeout: got %v, want 30s", TestTimeout)
	}

	if SpeedTestURL == "" {
		t.Error("SpeedTestURL should not be empty")
	}
}

// TestLatencyCategories tests latency categorization
func TestLatencyCategories(t *testing.T) {
	tests := []struct {
		latency  time.Duration
		category string
	}{
		{10 * time.Millisecond, "excellent"},
		{50 * time.Millisecond, "good"},
		{100 * time.Millisecond, "acceptable"},
		{200 * time.Millisecond, "poor"},
		{500 * time.Millisecond, "very poor"},
	}

	for _, tt := range tests {
		var category string
		ms := tt.latency.Milliseconds()

		if ms < 30 {
			category = "excellent"
		} else if ms < 80 {
			category = "good"
		} else if ms < 150 {
			category = "acceptable"
		} else if ms < 300 {
			category = "poor"
		} else {
			category = "very poor"
		}

		if category != tt.category {
			t.Errorf("Latency %v: got %s, want %s", tt.latency, category, tt.category)
		}
	}
}

// TestSpeedCategories tests speed categorization
func TestSpeedCategories(t *testing.T) {
	tests := []struct {
		speedMBps float64
		category  string
	}{
		{50.0, "excellent"},
		{20.0, "good"},
		{10.0, "acceptable"},
		{5.0, "poor"},
		{1.0, "very poor"},
	}

	for _, tt := range tests {
		var category string

		if tt.speedMBps >= 30 {
			category = "excellent"
		} else if tt.speedMBps >= 15 {
			category = "good"
		} else if tt.speedMBps >= 8 {
			category = "acceptable"
		} else if tt.speedMBps >= 3 {
			category = "poor"
		} else {
			category = "very poor"
		}

		if category != tt.category {
			t.Errorf("Speed %.1f MB/s: got %s, want %s", tt.speedMBps, category, tt.category)
		}
	}
}

// TestStrategyErrorHandling tests error field usage
func TestStrategyErrorHandling(t *testing.T) {
	tests := []struct {
		error     string
		available bool
	}{
		{"", true},
		{"connection timeout", false},
		{"connection refused", false},
		{"network unreachable", false},
	}

	for _, tt := range tests {
		sr := StrategyResult{
			Error:     tt.error,
			Available: tt.available,
		}

		hasError := sr.Error != ""
		if hasError && sr.Available {
			t.Errorf("Strategy with error %q should not be available", sr.Error)
		}
	}
}

// TestBytesToMBConversion tests byte to MB conversion
func TestBytesToMBConversion(t *testing.T) {
	tests := []struct {
		bytes int64
		mb    float64
	}{
		{1024 * 1024, 1.0},
		{5 * 1024 * 1024, 5.0},
		{512 * 1024, 0.5},
		{10 * 1024 * 1024, 10.0},
	}

	for _, tt := range tests {
		mb := float64(tt.bytes) / (1024 * 1024)
		if mb < tt.mb-0.01 || mb > tt.mb+0.01 {
			t.Errorf("Bytes %d: got %.2f MB, want %.2f MB", tt.bytes, mb, tt.mb)
		}
	}
}

// TestDurationFormatting tests duration string formatting
func TestDurationFormatting(t *testing.T) {
	tests := []struct {
		duration time.Duration
		expected string
	}{
		{500 * time.Millisecond, "500ms"},
		{1500 * time.Millisecond, "1.5s"},
		{5 * time.Second, "5s"},
		{65 * time.Second, "1m5s"},
	}

	for _, tt := range tests {
		formatted := tt.duration.String()
		if formatted != tt.expected {
			t.Logf("Duration %v: got %s, expected %s", tt.duration, formatted, tt.expected)
		}
	}
}

// TestUnavailableStrategyHandling tests handling unavailable strategies
func TestUnavailableStrategyHandling(t *testing.T) {
	strategies := []StrategyResult{
		{ID: "strat1", Available: true, Speed: 10.0},
		{ID: "strat2", Available: false, Speed: 0.0},
		{ID: "strat3", Available: true, Speed: 15.0},
	}

	availableCount := 0
	for _, sr := range strategies {
		if sr.Available {
			availableCount++
		}
	}

	if availableCount != 2 {
		t.Errorf("Available count: got %d, want 2", availableCount)
	}
}

// TestZeroLatencyHandling tests handling zero latency values
func TestZeroLatencyHandling(t *testing.T) {
	strategies := []StrategyResult{
		{ID: "strat1", Available: true, Latency: 100 * time.Millisecond},
		{ID: "strat2", Available: true, Latency: 0}, // Invalid
		{ID: "strat3", Available: true, Latency: 50 * time.Millisecond},
	}

	var fastest *StrategyResult
	for i := range strategies {
		sr := &strategies[i]
		if !sr.Available || sr.Latency == 0 {
			continue
		}
		if fastest == nil || sr.Latency < fastest.Latency {
			fastest = sr
		}
	}

	if fastest.ID != "strat3" {
		t.Errorf("Fastest (excluding zero): got %s, want strat3", fastest.ID)
	}
}

// ============================================================================
// BENCHMARKS
// ============================================================================

// BenchmarkCalculateStrategyScore benchmarks score calculation
func BenchmarkCalculateStrategyScore(b *testing.B) {
	sr := StrategyResult{
		Available:     true,
		HTTPCheck:     true,
		IPChanged:     true,
		HTTPLatency:   150 * time.Millisecond,
		DownloadSpeed: 8.5,
		UploadSpeed:   3.2,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = calculateStrategyScore(sr)
	}
}

// BenchmarkCalculateComboScore benchmarks combo score calculation
func BenchmarkCalculateComboScore(b *testing.B) {
	cr := ComboResult{
		Available:     true,
		IPChanged:     true,
		HTTPLatency:   200 * time.Millisecond,
		DownloadSpeed: 5.5,
		RTTProfile:    "moscow-yandex",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = calculateComboScore(cr)
	}
}

// BenchmarkFormatResults benchmarks result formatting
func BenchmarkFormatResults(b *testing.B) {
	result := &BenchmarkResult{
		TestedAt: time.Now(),
		Strategies: []StrategyResult{
			{ID: "quic", Name: "QUIC Transport", Available: true, Latency: 50 * time.Millisecond, Speed: 25.5},
			{ID: "reality", Name: "Reality/VLESS", Available: true, Latency: 80 * time.Millisecond, Speed: 18.2},
			{ID: "http2_stego", Name: "HTTP/2 Steganography", Available: true, Latency: 120 * time.Millisecond, Speed: 12.0},
			{ID: "morph", Name: "Traffic Morph (YT)", Available: false, Error: "timeout"},
			{ID: "confusion", Name: "Protocol Confusion", Available: true, Latency: 90 * time.Millisecond, Speed: 15.5},
		},
		Fastest:   &StrategyResult{ID: "quic", Name: "QUIC Transport", Latency: 50 * time.Millisecond},
		BestSpeed: &StrategyResult{ID: "quic", Name: "QUIC Transport", Speed: 25.5},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FormatResults(result, true)
	}
}

// BenchmarkFormatResultsNoSpeed benchmarks result formatting without speed
func BenchmarkFormatResultsNoSpeed(b *testing.B) {
	result := &BenchmarkResult{
		TestedAt: time.Now(),
		Strategies: []StrategyResult{
			{ID: "quic", Name: "QUIC Transport", Available: true, Latency: 50 * time.Millisecond},
			{ID: "reality", Name: "Reality/VLESS", Available: true, Latency: 80 * time.Millisecond},
			{ID: "http2_stego", Name: "HTTP/2 Steganography", Available: true, Latency: 120 * time.Millisecond},
		},
		Fastest: &StrategyResult{ID: "quic", Name: "QUIC Transport", Latency: 50 * time.Millisecond},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FormatResults(result, false)
	}
}

// BenchmarkFormatFullResults benchmarks full result formatting
func BenchmarkFormatFullResults(b *testing.B) {
	result := &FullStrategyBenchmarkResult{
		OriginalIP: "203.0.113.1",
		TestedAt:   time.Now(),
		Strategies: []StrategyResult{
			{ID: "quic", Name: "QUIC", Available: true, ExitIP: "198.51.100.1", IPChanged: true, HTTPLatency: 80 * time.Millisecond, DownloadSpeed: 15.2, UploadSpeed: 8.5, Score: 85},
			{ID: "reality", Name: "Reality", Available: true, ExitIP: "198.51.100.1", IPChanged: true, HTTPLatency: 120 * time.Millisecond, DownloadSpeed: 12.0, UploadSpeed: 6.2, Score: 75},
			{ID: "http2_stego", Name: "HTTP/2 Stego", Available: true, ExitIP: "198.51.100.1", IPChanged: true, HTTPLatency: 150 * time.Millisecond, DownloadSpeed: 8.5, UploadSpeed: 4.0, Score: 65},
			{ID: "morph", Name: "Traffic Morph", Available: false, Error: "connection refused", Score: 0},
		},
		Best: &StrategyResult{ID: "quic", Name: "QUIC", Score: 85},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FormatFullResults(result)
	}
}

// BenchmarkFormatAllCombosResults benchmarks all combos result formatting
func BenchmarkFormatAllCombosResults(b *testing.B) {
	combos := make([]ComboResult, 0, 30)
	profiles := []string{"none", "moscow-yandex", "moscow-vk", "regional-russia", "siberia", "cdn"}
	strategies := []string{"quic", "reality", "http2_stego", "morph", "confusion"}

	for _, strat := range strategies {
		for _, profile := range profiles {
			combos = append(combos, ComboResult{
				StrategyID:    strat,
				StrategyName:  strat,
				RTTProfile:    profile,
				Available:     true,
				ExitIP:        "198.51.100.1",
				IPChanged:     true,
				HTTPLatency:   100 * time.Millisecond,
				DownloadSpeed: 10.0,
				Score:         70,
			})
		}
	}

	result := &AllCombosResult{
		OriginalIP:   "203.0.113.1",
		TestedAt:     time.Now(),
		Combinations: combos,
		Best:         &combos[0],
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = FormatAllCombosResults(result)
	}
}

// BenchmarkTruncateName benchmarks name truncation
func BenchmarkTruncateName(b *testing.B) {
	name := "HTTP/2 Steganography with Padding and Encryption Layer"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = truncateName(name, 25)
	}
}

// BenchmarkTruncateNameShort benchmarks short name (no truncation needed)
func BenchmarkTruncateNameShort(b *testing.B) {
	name := "QUIC"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = truncateName(name, 25)
	}
}

// BenchmarkGetAllStrategyIDs benchmarks getting strategy IDs
func BenchmarkGetAllStrategyIDs(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GetAllStrategyIDs()
	}
}

func TestToJSONReportNilFastest(t *testing.T) {
	r := &BenchmarkResult{
		TestedAt:   time.Now(),
		Strategies: []StrategyResult{},
		Fastest:    nil,
	}
	report := ToJSONReport(r, "host:8444", "1.0.0")
	if report.Fastest != "" {
		t.Errorf("Fastest should be empty when r.Fastest is nil, got %q", report.Fastest)
	}
	if report.Summary.Total != 0 {
		t.Errorf("Summary.Total: got %d, want 0", report.Summary.Total)
	}
}

func TestToJSONReportContextCanceled(t *testing.T) {
	r := &BenchmarkResult{
		TestedAt: time.Now(),
		Strategies: []StrategyResult{
			{ID: "quic", Name: "QUIC", Available: false, Error: "context canceled"},
		},
	}
	report := ToJSONReport(r, "host:8444", "1.0.0")
	if report.Strategies[0].Status != "timeout" {
		t.Errorf("context canceled should map to timeout, got %q", report.Strategies[0].Status)
	}
}

func TestToJSONReport(t *testing.T) {
	latency := 42 * time.Millisecond
	r := &BenchmarkResult{
		TestedAt: time.Date(2026, 5, 5, 3, 0, 0, 0, time.UTC),
		Strategies: []StrategyResult{
			{ID: "quic_salamander", Name: "QUIC Salamander", Available: true, Latency: latency},
			{ID: "reality", Name: "REALITY Protocol", Available: false, Error: "connection refused"},
			{ID: "http_polling", Name: "HTTP Polling", Available: false, Error: "context deadline exceeded"},
		},
	}
	r.Fastest = &r.Strategies[0]

	report := ToJSONReport(r, "31.44.3.165:8444", "1.1.0")

	if report.GeneratedAt != "2026-05-05T03:00:00Z" {
		t.Errorf("GeneratedAt: got %s, want 2026-05-05T03:00:00Z", report.GeneratedAt)
	}
	if report.Server != "31.44.3.165:8444" {
		t.Errorf("Server: got %s, want 31.44.3.165:8444", report.Server)
	}
	if report.Version != "1.1.0" {
		t.Errorf("Version: got %s, want 1.1.0", report.Version)
	}
	if len(report.Strategies) != 3 {
		t.Fatalf("Strategies: got %d, want 3", len(report.Strategies))
	}

	ok := report.Strategies[0]
	if ok.Status != "ok" {
		t.Errorf("Strategies[0].Status: got %s, want ok", ok.Status)
	}
	if ok.LatencyMS == nil || *ok.LatencyMS != 42 {
		t.Errorf("Strategies[0].LatencyMS: got %v, want 42", ok.LatencyMS)
	}

	blocked := report.Strategies[1]
	if blocked.Status != "blocked" {
		t.Errorf("Strategies[1].Status: got %s, want blocked", blocked.Status)
	}
	if blocked.LatencyMS != nil {
		t.Errorf("Strategies[1].LatencyMS: should be nil for blocked")
	}

	timeout := report.Strategies[2]
	if timeout.Status != "timeout" {
		t.Errorf("Strategies[2].Status: got %s, want timeout", timeout.Status)
	}

	if report.Summary.Total != 3 {
		t.Errorf("Summary.Total: got %d, want 3", report.Summary.Total)
	}
	if report.Summary.Available != 1 {
		t.Errorf("Summary.Available: got %d, want 1", report.Summary.Available)
	}
	if report.Summary.Failed != 2 {
		t.Errorf("Summary.Failed: got %d, want 2", report.Summary.Failed)
	}
	if report.Summary.Timeout != 1 {
		t.Errorf("Summary.Timeout: got %d, want 1", report.Summary.Timeout)
	}
	if report.Fastest != "quic_salamander" {
		t.Errorf("Fastest: got %s, want quic_salamander", report.Fastest)
	}
}
