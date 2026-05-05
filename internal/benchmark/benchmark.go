package benchmark

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tiredvpn/tiredvpn/internal/strategy"
	"golang.org/x/net/proxy"
)

// TestURL for speed testing - Ubuntu NL mirror (close to most EU servers)
const (
	SpeedTestURL  = "http://nl.archive.ubuntu.com/ubuntu/pool/main/b/base-files/base-files_13ubuntu10.1_amd64.deb"
	SpeedTestSize = 5 * 1024 * 1024  // 5MB per strategy
	TestTimeout   = 30 * time.Second // 30s timeout per strategy
)

// StrategyResult holds benchmark results for a strategy
type StrategyResult struct {
	ID         string
	Name       string
	Available  bool
	Latency    time.Duration
	Speed      float64 // MB/s
	Downloaded int64   // bytes
	Duration   time.Duration
	Error      string

	// Extended test results
	HTTPCheck     bool          `json:"http_check"`
	ExitIP        string        `json:"exit_ip"`
	IPChanged     bool          `json:"ip_changed"`
	HTTPLatency   time.Duration `json:"http_latency"`
	DownloadSpeed float64       `json:"download_mbps"`
	UploadSpeed   float64       `json:"upload_mbps"`
	Score         int           `json:"score"`
}

// BenchmarkResult holds all benchmark results
type BenchmarkResult struct {
	Strategies []StrategyResult
	Fastest    *StrategyResult
	BestSpeed  *StrategyResult
	TestedAt   time.Time
}

// JSONStrategyResult is the JSON-serializable form of a single strategy probe result.
type JSONStrategyResult struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"` // "ok", "blocked", "timeout"
	LatencyMS *int64 `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

// JSONSummary aggregates counts across all strategies.
type JSONSummary struct {
	Total     int `json:"total"`
	Available int `json:"available"`
	Failed    int `json:"failed"`
	Timeout   int `json:"timeout"`
}

// JSONReport is the top-level structure written to stdout by -benchmark-json.
type JSONReport struct {
	GeneratedAt string               `json:"generated_at"`
	Server      string               `json:"server"`
	Version     string               `json:"version"`
	Strategies  []JSONStrategyResult `json:"strategies"`
	Summary     JSONSummary          `json:"summary"`
	Fastest     string               `json:"fastest,omitempty"`
}

// strategyStatus converts an internal StrategyResult to the string status used in reports.
func strategyStatus(sr StrategyResult) string {
	if sr.Available {
		return "ok"
	}
	if strings.Contains(sr.Error, "timeout") ||
		strings.Contains(sr.Error, "deadline exceeded") ||
		strings.Contains(sr.Error, "context canceled") {
		return "timeout"
	}
	return "blocked"
}

// ToJSONReport converts a BenchmarkResult into a JSON-serializable report.
func ToJSONReport(r *BenchmarkResult, serverAddr, version string) JSONReport {
	report := JSONReport{
		GeneratedAt: r.TestedAt.UTC().Format(time.RFC3339),
		Server:      serverAddr,
		Version:     version,
	}

	var summary JSONSummary
	summary.Total = len(r.Strategies)

	for _, sr := range r.Strategies {
		status := strategyStatus(sr)
		jsr := JSONStrategyResult{
			ID:     sr.ID,
			Name:   sr.Name,
			Status: status,
			Error:  sr.Error,
		}
		if sr.Available {
			ms := sr.Latency.Milliseconds()
			jsr.LatencyMS = &ms
		}
		report.Strategies = append(report.Strategies, jsr)

		switch status {
		case "ok":
			summary.Available++
		case "timeout":
			summary.Failed++
			summary.Timeout++
		default:
			summary.Failed++
		}
	}

	if r.Fastest != nil {
		report.Fastest = r.Fastest.ID
	}
	report.Summary = summary
	return report
}

// RunBenchmark tests all strategies for latency and speed
func RunBenchmark(ctx context.Context, mgr *strategy.Manager, serverAddr string, testSpeed bool) *BenchmarkResult {
	result := &BenchmarkResult{
		TestedAt: time.Now(),
	}

	strategies := mgr.GetOrderedStrategies()

	// Test each strategy
	for i, strat := range strategies {
		if testSpeed {
			fmt.Printf("  [%d/%d] Testing %s...", i+1, len(strategies), strat.Name())
		}
		sr := testStrategy(ctx, mgr, strat, serverAddr, testSpeed)
		result.Strategies = append(result.Strategies, sr)
		if testSpeed {
			if sr.Speed > 0 {
				fmt.Printf(" %.1f MB/s\n", sr.Speed)
			} else if sr.Error != "" {
				fmt.Printf(" FAILED (%s)\n", sr.Error)
			} else {
				fmt.Printf(" OK\n")
			}
		}
	}

	// Find fastest latency and best speed
	for i := range result.Strategies {
		sr := &result.Strategies[i]
		if !sr.Available {
			continue
		}

		if result.Fastest == nil || (sr.Latency > 0 && sr.Latency < result.Fastest.Latency) {
			result.Fastest = sr
		}

		if testSpeed && (result.BestSpeed == nil || sr.Speed > result.BestSpeed.Speed) {
			result.BestSpeed = sr
		}
	}

	return result
}

func testStrategy(ctx context.Context, mgr *strategy.Manager, strat strategy.Strategy, serverAddr string, testSpeed bool) StrategyResult {
	sr := StrategyResult{
		ID:   strat.ID(),
		Name: strat.Name(),
	}

	// Test latency with probe
	start := time.Now()
	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	conn, err := strat.Connect(probeCtx, serverAddr)
	cancel()

	if err != nil {
		sr.Available = false
		sr.Error = err.Error()
		return sr
	}

	sr.Available = true
	sr.Latency = time.Since(start)
	conn.Close()

	// Test speed if requested
	if testSpeed {
		sr.Speed, sr.Downloaded, sr.Duration, sr.Error = testStrategySpeed(ctx, strat, serverAddr)
	}

	return sr
}

func testStrategySpeed(ctx context.Context, strat strategy.Strategy, serverAddr string) (speed float64, downloaded int64, duration time.Duration, errStr string) {
	// Connect directly via this strategy
	connCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	conn, err := strat.Connect(connCtx, serverAddr)
	cancel()

	if err != nil {
		errStr = fmt.Sprintf("connect: %v", err)
		return
	}
	defer conn.Close()

	// Send target address (speed test URL host)
	targetAddr := "nl.archive.ubuntu.com:80"
	addrBytes := []byte(targetAddr)
	addrPacket := make([]byte, 2+len(addrBytes))
	addrPacket[0] = byte(len(addrBytes) >> 8)
	addrPacket[1] = byte(len(addrBytes))
	copy(addrPacket[2:], addrBytes)

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(addrPacket); err != nil {
		errStr = fmt.Sprintf("write addr: %v", err)
		return
	}

	// Read response
	resp := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, resp); err != nil {
		errStr = fmt.Sprintf("read resp: %v", err)
		return
	}

	if resp[0] != 0x00 {
		errStr = "server rejected"
		return
	}

	// Send HTTP request
	httpReq := fmt.Sprintf("GET /ubuntu/pool/main/b/base-files/base-files_13ubuntu10.1_amd64.deb HTTP/1.1\r\nHost: nl.archive.ubuntu.com\r\nConnection: close\r\nRange: bytes=0-%d\r\n\r\n", SpeedTestSize-1)

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(httpReq)); err != nil {
		errStr = fmt.Sprintf("write http: %v", err)
		return
	}

	// Read response and measure speed
	start := time.Now()
	buf := make([]byte, 32*1024)
	headerDone := false
	var totalRead int64

	conn.SetReadDeadline(time.Now().Add(TestTimeout))

	for totalRead < SpeedTestSize {
		n, err := conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			if totalRead > 0 {
				break // Got some data, that's ok
			}
			errStr = fmt.Sprintf("read: %v", err)
			return
		}

		if !headerDone {
			// Skip HTTP headers
			data := string(buf[:n])
			if idx := strings.Index(data, "\r\n\r\n"); idx >= 0 {
				headerDone = true
				totalRead += int64(n - idx - 4)
			}
		} else {
			totalRead += int64(n)
		}
	}

	duration = time.Since(start)
	downloaded = totalRead

	if duration > 0 {
		speed = float64(downloaded) / duration.Seconds() / (1024 * 1024) // MB/s
	}

	return
}

// FormatResults formats benchmark results as a nice table
func FormatResults(r *BenchmarkResult, showSpeed bool) string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString("╔══════════════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║                    TiredVPN Strategy Benchmark                       ║\n")
	sb.WriteString("╠══════════════════════════════════════════════════════════════════════╣\n")

	// Sort by latency for display
	sorted := make([]StrategyResult, len(r.Strategies))
	copy(sorted, r.Strategies)
	sort.Slice(sorted, func(i, j int) bool {
		if !sorted[i].Available && !sorted[j].Available {
			return sorted[i].Name < sorted[j].Name
		}
		if !sorted[i].Available {
			return false
		}
		if !sorted[j].Available {
			return true
		}
		return sorted[i].Latency < sorted[j].Latency
	})

	if showSpeed {
		sb.WriteString("║  #  │ Strategy                    │ Latency │  Speed  │ Status     ║\n")
		sb.WriteString("╟─────┼─────────────────────────────┼─────────┼─────────┼────────────╢\n")
	} else {
		sb.WriteString("║  #  │ Strategy                         │ Latency  │ Status          ║\n")
		sb.WriteString("╟─────┼──────────────────────────────────┼──────────┼─────────────────╢\n")
	}

	for i, sr := range sorted {
		status := "✓ OK"
		if !sr.Available {
			status = "✗ FAIL"
		}

		latStr := "-"
		if sr.Latency > 0 {
			latStr = fmt.Sprintf("%dms", sr.Latency.Milliseconds())
		}

		if showSpeed {
			speedStr := "-"
			if sr.Speed > 0 {
				speedStr = fmt.Sprintf("%.1fMB/s", sr.Speed)
			}
			fmt.Fprintf(&sb, "║ %2d  │ %-27s │ %7s │ %7s │ %-10s ║\n",
				i+1, truncateName(sr.Name, 27), latStr, speedStr, status)
		} else {
			fmt.Fprintf(&sb, "║ %2d  │ %-32s │ %8s │ %-15s ║\n",
				i+1, truncateName(sr.Name, 32), latStr, status)
		}

		// Show error message for failed strategies
		if !sr.Available && sr.Error != "" {
			// Wrap long error messages
			errLines := wrapText(sr.Error, 62)
			for idx, line := range errLines {
				if idx == 0 {
					fmt.Fprintf(&sb, "║     │ Error: %-56s ║\n", line)
				} else {
					fmt.Fprintf(&sb, "║     │        %-56s ║\n", line)
				}
			}
		}
	}

	sb.WriteString("╠══════════════════════════════════════════════════════════════════════╣\n")

	// Summary
	available := 0
	for _, sr := range r.Strategies {
		if sr.Available {
			available++
		}
	}

	fmt.Fprintf(&sb, "║ Available: %d/%d strategies                                          ║\n",
		available, len(r.Strategies))

	if r.Fastest != nil {
		fmt.Fprintf(&sb, "║ Fastest:   %-40s %dms          ║\n",
			truncateName(r.Fastest.Name, 40), r.Fastest.Latency.Milliseconds())
	}

	if showSpeed && r.BestSpeed != nil && r.BestSpeed.Speed > 0 {
		fmt.Fprintf(&sb, "║ Best Speed: %-24s (%.1f MB/s)                 ║\n",
			truncateName(r.BestSpeed.Name, 24), r.BestSpeed.Speed)
	}

	sb.WriteString("╚══════════════════════════════════════════════════════════════════════╝\n")

	return sb.String()
}

func truncateName(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func wrapText(text string, maxLen int) []string {
	if len(text) <= maxLen {
		return []string{text}
	}

	var lines []string
	for len(text) > maxLen {
		// Try to break at space
		breakAt := maxLen
		for i := maxLen - 1; i > maxLen/2; i-- {
			if text[i] == ' ' {
				breakAt = i
				break
			}
		}
		lines = append(lines, text[:breakAt])
		text = text[breakAt:]
		// Trim leading space from continuation
		if len(text) > 0 && text[0] == ' ' {
			text = text[1:]
		}
	}
	if len(text) > 0 {
		lines = append(lines, text)
	}
	return lines
}

// QuickProbe does a fast latency-only test of all strategies
func QuickProbe(ctx context.Context, mgr *strategy.Manager, serverAddr string) *BenchmarkResult {
	return RunBenchmark(ctx, mgr, serverAddr, false)
}

// FullBenchmark does latency + speed test of all strategies
func FullBenchmark(ctx context.Context, mgr *strategy.Manager, serverAddr string) *BenchmarkResult {
	return RunBenchmark(ctx, mgr, serverAddr, true)
}

// ParallelProbe probes all strategies in parallel for speed
func ParallelProbe(ctx context.Context, mgr *strategy.Manager, serverAddr string) *BenchmarkResult {
	result := &BenchmarkResult{
		TestedAt: time.Now(),
	}

	strategies := mgr.GetOrderedStrategies()
	results := make([]StrategyResult, len(strategies))

	var wg sync.WaitGroup
	for i, strat := range strategies {
		wg.Add(1)
		go func(idx int, s strategy.Strategy) {
			defer wg.Done()
			results[idx] = testStrategy(ctx, mgr, s, serverAddr, false)
		}(i, strat)
	}
	wg.Wait()

	result.Strategies = results

	// Find fastest
	for i := range result.Strategies {
		sr := &result.Strategies[i]
		if sr.Available && (result.Fastest == nil || sr.Latency < result.Fastest.Latency) {
			result.Fastest = sr
		}
	}

	return result
}

// FullStrategyBenchmarkResult holds comprehensive benchmark results
type FullStrategyBenchmarkResult struct {
	OriginalIP string
	Strategies []StrategyResult
	Best       *StrategyResult
	TestedAt   time.Time
}

// GetOriginalIP fetches your original IP without any proxy
func GetOriginalIP(ctx context.Context) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org?format=json", nil)
	if err != nil {
		return "", err
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result.IP, nil
}

// RunFullStrategyBenchmark tests all strategies via SOCKS5 proxy
// Tests: HTTP availability, exit IP, latency, download/upload speed
func RunFullStrategyBenchmark(ctx context.Context, socksAddr string, strategies []string, originalIP string) *FullStrategyBenchmarkResult {
	result := &FullStrategyBenchmarkResult{
		OriginalIP: originalIP,
		TestedAt:   time.Now(),
	}

	for i, stratID := range strategies {
		fmt.Printf("  [%d/%d] Testing %s...\n", i+1, len(strategies), stratID)
		sr := testStrategyViaSocks(ctx, socksAddr, stratID, originalIP)
		result.Strategies = append(result.Strategies, sr)

		// Print quick result
		if sr.Available {
			fmt.Printf("         ✓ HTTP OK, Exit IP: %s", sr.ExitIP)
			if sr.IPChanged {
				fmt.Printf(" (CHANGED)")
			}
			fmt.Printf(", Latency: %dms", sr.HTTPLatency.Milliseconds())
			if sr.DownloadSpeed > 0 {
				fmt.Printf(", DL: %.1f MB/s", sr.DownloadSpeed)
			}
			if sr.UploadSpeed > 0 {
				fmt.Printf(", UL: %.1f MB/s", sr.UploadSpeed)
			}
			fmt.Printf(", Score: %d/100\n", sr.Score)
		} else {
			fmt.Printf("         ✗ FAILED: %s\n", sr.Error)
		}
	}

	// Find best by score
	for i := range result.Strategies {
		sr := &result.Strategies[i]
		if sr.Available && (result.Best == nil || sr.Score > result.Best.Score) {
			result.Best = sr
		}
	}

	return result
}

func testStrategyViaSocks(ctx context.Context, socksAddr, strategyID, originalIP string) StrategyResult {
	sr := StrategyResult{
		ID:   strategyID,
		Name: strategyID,
	}

	// Create SOCKS5 dialer
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		sr.Error = fmt.Sprintf("socks5 dialer: %v", err)
		return sr
	}

	// Create HTTP client with SOCKS5 proxy
	transport := &http.Transport{
		Dial: dialer.Dial,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// Test 1: HTTP availability and get exit IP
	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org?format=json", nil)
	resp, err := client.Do(req)
	if err != nil {
		sr.Error = fmt.Sprintf("http check: %v", err)
		return sr
	}
	defer resp.Body.Close()

	var ipResult struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ipResult); err != nil {
		sr.Error = fmt.Sprintf("decode ip: %v", err)
		return sr
	}

	sr.HTTPCheck = true
	sr.HTTPLatency = time.Since(start)
	sr.ExitIP = ipResult.IP
	sr.IPChanged = (ipResult.IP != originalIP)
	sr.Available = true
	sr.Latency = sr.HTTPLatency

	// Test 2: Download speed (5MB)
	sr.DownloadSpeed = measureDownloadSpeed(ctx, client)

	// Test 3: Upload speed (1MB)
	sr.UploadSpeed = measureUploadSpeed(ctx, client)

	// Calculate score
	sr.Score = calculateStrategyScore(sr)

	return sr
}

func measureDownloadSpeed(ctx context.Context, client *http.Client) float64 {
	// Use a reliable speed test file
	url := "http://speedtest.tele2.net/1MB.zip"

	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()

	// Read all data
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil || n == 0 {
		return 0
	}

	duration := time.Since(start)
	if duration > 0 {
		return float64(n) / duration.Seconds() / (1024 * 1024) // MB/s
	}
	return 0
}

func measureUploadSpeed(ctx context.Context, client *http.Client) float64 {
	// httpbin.org accepts POST data
	url := "https://httpbin.org/post"

	// Generate 512KB of test data
	testData := strings.NewReader(strings.Repeat("X", 512*1024))

	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, "POST", url, testData)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	duration := time.Since(start)
	if duration > 0 {
		return float64(512*1024) / duration.Seconds() / (1024 * 1024) // MB/s
	}
	return 0
}

func calculateStrategyScore(sr StrategyResult) int {
	if !sr.Available {
		return 0
	}

	score := 0

	// HTTP check: 20 points
	if sr.HTTPCheck {
		score += 20
	}

	// IP changed: 20 points (critical for privacy)
	if sr.IPChanged {
		score += 20
	}

	// Latency: up to 20 points (100ms = 20pts, 500ms = 10pts, 1s+ = 5pts)
	latMs := sr.HTTPLatency.Milliseconds()
	if latMs < 100 {
		score += 20
	} else if latMs < 300 {
		score += 15
	} else if latMs < 500 {
		score += 10
	} else if latMs < 1000 {
		score += 5
	}

	// Download speed: up to 20 points
	if sr.DownloadSpeed >= 10 {
		score += 20
	} else if sr.DownloadSpeed >= 5 {
		score += 15
	} else if sr.DownloadSpeed >= 2 {
		score += 10
	} else if sr.DownloadSpeed >= 1 {
		score += 5
	}

	// Upload speed: up to 20 points
	if sr.UploadSpeed >= 5 {
		score += 20
	} else if sr.UploadSpeed >= 2 {
		score += 15
	} else if sr.UploadSpeed >= 1 {
		score += 10
	} else if sr.UploadSpeed >= 0.5 {
		score += 5
	}

	return score
}

// FormatFullResults formats full benchmark results
func FormatFullResults(r *FullStrategyBenchmarkResult) string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString("╔════════════════════════════════════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║                          TiredVPN Full Strategy Benchmark                                  ║\n")
	sb.WriteString("╠════════════════════════════════════════════════════════════════════════════════════════════╣\n")
	fmt.Fprintf(&sb, "║ Original IP: %-77s ║\n", r.OriginalIP)
	sb.WriteString("╠════════════════════════════════════════════════════════════════════════════════════════════╣\n")
	sb.WriteString("║  #  │ Strategy                  │ Exit IP         │ Latency │ DL MB/s │ UL MB/s │ Score   ║\n")
	sb.WriteString("╟─────┼───────────────────────────┼─────────────────┼─────────┼─────────┼─────────┼─────────╢\n")

	// Sort by score
	sorted := make([]StrategyResult, len(r.Strategies))
	copy(sorted, r.Strategies)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Score > sorted[j].Score
	})

	for i, sr := range sorted {
		status := ""
		if !sr.Available {
			status = "FAIL"
		} else if sr.IPChanged {
			status = "✓"
		} else {
			status = "⚠" // IP didn't change - warning
		}

		exitIP := sr.ExitIP
		if len(exitIP) > 15 {
			exitIP = exitIP[:12] + "..."
		}
		if exitIP == "" {
			exitIP = "-"
		}

		latStr := "-"
		if sr.HTTPLatency > 0 {
			latStr = fmt.Sprintf("%dms", sr.HTTPLatency.Milliseconds())
		}

		dlStr := "-"
		if sr.DownloadSpeed > 0 {
			dlStr = fmt.Sprintf("%.1f", sr.DownloadSpeed)
		}

		ulStr := "-"
		if sr.UploadSpeed > 0 {
			ulStr = fmt.Sprintf("%.1f", sr.UploadSpeed)
		}

		scoreStr := fmt.Sprintf("%d/100 %s", sr.Score, status)

		fmt.Fprintf(&sb, "║ %2d  │ %-25s │ %-15s │ %7s │ %7s │ %7s │ %-7s ║\n",
			i+1, truncateName(sr.Name, 25), exitIP, latStr, dlStr, ulStr, scoreStr)
	}

	sb.WriteString("╠════════════════════════════════════════════════════════════════════════════════════════════╣\n")

	// Summary
	available := 0
	ipChanged := 0
	for _, sr := range r.Strategies {
		if sr.Available {
			available++
			if sr.IPChanged {
				ipChanged++
			}
		}
	}

	fmt.Fprintf(&sb, "║ Available: %d/%d strategies, IP Changed: %d/%d                                              ║\n",
		available, len(r.Strategies), ipChanged, available)

	if r.Best != nil {
		fmt.Fprintf(&sb, "║ Best Strategy: %-25s (Score: %d/100)                                 ║\n",
			truncateName(r.Best.Name, 25), r.Best.Score)
	}

	sb.WriteString("╚════════════════════════════════════════════════════════════════════════════════════════════╝\n")

	return sb.String()
}

// GetAllStrategyIDs returns all available strategy IDs
func GetAllStrategyIDs() []string {
	return []string{
		"quic",
		"reality",
		"websocket_padded",
		"http2_stego",
		"morph_Yandex Video",
		"morph_VK Video",
		"antiprobe",
		"confusion_0",
		"confusion_1",
		"confusion_2",
		"confusion_3",
		"confusion_4",
		"state_exhaustion",
	}
}

// RunFullBenchmarkDirect tests all strategies directly through the manager
// Tests: latency, HTTP availability, exit IP, download/upload speed
func RunFullBenchmarkDirect(ctx context.Context, mgr *strategy.Manager, serverAddr string, originalIP string) *FullStrategyBenchmarkResult {
	result := &FullStrategyBenchmarkResult{
		OriginalIP: originalIP,
		TestedAt:   time.Now(),
	}

	strategies := mgr.GetOrderedStrategies()

	for i, strat := range strategies {
		fmt.Printf("  [%d/%d] Testing %s...\n", i+1, len(strategies), strat.Name())
		sr := testStrategyDirect(ctx, strat, serverAddr, originalIP)
		result.Strategies = append(result.Strategies, sr)

		// Print quick result
		if sr.Available {
			fmt.Printf("         ✓ HTTP OK, Exit IP: %s", sr.ExitIP)
			if sr.IPChanged {
				fmt.Printf(" (CHANGED)")
			}
			fmt.Printf(", Latency: %dms", sr.Latency.Milliseconds())
			if sr.DownloadSpeed > 0 {
				fmt.Printf(", DL: %.1f MB/s", sr.DownloadSpeed)
			}
			fmt.Printf(", Score: %d/100\n", sr.Score)
		} else {
			fmt.Printf("         ✗ FAILED: %s\n", sr.Error)
		}
	}

	// Find best by score
	for i := range result.Strategies {
		sr := &result.Strategies[i]
		if sr.Available && (result.Best == nil || sr.Score > result.Best.Score) {
			result.Best = sr
		}
	}

	return result
}

func testStrategyDirect(ctx context.Context, strat strategy.Strategy, serverAddr string, originalIP string) StrategyResult {
	sr := StrategyResult{
		ID:   strat.ID(),
		Name: strat.Name(),
	}

	// Test 1: Connect and measure latency
	start := time.Now()
	connCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	conn, err := strat.Connect(connCtx, serverAddr)
	cancel()

	if err != nil {
		sr.Error = fmt.Sprintf("connect: %v", err)
		return sr
	}
	defer conn.Close()

	sr.Latency = time.Since(start)
	sr.Available = true

	// Test 2: HTTP request through the tunnel to get exit IP
	exitIP, httpLatency, err := testHTTPThroughTunnel(conn, serverAddr)
	if err != nil {
		sr.Error = fmt.Sprintf("http test: %v", err)
		sr.HTTPCheck = false
		// Still available but HTTP failed
		sr.Score = calculateStrategyScore(sr)
		return sr
	}

	sr.HTTPCheck = true
	sr.HTTPLatency = httpLatency
	sr.ExitIP = exitIP
	sr.IPChanged = (exitIP != originalIP && originalIP != "unknown")

	// Test 3: Download speed through tunnel
	// Reconnect for download test
	connCtx2, cancel2 := context.WithTimeout(ctx, 15*time.Second)
	conn2, err := strat.Connect(connCtx2, serverAddr)
	cancel2()
	if err == nil {
		sr.DownloadSpeed = testDownloadThroughTunnel(conn2)
		conn2.Close()
	}

	// Calculate score
	sr.Score = calculateStrategyScore(sr)

	return sr
}

// flushConn flushes buffered data if connection supports it (e.g., RTT masking)
func flushConn(conn net.Conn) {
	if f, ok := conn.(interface{ Flush() error }); ok {
		f.Flush()
	}
}

func testHTTPThroughTunnel(conn net.Conn, serverAddr string) (exitIP string, latency time.Duration, err error) {
	// Longer timeouts for RTT masking scenarios (adds artificial delays)
	writeTimeout := 10 * time.Second
	readTimeout := 15 * time.Second

	// Send target address to server (ifconfig.me - simple, returns just IP)
	targetAddr := "ifconfig.me:80"
	addrBytes := []byte(targetAddr)
	addrPacket := make([]byte, 2+len(addrBytes))
	addrPacket[0] = byte(len(addrBytes) >> 8)
	addrPacket[1] = byte(len(addrBytes))
	copy(addrPacket[2:], addrBytes)

	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err = conn.Write(addrPacket); err != nil {
		return "", 0, fmt.Errorf("write addr: %w", err)
	}
	flushConn(conn) // Flush any buffered data (important for RTT masking)

	// Read server response
	resp := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(readTimeout))
	if _, err = io.ReadFull(conn, resp); err != nil {
		return "", 0, fmt.Errorf("read resp: %w", err)
	}
	if resp[0] != 0x00 {
		return "", 0, fmt.Errorf("server rejected connection")
	}

	// Send HTTP request
	start := time.Now()
	httpReq := "GET / HTTP/1.1\r\nHost: ifconfig.me\r\nUser-Agent: curl/8.0\r\nConnection: close\r\n\r\n"

	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err = conn.Write([]byte(httpReq)); err != nil {
		return "", 0, fmt.Errorf("write http: %w", err)
	}
	flushConn(conn) // Flush HTTP request

	// Read response
	conn.SetReadDeadline(time.Now().Add(readTimeout))
	buf := make([]byte, 4096)
	var fullResp []byte
	firstByte := true
	for {
		n, readErr := conn.Read(buf)
		if n > 0 {
			if firstByte {
				// Measure latency to first byte
				latency = time.Since(start)
				firstByte = false
			}
			fullResp = append(fullResp, buf[:n]...)
		}
		if readErr != nil {
			break
		}
		if len(fullResp) > 2048 {
			break
		}
	}
	if firstByte {
		// Never got any data
		latency = time.Since(start)
	}

	// Parse IP from response (ifconfig.me returns plain IP in body)
	respStr := string(fullResp)
	// Look for body after headers
	bodyStart := strings.Index(respStr, "\r\n\r\n")
	if bodyStart >= 0 {
		respStr = respStr[bodyStart+4:]
	}

	// ifconfig.me returns plain IP like "1.2.3.4\n"
	exitIP = strings.TrimSpace(respStr)

	// Validate it looks like an IP
	if exitIP == "" || (!strings.Contains(exitIP, ".") && !strings.Contains(exitIP, ":")) {
		return "", latency, fmt.Errorf("could not parse IP from response: %s", respStr[:min(len(respStr), 100)])
	}

	// Clean up - take only first line (IP)
	if idx := strings.Index(exitIP, "\n"); idx > 0 {
		exitIP = exitIP[:idx]
	}

	return exitIP, latency, nil
}

// ComboResult holds result for a strategy + RTT profile combination
type ComboResult struct {
	StrategyID    string
	StrategyName  string
	RTTProfile    string // "none" or profile name
	Available     bool
	Latency       time.Duration
	HTTPLatency   time.Duration
	ExitIP        string
	IPChanged     bool
	DownloadSpeed float64
	Score         int
	Error         string
}

// AllCombosResult holds results for all combinations
type AllCombosResult struct {
	OriginalIP   string
	Combinations []ComboResult
	Best         *ComboResult
	TestedAt     time.Time
}

// RunAllCombinationsBenchmark tests all strategy × RTT profile combinations
func RunAllCombinationsBenchmark(ctx context.Context, mgr *strategy.Manager, serverAddr string, originalIP string, rttProfiles []*strategy.RTTProfile) *AllCombosResult {
	result := &AllCombosResult{
		OriginalIP: originalIP,
		TestedAt:   time.Now(),
	}

	strategies := mgr.GetOrderedStrategies()

	// RTT variants: "none" + all profiles
	rttVariants := make([]string, 0, len(rttProfiles)+1)
	rttVariants = append(rttVariants, "none")
	for _, p := range rttProfiles {
		rttVariants = append(rttVariants, p.Name)
	}

	totalCombos := len(strategies) * len(rttVariants)
	comboNum := 0

	for _, strat := range strategies {
		for _, rttName := range rttVariants {
			comboNum++
			fmt.Printf("  [%d/%d] %s + RTT:%s...\n", comboNum, totalCombos, strat.Name(), rttName)

			cr := testCombo(ctx, strat, serverAddr, originalIP, rttName, rttProfiles)
			result.Combinations = append(result.Combinations, cr)

			// Print quick result
			if cr.Available {
				fmt.Printf("         ✓ Exit: %s, Lat: %dms, DL: %.1f MB/s, Score: %d\n",
					cr.ExitIP, cr.HTTPLatency.Milliseconds(), cr.DownloadSpeed, cr.Score)
			} else {
				fmt.Printf("         ✗ %s\n", cr.Error)
			}
		}
	}

	// Find best
	for i := range result.Combinations {
		cr := &result.Combinations[i]
		if cr.Available && (result.Best == nil || cr.Score > result.Best.Score) {
			result.Best = cr
		}
	}

	return result
}

func testCombo(ctx context.Context, strat strategy.Strategy, serverAddr string, originalIP string, rttName string, rttProfiles []*strategy.RTTProfile) ComboResult {
	cr := ComboResult{
		StrategyID:   strat.ID(),
		StrategyName: strat.Name(),
		RTTProfile:   rttName,
	}

	// Connect
	start := time.Now()
	connCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	conn, err := strat.Connect(connCtx, serverAddr)
	cancel()

	if err != nil {
		cr.Error = fmt.Sprintf("connect: %v", err)
		return cr
	}

	cr.Latency = time.Since(start)
	cr.Available = true

	// Wrap with RTT masking if needed
	if rttName != "none" {
		for _, p := range rttProfiles {
			if p.Name == rttName {
				conn = strategy.WrapWithRTTMasking(conn, p)
				break
			}
		}
	}
	defer conn.Close()

	// Test HTTP through tunnel
	exitIP, httpLatency, err := testHTTPThroughTunnel(conn, serverAddr)
	if err != nil {
		cr.Error = fmt.Sprintf("http: %v", err)
		cr.Score = 10 // Some score for connecting
		return cr
	}

	cr.HTTPLatency = httpLatency
	cr.ExitIP = exitIP
	cr.IPChanged = (exitIP != originalIP && originalIP != "unknown")

	// Download test with new connection
	connCtx2, cancel2 := context.WithTimeout(ctx, 15*time.Second)
	conn2, err := strat.Connect(connCtx2, serverAddr)
	cancel2()
	if err == nil {
		if rttName != "none" {
			for _, p := range rttProfiles {
				if p.Name == rttName {
					conn2 = strategy.WrapWithRTTMasking(conn2, p)
					break
				}
			}
		}
		cr.DownloadSpeed = testDownloadThroughTunnel(conn2)
		conn2.Close()
	}

	// Calculate score
	cr.Score = calculateComboScore(cr)

	return cr
}

func calculateComboScore(cr ComboResult) int {
	if !cr.Available {
		return 0
	}

	score := 20 // Base for being available

	// IP changed: +20
	if cr.IPChanged {
		score += 20
	}

	// Latency scoring
	latMs := cr.HTTPLatency.Milliseconds()
	if latMs < 100 {
		score += 20
	} else if latMs < 300 {
		score += 15
	} else if latMs < 500 {
		score += 10
	} else if latMs < 1000 {
		score += 5
	}

	// Download speed
	if cr.DownloadSpeed >= 5 {
		score += 20
	} else if cr.DownloadSpeed >= 2 {
		score += 15
	} else if cr.DownloadSpeed >= 1 {
		score += 10
	} else if cr.DownloadSpeed > 0 {
		score += 5
	}

	// RTT masking bonus (obfuscation)
	if cr.RTTProfile != "none" {
		score += 10
	}

	return score
}

// FormatAllCombosResults formats all combinations benchmark results
func FormatAllCombosResults(r *AllCombosResult) string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString("╔═══════════════════════════════════════════════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║                     TiredVPN EXHAUSTIVE Benchmark (All Combinations)                                  ║\n")
	sb.WriteString("╠═══════════════════════════════════════════════════════════════════════════════════════════════════════╣\n")
	fmt.Fprintf(&sb, "║ Original IP: %-88s ║\n", r.OriginalIP)
	sb.WriteString("╠═══════════════════════════════════════════════════════════════════════════════════════════════════════╣\n")
	sb.WriteString("║  #  │ Strategy                  │ RTT Profile     │ Exit IP         │ Lat(ms) │ DL MB/s │ Score    ║\n")
	sb.WriteString("╟─────┼───────────────────────────┼─────────────────┼─────────────────┼─────────┼─────────┼──────────╢\n")

	// Sort by score descending
	sorted := make([]ComboResult, len(r.Combinations))
	copy(sorted, r.Combinations)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Score > sorted[j].Score
	})

	// Show top 30 and bottom failures
	maxShow := 30
	if len(sorted) < maxShow {
		maxShow = len(sorted)
	}

	for i := 0; i < maxShow; i++ {
		cr := sorted[i]
		formatComboRow(&sb, i+1, cr)
	}

	// Count stats
	available := 0
	ipChanged := 0
	for _, cr := range r.Combinations {
		if cr.Available {
			available++
			if cr.IPChanged {
				ipChanged++
			}
		}
	}

	sb.WriteString("╠═══════════════════════════════════════════════════════════════════════════════════════════════════════╣\n")
	fmt.Fprintf(&sb, "║ Tested: %d combinations | Available: %d | IP Changed: %d                                              ║\n",
		len(r.Combinations), available, ipChanged)

	if r.Best != nil {
		fmt.Fprintf(&sb, "║ BEST: %-25s + RTT:%-12s (Score: %d)                                    ║\n",
			truncateName(r.Best.StrategyName, 25), r.Best.RTTProfile, r.Best.Score)
	}

	sb.WriteString("╚═══════════════════════════════════════════════════════════════════════════════════════════════════════╝\n")

	return sb.String()
}

func formatComboRow(sb *strings.Builder, num int, cr ComboResult) {
	status := "✓"
	if !cr.Available {
		status = "✗"
	} else if !cr.IPChanged {
		status = "⚠"
	}

	exitIP := cr.ExitIP
	if len(exitIP) > 15 {
		exitIP = exitIP[:12] + "..."
	}
	if exitIP == "" {
		exitIP = "-"
	}

	latStr := "-"
	if cr.HTTPLatency > 0 {
		latStr = fmt.Sprintf("%d", cr.HTTPLatency.Milliseconds())
	}

	dlStr := "-"
	if cr.DownloadSpeed > 0 {
		dlStr = fmt.Sprintf("%.1f", cr.DownloadSpeed)
	}

	scoreStr := fmt.Sprintf("%d %s", cr.Score, status)

	fmt.Fprintf(sb, "║ %2d  │ %-25s │ %-15s │ %-15s │ %7s │ %7s │ %-8s ║\n",
		num, truncateName(cr.StrategyName, 25), cr.RTTProfile, exitIP, latStr, dlStr, scoreStr)
}

func testDownloadThroughTunnel(conn net.Conn) float64 {
	// Longer timeouts for RTT masking scenarios
	writeTimeout := 10 * time.Second
	readTimeout := 60 * time.Second // Longer for download

	// Download 10MB from Ubuntu ISO (reliable, fast NL mirror)
	targetAddr := "releases.ubuntu.com:80"
	addrBytes := []byte(targetAddr)
	addrPacket := make([]byte, 2+len(addrBytes))
	addrPacket[0] = byte(len(addrBytes) >> 8)
	addrPacket[1] = byte(len(addrBytes))
	copy(addrPacket[2:], addrBytes)

	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := conn.Write(addrPacket); err != nil {
		return 0
	}
	flushConn(conn) // Flush for RTT masking

	// Read response
	resp := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(readTimeout))
	if _, err := io.ReadFull(conn, resp); err != nil || resp[0] != 0x00 {
		return 0
	}

	// Request Ubuntu ISO (will cut after 10MB)
	httpReq := "GET /24.04/ubuntu-24.04.3-live-server-amd64.iso HTTP/1.1\r\nHost: releases.ubuntu.com\r\nConnection: close\r\n\r\n"

	conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := conn.Write([]byte(httpReq)); err != nil {
		return 0
	}
	flushConn(conn) // Flush HTTP request

	// Read and measure speed - stop at 10MB
	const targetBytes = 10 * 1024 * 1024 // 10MB
	start := time.Now()
	buf := make([]byte, 64*1024) // 64KB buffer for speed
	headerDone := false
	var totalRead int64

	conn.SetReadDeadline(time.Now().Add(readTimeout))

	for totalRead < targetBytes {
		n, err := conn.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			if totalRead > 0 {
				break
			}
			return 0
		}

		if !headerDone {
			data := string(buf[:n])
			if idx := strings.Index(data, "\r\n\r\n"); idx >= 0 {
				headerDone = true
				totalRead += int64(n - idx - 4)
			}
		} else {
			totalRead += int64(n)
		}
	}

	duration := time.Since(start)
	if duration > 0 && totalRead > 0 {
		return float64(totalRead) / duration.Seconds() / (1024 * 1024) // MB/s
	}
	return 0
}
