package log

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestLogLevels tests log level constants
func TestLogLevels(t *testing.T) {
	tests := []struct {
		level Level
		name  string
		value int
	}{
		{LevelDebug, "DBG", 0},
		{LevelInfo, "INF", 1},
		{LevelWarn, "WRN", 2},
		{LevelError, "ERR", 3},
	}

	for _, tt := range tests {
		if int(tt.level) != tt.value {
			t.Errorf("Level %s: got %d, want %d", tt.name, tt.level, tt.value)
		}

		if levelNames[tt.level] != tt.name {
			t.Errorf("Level name: got %s, want %s", levelNames[tt.level], tt.name)
		}

		if levelColors[tt.level] == "" {
			t.Errorf("Level %s has no color", tt.name)
		}
	}
}

// TestLoggerCreation tests logger initialization
func TestLoggerCreation(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		out:      &buf,
		level:    LevelInfo,
		prefix:   "test",
		color:    false,
		showFile: false,
	}

	if logger.out != &buf {
		t.Error("Output not set correctly")
	}

	if logger.level != LevelInfo {
		t.Errorf("Level: got %v, want %v", logger.level, LevelInfo)
	}

	if logger.prefix != "test" {
		t.Errorf("Prefix: got %s, want test", logger.prefix)
	}
}

// TestLogLevelFiltering tests that messages below level are filtered
func TestLogLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		out:      &buf,
		level:    LevelWarn, // Only warn and error
		color:    false,
		showFile: false,
	}

	// These should be filtered
	logger.Debug("debug message")
	logger.Info("info message")

	if buf.Len() > 0 {
		t.Error("Debug/Info messages should be filtered at Warn level")
	}

	// These should pass
	logger.Warn("warn message")
	logger.Error("error message")

	output := buf.String()
	if !strings.Contains(output, "warn message") {
		t.Error("Warn message should be logged")
	}
	if !strings.Contains(output, "error message") {
		t.Error("Error message should be logged")
	}
}

// TestLogFormatting tests log message formatting
func TestLogFormatting(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		out:      &buf,
		level:    LevelInfo,
		color:    false,
		showFile: false,
	}

	logger.Info("test message")
	output := buf.String()

	// Should contain level name
	if !strings.Contains(output, "INF") {
		t.Error("Output should contain INF level")
	}

	// Should contain message
	if !strings.Contains(output, "test message") {
		t.Error("Output should contain message")
	}

	// Should contain timestamp (HH:MM:SS format)
	if !strings.Contains(output, ":") {
		t.Error("Output should contain timestamp")
	}
}

// TestLogFormattingWithArgs tests formatted messages
func TestLogFormattingWithArgs(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		out:      &buf,
		level:    LevelInfo,
		color:    false,
		showFile: false,
	}

	logger.Info("value: %d, name: %s", 42, "test")
	output := buf.String()

	if !strings.Contains(output, "value: 42") {
		t.Error("Output should contain formatted integer")
	}
	if !strings.Contains(output, "name: test") {
		t.Error("Output should contain formatted string")
	}
}

// TestLogPrefix tests prefix functionality
func TestLogPrefix(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		out:      &buf,
		level:    LevelInfo,
		prefix:   "myprefix",
		color:    false,
		showFile: false,
	}

	logger.Info("test message")
	output := buf.String()

	if !strings.Contains(output, "[myprefix]") {
		t.Error("Output should contain prefix [myprefix]")
	}
}

// TestLogColorDisabled tests output without colors
func TestLogColorDisabled(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		out:      &buf,
		level:    LevelInfo,
		color:    false,
		showFile: false,
	}

	logger.Info("test message")
	output := buf.String()

	// Should NOT contain ANSI escape codes
	if strings.Contains(output, "\033[") {
		t.Error("Output should not contain ANSI color codes when color=false")
	}
}

// TestLogColorEnabled tests output with colors
func TestLogColorEnabled(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		out:      &buf,
		level:    LevelInfo,
		color:    true,
		showFile: false,
	}

	logger.Info("test message")
	output := buf.String()

	// Should contain ANSI escape codes
	if !strings.Contains(output, "\033[") {
		t.Error("Output should contain ANSI color codes when color=true")
	}

	// Should contain reset code
	if !strings.Contains(output, colorReset) {
		t.Error("Output should contain color reset")
	}
}

// TestWithPrefix tests creating prefixed loggers
func TestWithPrefix(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	SetLevel(LevelInfo)
	SetColor(false)

	logger := WithPrefix("custom")
	logger.Info("test message")

	output := buf.String()
	if !strings.Contains(output, "[custom]") {
		t.Error("Prefixed logger should include prefix")
	}
}

// TestSetLevel tests global level setting
func TestSetLevel(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	SetColor(false)

	// Set to error level
	SetLevel(LevelError)
	Info("should be filtered")
	Warn("should be filtered")

	if buf.Len() > 0 {
		t.Error("Info/Warn should be filtered at Error level")
	}

	Error("should appear")
	if !strings.Contains(buf.String(), "should appear") {
		t.Error("Error should be logged at Error level")
	}
}

// TestSetDebug tests debug mode toggling
func TestSetDebug(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	SetColor(false)

	// Disable debug
	SetDebug(false)
	Debug("should be filtered")
	if buf.Len() > 0 {
		t.Error("Debug should be filtered when debug=false")
	}

	// Enable debug
	SetDebug(true)
	Debug("should appear")
	if !strings.Contains(buf.String(), "should appear") {
		t.Error("Debug should be logged when debug=true")
	}
}

// TestPackageLevelFunctions tests global log functions
func TestPackageLevelFunctions(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	SetLevel(LevelDebug)
	SetColor(false)

	Debug("debug")
	Info("info")
	Warn("warn")
	Error("error")

	output := buf.String()

	if !strings.Contains(output, "debug") {
		t.Error("Debug() should work")
	}
	if !strings.Contains(output, "info") {
		t.Error("Info() should work")
	}
	if !strings.Contains(output, "warn") {
		t.Error("Warn() should work")
	}
	if !strings.Contains(output, "error") {
		t.Error("Error() should work")
	}
}

// TestConcurrentLogging tests thread safety
func TestConcurrentLogging(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		out:      &buf,
		level:    LevelInfo,
		color:    false,
		showFile: false,
	}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			logger.Info("message %d", id)
		}(i)
	}

	wg.Wait()

	// Should have 10 messages
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 10 {
		t.Errorf("Expected 10 log lines, got %d", len(lines))
	}
}

// TestHexDump tests hex dump utility
func TestHexDump(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	dump := HexDump(data, 100)

	// Should contain hex values
	if !strings.Contains(dump, "01") {
		t.Error("Hex dump should contain '01'")
	}
	if !strings.Contains(dump, "02") {
		t.Error("Hex dump should contain '02'")
	}

	// Should have spaces between bytes
	if !strings.Contains(dump, " ") {
		t.Error("Hex dump should have spaces between bytes")
	}
}

// TestHexDumpTruncation tests hex dump length limiting
func TestHexDumpTruncation(t *testing.T) {
	data := make([]byte, 100)
	for i := range data {
		data[i] = byte(i)
	}

	dump := HexDump(data, 10)

	// Should be truncated
	if !strings.Contains(dump, "...") {
		t.Error("Long hex dump should be truncated with '...'")
	}

	// Should only show first 10 bytes
	lines := strings.Split(dump, "\n")
	firstLine := strings.TrimSpace(lines[0])
	byteCount := len(strings.Fields(strings.ReplaceAll(firstLine, "...", "")))
	if byteCount > 10 {
		t.Errorf("Truncated dump should show at most 10 bytes, got %d", byteCount)
	}
}

// TestHexDumpFormatting tests hex dump line breaks
func TestHexDumpFormatting(t *testing.T) {
	// Create 32 bytes (should wrap at 16)
	data := make([]byte, 32)
	for i := range data {
		data[i] = byte(i)
	}

	dump := HexDump(data, 100)

	// Should have newline after 16 bytes
	if !strings.Contains(dump, "\n") {
		t.Error("Hex dump should wrap at 16 bytes")
	}
}

// TestTrace tests function tracing
func TestTrace(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	SetLevel(LevelDebug)
	SetColor(false)

	func() {
		defer Trace("testFunc")()
		time.Sleep(10 * time.Millisecond)
	}()

	output := buf.String()

	// Should have entry
	if !strings.Contains(output, "→ testFunc") {
		t.Error("Trace should log function entry")
	}

	// Should have exit with duration
	if !strings.Contains(output, "← testFunc") {
		t.Error("Trace should log function exit")
	}
}

// TestTraceNoOpAtHigherLevel tests trace is disabled when not debug level
func TestTraceNoOpAtHigherLevel(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	SetLevel(LevelInfo) // Higher than debug
	SetColor(false)

	func() {
		defer Trace("testFunc")()
	}()

	output := buf.String()

	// Should NOT log anything
	if strings.Contains(output, "testFunc") {
		t.Error("Trace should be no-op at non-debug level")
	}
}

// TestStrategyLogger tests strategy logger creation
func TestStrategyLogger(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	SetLevel(LevelInfo)
	SetColor(false)

	logger := StrategyLogger("http2-stego")
	logger.Info("test message")

	output := buf.String()
	if !strings.Contains(output, "[strategy:http2-stego]") {
		t.Error("Strategy logger should include strategy ID in prefix")
	}
}

// TestServerLogger tests server logger creation
func TestServerLogger(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	SetLevel(LevelInfo)
	SetColor(false)

	logger := ServerLogger()
	logger.Info("test message")

	output := buf.String()
	if !strings.Contains(output, "[server]") {
		t.Error("Server logger should include 'server' prefix")
	}
}

// TestClientLogger tests client logger creation
func TestClientLogger(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	SetLevel(LevelInfo)
	SetColor(false)

	logger := ClientLogger()
	logger.Info("test message")

	output := buf.String()
	if !strings.Contains(output, "[client]") {
		t.Error("Client logger should include 'client' prefix")
	}
}

// TestConnLogger tests connection logger creation
func TestConnLogger(t *testing.T) {
	var buf bytes.Buffer
	SetOutput(&buf)
	SetLevel(LevelInfo)
	SetColor(false)

	logger := ConnLogger("abc123")
	logger.Info("test message")

	output := buf.String()
	if !strings.Contains(output, "[conn:abc123]") {
		t.Error("Connection logger should include conn ID in prefix")
	}
}

// TestMultipleLevelsOutput tests all log levels produce output
func TestMultipleLevelsOutput(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		out:      &buf,
		level:    LevelDebug,
		color:    false,
		showFile: false,
	}

	logger.Debug("debug")
	logger.Info("info")
	logger.Warn("warn")
	logger.Error("error")

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	if len(lines) != 4 {
		t.Errorf("Expected 4 log lines, got %d", len(lines))
	}

	// Verify level names
	if !strings.Contains(output, "DBG") {
		t.Error("Should contain DBG level")
	}
	if !strings.Contains(output, "INF") {
		t.Error("Should contain INF level")
	}
	if !strings.Contains(output, "WRN") {
		t.Error("Should contain WRN level")
	}
	if !strings.Contains(output, "ERR") {
		t.Error("Should contain ERR level")
	}
}

// TestLevelColors tests color codes for each level
func TestLevelColors(t *testing.T) {
	tests := []struct {
		level Level
		color string
	}{
		{LevelDebug, "\033[36m"}, // Cyan
		{LevelInfo, "\033[32m"},  // Green
		{LevelWarn, "\033[33m"},  // Yellow
		{LevelError, "\033[31m"}, // Red
	}

	for _, tt := range tests {
		if levelColors[tt.level] != tt.color {
			t.Errorf("Level %d color: got %s, want %s",
				tt.level, levelColors[tt.level], tt.color)
		}
	}
}

// TestEmptyMessage tests logging empty messages
func TestEmptyMessage(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		out:      &buf,
		level:    LevelInfo,
		color:    false,
		showFile: false,
	}

	logger.Info("")
	output := buf.String()

	// Should still produce output with level and timestamp
	if !strings.Contains(output, "INF") {
		t.Error("Empty message should still log level")
	}
}

// TestVeryLongMessage tests handling of long messages
func TestVeryLongMessage(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		out:      &buf,
		level:    LevelInfo,
		color:    false,
		showFile: false,
	}

	longMsg := strings.Repeat("x", 1000)
	logger.Info("%s", longMsg)
	output := buf.String()

	if !strings.Contains(output, longMsg) {
		t.Error("Long message should be fully logged")
	}
}
