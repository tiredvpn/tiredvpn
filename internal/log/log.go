package log

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Level represents log level
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

var levelNames = map[Level]string{
	LevelDebug: "DBG",
	LevelInfo:  "INF",
	LevelWarn:  "WRN",
	LevelError: "ERR",
}

var levelColors = map[Level]string{
	LevelDebug: "\033[36m", // Cyan
	LevelInfo:  "\033[32m", // Green
	LevelWarn:  "\033[33m", // Yellow
	LevelError: "\033[31m", // Red
}

const colorReset = "\033[0m"

// dedupState tracks the current run of identical log messages.
type dedupState struct {
	msg   string
	level Level
	count int // suppressed occurrences (not counting the first emitted one)
	last  time.Time
}

// Logger provides structured logging with debug support
type Logger struct {
	mu       sync.Mutex
	out      io.Writer
	level    Level
	prefix   string
	color    bool
	showFile bool

	// Dedup: suppress runs of identical messages.
	// A "run" ends when a different message arrives or dedupWindow elapses
	// since the last occurrence. Default window: 5 s. Enabled by default.
	dedup        dedupState
	dedupEnabled bool
	dedupWindow  time.Duration
}

var defaultLogger = &Logger{
	out:          os.Stderr,
	level:        LevelInfo,
	color:        true,
	showFile:     true,
	dedupEnabled: true,
	dedupWindow:  5 * time.Second,
}

// defaultLevel mirrors defaultLogger.level so per-packet code can test it
// without taking the logger mutex.
var defaultLevel atomic.Int32

func init() {
	defaultLevel.Store(int32(defaultLogger.level))
}

// DebugEnabled reports whether the package-level Debug output is currently
// emitted. Per-packet call sites gate their log.Debug on it because Go
// evaluates the arguments regardless of level: hex dumps, IP.String and the
// variadic boxing all allocate on every packet even when the line is dropped.
func DebugEnabled() bool {
	return Level(defaultLevel.Load()) <= LevelDebug
}

// SetLevel sets global log level
func SetLevel(l Level) {
	defaultLogger.mu.Lock()
	defaultLogger.level = l
	defaultLogger.mu.Unlock()
	defaultLevel.Store(int32(l))
}

// SetDebug enables debug logging
func SetDebug(enabled bool) {
	if enabled {
		SetLevel(LevelDebug)
	} else {
		SetLevel(LevelInfo)
	}
}

// SetOutput sets log output. Resets dedup state (new output = new context).
func SetOutput(w io.Writer) {
	defaultLogger.mu.Lock()
	defaultLogger.out = w
	defaultLogger.dedup = dedupState{}
	defaultLogger.mu.Unlock()
}

// SetColor enables/disables color output
func SetColor(enabled bool) {
	defaultLogger.mu.Lock()
	defaultLogger.color = enabled
	defaultLogger.mu.Unlock()
}

// SetDedupWindow configures repeated-message suppression.
// window=0 disables dedup entirely. Default is 5s (enabled).
func SetDedupWindow(window time.Duration) {
	defaultLogger.mu.Lock()
	if window <= 0 {
		defaultLogger.dedupEnabled = false
	} else {
		defaultLogger.dedupEnabled = true
		defaultLogger.dedupWindow = window
	}
	defaultLogger.mu.Unlock()
}

// WithPrefix creates a new logger with prefix
func WithPrefix(prefix string) *Logger {
	return &Logger{
		out:      defaultLogger.out,
		level:    defaultLogger.level,
		prefix:   prefix,
		color:    defaultLogger.color,
		showFile: defaultLogger.showFile,
	}
}

func (l *Logger) log(level Level, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	msg := fmt.Sprintf(format, args...)

	// Dedup: suppress identical consecutive messages within the window.
	// When a different message arrives (or window expires), flush the suppressed count.
	if l.dedupEnabled {
		sameMsg := msg == l.dedup.msg
		withinWindow := now.Sub(l.dedup.last) < l.dedupWindow

		if sameMsg && withinWindow {
			l.dedup.count++
			l.dedup.last = now
			return
		}

		// Flush pending count before emitting a new message.
		if l.dedup.count > 0 {
			l.emit(l.dedup.level, l.dedup.last,
				fmt.Sprintf("... last message repeated %d more time(s)", l.dedup.count))
		}

		l.dedup = dedupState{msg: msg, level: level, count: 0, last: now}
	}

	l.emit(level, now, msg)
}

// emit writes a single line; caller must hold l.mu.
func (l *Logger) emit(level Level, t time.Time, msg string) {
	ts := t.Format("15:04:05.000")

	var fileInfo string
	if l.showFile && level == LevelDebug {
		_, file, line, ok := runtime.Caller(3)
		if ok {
			parts := strings.Split(file, "/")
			if len(parts) > 2 {
				file = strings.Join(parts[len(parts)-2:], "/")
			}
			fileInfo = fmt.Sprintf(" [%s:%d]", file, line)
		}
	}

	var prefix string
	if l.prefix != "" {
		prefix = fmt.Sprintf("[%s] ", l.prefix)
	}

	var output string
	if l.color {
		output = fmt.Sprintf("%s%s%s %s%s %s%s\n",
			levelColors[level], levelNames[level], colorReset,
			ts, fileInfo, prefix, msg)
	} else {
		output = fmt.Sprintf("%s %s%s %s%s\n",
			levelNames[level], ts, fileInfo, prefix, msg)
	}

	l.out.Write([]byte(output))
}

// Debug logs debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(LevelDebug, format, args...)
}

// Info logs info message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(LevelInfo, format, args...)
}

// Warn logs warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(LevelWarn, format, args...)
}

// Error logs error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(LevelError, format, args...)
}

// Package-level functions
func Debug(format string, args ...interface{}) {
	defaultLogger.log(LevelDebug, format, args...)
}

func Info(format string, args ...interface{}) {
	defaultLogger.log(LevelInfo, format, args...)
}

func Warn(format string, args ...interface{}) {
	defaultLogger.log(LevelWarn, format, args...)
}

func Error(format string, args ...interface{}) {
	defaultLogger.log(LevelError, format, args...)
}

// Trace logs function entry/exit for debugging
func Trace(name string) func() {
	if defaultLogger.level > LevelDebug {
		return func() {}
	}

	start := time.Now()
	Debug("→ %s", name)
	return func() {
		Debug("← %s (%v)", name, time.Since(start))
	}
}

// HexDump returns hex dump of data for debugging
func HexDump(data []byte, maxLen int) string {
	if len(data) > maxLen {
		data = data[:maxLen]
	}

	var sb strings.Builder
	for i, b := range data {
		if i > 0 && i%16 == 0 {
			sb.WriteString("\n")
		}
		fmt.Fprintf(&sb, "%02x ", b)
	}

	if len(data) == maxLen {
		sb.WriteString("...")
	}

	return sb.String()
}

// StrategyLogger creates logger for a strategy
func StrategyLogger(strategyID string) *Logger {
	return WithPrefix("strategy:" + strategyID)
}

// ServerLogger creates logger for server
func ServerLogger() *Logger {
	return WithPrefix("server")
}

// ClientLogger creates logger for client
func ClientLogger() *Logger {
	return WithPrefix("client")
}

// ConnLogger creates logger for connection
func ConnLogger(connID string) *Logger {
	return WithPrefix("conn:" + connID)
}
