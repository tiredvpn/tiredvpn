package log

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
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

// Logger provides structured logging with debug support
type Logger struct {
	mu       sync.Mutex
	out      io.Writer
	level    Level
	prefix   string
	color    bool
	showFile bool
}

var defaultLogger = &Logger{
	out:      os.Stderr,
	level:    LevelInfo,
	color:    true,
	showFile: true,
}

// SetLevel sets global log level
func SetLevel(l Level) {
	defaultLogger.mu.Lock()
	defaultLogger.level = l
	defaultLogger.mu.Unlock()
}

// SetDebug enables debug logging
func SetDebug(enabled bool) {
	if enabled {
		SetLevel(LevelDebug)
	} else {
		SetLevel(LevelInfo)
	}
}

// SetOutput sets log output
func SetOutput(w io.Writer) {
	defaultLogger.mu.Lock()
	defaultLogger.out = w
	defaultLogger.mu.Unlock()
}

// SetColor enables/disables color output
func SetColor(enabled bool) {
	defaultLogger.mu.Lock()
	defaultLogger.color = enabled
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

	now := time.Now().Format("15:04:05.000")
	msg := fmt.Sprintf(format, args...)

	// Get caller info
	var fileInfo string
	if l.showFile && level == LevelDebug {
		_, file, line, ok := runtime.Caller(2)
		if ok {
			// Shorten path
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
		output = fmt.Sprintf("%s%s%s %s%s%s\n",
			levelColors[level], levelNames[level], colorReset,
			now, fileInfo,
			fmt.Sprintf(" %s%s", prefix, msg))
	} else {
		output = fmt.Sprintf("%s %s%s %s%s\n",
			levelNames[level], now, fileInfo, prefix, msg)
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
