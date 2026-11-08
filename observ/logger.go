// Package observ provides minimal structured logging adapters used by
// go-secguard components. It depends only on the Go standard library.
package observ

import (
	"fmt"
	"log"
	"log/slog"
	"sort"
	"strings"
)

// Logger is the structured logging interface used by go-secguard components.
// Implementations must be safe for concurrent use.
type Logger interface {
	Debug(msg string, fields map[string]any)
	Info(msg string, fields map[string]any)
	Warn(msg string, fields map[string]any)
	Error(msg string, err error, fields map[string]any)
}

// NoopLogger discards every log entry.
type NoopLogger struct{}

// NewNoopLogger returns a Logger that discards all output.
func NewNoopLogger() Logger { return NoopLogger{} }

func (NoopLogger) Debug(string, map[string]any)        {}
func (NoopLogger) Info(string, map[string]any)         {}
func (NoopLogger) Warn(string, map[string]any)         {}
func (NoopLogger) Error(string, error, map[string]any) {}

// StdlibAdapter adapts a standard library *log.Logger to Logger.
type StdlibAdapter struct {
	logger *log.Logger
}

// NewStdlibAdapter returns a Logger backed by l. A nil logger yields a no-op
// logger.
func NewStdlibAdapter(l *log.Logger) Logger {
	if l == nil {
		return NewNoopLogger()
	}
	return &StdlibAdapter{logger: l}
}

func (a *StdlibAdapter) Debug(msg string, fields map[string]any) {
	a.log("DEBUG", msg, nil, fields)
}

func (a *StdlibAdapter) Info(msg string, fields map[string]any) {
	a.log("INFO", msg, nil, fields)
}

func (a *StdlibAdapter) Warn(msg string, fields map[string]any) {
	a.log("WARN", msg, nil, fields)
}

func (a *StdlibAdapter) Error(msg string, err error, fields map[string]any) {
	a.log("ERROR", msg, err, fields)
}

func (a *StdlibAdapter) log(level, msg string, err error, fields map[string]any) {
	parts := make([]string, 0, len(fields)+2)
	parts = append(parts, fmt.Sprintf("level=%s", level))
	if err != nil {
		parts = append(parts, fmt.Sprintf("error=%v", err))
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", key, fields[key]))
	}
	a.logger.Printf("%s %s", msg, strings.Join(parts, " "))
}

// SlogAdapter adapts a *slog.Logger to Logger.
type SlogAdapter struct {
	logger *slog.Logger
}

// NewSlogAdapter returns a Logger backed by l. A nil logger yields a no-op
// logger.
func NewSlogAdapter(l *slog.Logger) Logger {
	if l == nil {
		return NewNoopLogger()
	}
	return &SlogAdapter{logger: l}
}

func (a *SlogAdapter) Debug(msg string, fields map[string]any) {
	a.logger.Debug(msg, args(fields)...)
}

func (a *SlogAdapter) Info(msg string, fields map[string]any) {
	a.logger.Info(msg, args(fields)...)
}

func (a *SlogAdapter) Warn(msg string, fields map[string]any) {
	a.logger.Warn(msg, args(fields)...)
}

func (a *SlogAdapter) Error(msg string, err error, fields map[string]any) {
	attrs := args(fields)
	if err != nil {
		attrs = append(attrs, slog.Any("error", err))
	}
	a.logger.Error(msg, attrs...)
}

func args(fields map[string]any) []any {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]any, 0, len(keys)*2)
	for _, key := range keys {
		out = append(out, key, fields[key])
	}
	return out
}
