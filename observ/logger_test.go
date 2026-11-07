package observ

import (
	"bytes"
	"errors"
	"log"
	"log/slog"
	"strings"
	"testing"
)

func TestNoopLogger(t *testing.T) {
	t.Parallel()

	logger := NewNoopLogger()
	logger.Debug("debug", map[string]any{"a": 1})
	logger.Info("info", map[string]any{"a": 1})
	logger.Warn("warn", map[string]any{"a": 1})
	logger.Error("error", errors.New("boom"), map[string]any{"a": 1})
}

func TestStdlibAdapter(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := NewStdlibAdapter(log.New(&buf, "", 0))
	logger.Debug("debug message", map[string]any{"z": 2, "a": 1})
	logger.Info("info message", nil)
	logger.Warn("warn message", map[string]any{"k": "v"})
	logger.Error("error message", errors.New("boom"), map[string]any{"k": "v"})

	out := buf.String()
	for _, want := range []string{
		"debug message level=DEBUG a=1 z=2",
		"info message level=INFO",
		"warn message level=WARN k=v",
		"error message level=ERROR error=boom k=v",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output %q does not contain %q", out, want)
		}
	}
}

func TestStdlibAdapterNilLogger(t *testing.T) {
	t.Parallel()

	logger := NewStdlibAdapter(nil)
	if _, ok := logger.(NoopLogger); !ok {
		t.Fatalf("expected NoopLogger, got %T", logger)
	}
}

func TestSlogAdapter(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := NewSlogAdapter(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	logger.Debug("debug message", map[string]any{"z": 2, "a": 1})
	logger.Info("info message", nil)
	logger.Warn("warn message", map[string]any{"k": "v"})
	logger.Error("error message", errors.New("boom"), map[string]any{"k": "v"})

	out := buf.String()
	for _, want := range []string{
		"msg=\"debug message\"",
		"a=1",
		"z=2",
		"msg=\"info message\"",
		"msg=\"warn message\"",
		"msg=\"error message\"",
		"error=boom",
		"k=v",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output %q does not contain %q", out, want)
		}
	}
}

func TestSlogAdapterNilLogger(t *testing.T) {
	t.Parallel()

	logger := NewSlogAdapter(nil)
	if _, ok := logger.(NoopLogger); !ok {
		t.Fatalf("expected NoopLogger, got %T", logger)
	}
}
