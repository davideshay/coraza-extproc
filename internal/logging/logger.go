package logging

import (
	"context"
	"log/slog"
	"os"
	"runtime"
	"strings"
)

// Setup configures and returns a structured logger
func Setup() *slog.Logger {
	level := getLogLevelFromEnv("LOG_LEVEL")

	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level:     level,
		AddSource: level == slog.LevelDebug, // Add source info for debug
	})

	logger := slog.New(handler)

	// Log startup info
	logger.Info("Logger initialized",
		slog.String("level", level.Level().String()),
		slog.String("go_version", strings.TrimPrefix(runtime.Version(), "go")))

	return logger
}

// getLogLevelFromEnv parses log level from environment variable
func getLogLevelFromEnv(envVar string) slog.Leveler {
	levelStr := strings.ToLower(os.Getenv(envVar))
	switch levelStr {
	case "debug", "d", "1":
		return slog.LevelDebug
	case "info", "information", "i", "2":
		return slog.LevelInfo
	case "warn", "warning", "w", "3":
		return slog.LevelWarn
	case "error", "err", "e", "4":
		return slog.LevelError
	default:
		return slog.LevelInfo // default level
	}
}

// Security logs sensitive operations
func LogSecurityEvent(event string, fields ...slog.Attr) {
	attrs := append([]slog.Attr{
		slog.String("event_type", "security"),
		slog.String("event", event),
	}, fields...)

	slog.LogAttrs(context.Background(), slog.LevelWarn, "Security Event", attrs...)
}

// LogWAFAction logs WAF actions for monitoring
func LogWAFAction(action, authority string, ruleID int, blocked bool) {
	slog.Info("WAF Action",
		slog.String("action", action),
		slog.String("authority", authority),
		slog.Int("rule_id", ruleID),
		slog.Bool("blocked", blocked))
}
