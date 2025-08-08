package logging

import (
	"coraza-extproc/internal/types"
	"log/slog"
	"os"
	"runtime"
	"strings"

	coraza_types "github.com/corazawaf/coraza/v3/types"
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
func LogSecurityEvent(msg string, streamInfo types.StreamInfo, interruption *coraza_types.Interruption) {
	slog.Warn("WAF Event", slog.String("msg", msg), slog.String("authority", streamInfo.Authority),
		slog.String("uri", streamInfo.URI), slog.String("action", interruption.Action),
		slog.Int("ruleID", interruption.RuleID))

}
