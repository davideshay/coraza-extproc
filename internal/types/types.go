package types

import (
	"time"

	"github.com/corazawaf/coraza/v3/types"
)

// StreamInfo holds information about an active stream
type StreamInfo struct {
	StreamID     string
	Authority    string
	URI          string
	Transaction  types.Transaction
	CreatedAt    time.Time
	IsWebSocket  bool
	LastActivity time.Time
}

// Configuration constants
const (
	// Timeout durations
	HTTPRequestTimeout  = 5 * time.Minute
	WebSocketTimeout    = 30 * time.Minute
	CleanupInterval     = 30 * time.Second
	ConfigWatchInterval = 5 * time.Second

	// Size limits
	MaxConfigFileSize = 10 * 1024 * 1024 // 10MB
	StreamIDLength    = 16               // bytes for random ID

	// Default paths
	DefaultBaseDir = "/etc/coraza/"
	DefaultConfDir = "conf"
	DefaultPort    = "9000"
)

// Common error messages
const (
	ErrNoAuthority    = "no authority found in headers"
	ErrNoWAFEngine    = "no WAF engine found for authority"
	ErrInvalidHeaders = "invalid headers structure"
	ErrNoStreamInfo   = "no stream info found"
	ErrNoTransaction  = "no transaction found"
)
