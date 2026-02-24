package processor

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"coraza-extproc/internal/types"

	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
)

// generateSecureStreamID creates a cryptographically secure stream ID
func generateSecureStreamID() string {
	bytes := make([]byte, types.StreamIDLength)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID if crypto/rand fails
		return fmt.Sprintf("fallback_%d_%d", time.Now().UnixNano(), os.Getpid())
	}
	return hex.EncodeToString(bytes)
}

// getStreamIDFromRequest extracts stream ID from request headers
func getStreamIDFromRequest(req *envoy_service_ext_proc_v3.ProcessingRequest) string {
	if req == nil {
		return ""
	}

	switch r := req.Request.(type) {
	case *envoy_service_ext_proc_v3.ProcessingRequest_RequestHeaders:
		if r.RequestHeaders != nil && r.RequestHeaders.Headers != nil {
			for _, header := range r.RequestHeaders.Headers.Headers {
				if header == nil {
					continue
				}

				headerKey := strings.ToLower(header.Key)
				if headerKey == "x-request-id" || headerKey == "x-trace-id" {
					headerValue := string(header.RawValue)
					if headerValue != "" {
						slog.Debug("Found request ID in headers", slog.String("key", header.Key))
						return headerValue
					}
				}
			}
		}
	}
	return ""
}

// getStreamID determines a unique ID for the stream
func (p *Processor) getStreamID(req *envoy_service_ext_proc_v3.ProcessingRequest) string {
	// Try to get ID from request headers first
	if streamID := getStreamIDFromRequest(req); streamID != "" {
		return streamID
	}

	// Generate secure random ID as fallback
	streamID := generateSecureStreamID()
	slog.Debug("Generated secure stream ID")
	return streamID
}

// getStreamInfo retrieves stream information
func (p *Processor) getStreamInfo(streamID string) *types.StreamInfo {
	p.streamMutex.RLock()
	defer p.streamMutex.RUnlock()
	return p.streams[streamID]
}

// setStreamInfo stores stream information
func (p *Processor) setStreamInfo(streamID string, info *types.StreamInfo) {
	p.streamMutex.Lock()
	defer p.streamMutex.Unlock()

	info.LastActivity = time.Now()
	p.streams[streamID] = info

	slog.Debug("Stored stream info",
		slog.String("streamID", streamID),
		slog.Bool("isWebSocket", info.IsWebSocket),
		slog.Int("totalStreams", len(p.streams)))
}

// removeStreamInfo cleans up stream information
func (p *Processor) removeStreamInfo(streamID string) {
	p.streamMutex.Lock()
	defer p.streamMutex.Unlock()

	if info, exists := p.streams[streamID]; exists {
		if info.Transaction != nil {
			info.Transaction.ProcessLogging()
			info.Transaction.Close()
		}
		delete(p.streams, streamID)

		slog.Debug("Removed stream info",
			slog.String("streamID", streamID),
			slog.Bool("wasWebSocket", info.IsWebSocket),
			slog.Duration("age", time.Since(info.CreatedAt)),
			slog.Int("remainingStreams", len(p.streams)))
	}
}

// startCleanupRoutine starts the background cleanup process
func (p *Processor) startCleanupRoutine() {
	go func() {
		ticker := time.NewTicker(types.CleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				p.cleanupExpiredStreams()
			case <-p.shutdownChan:
				return
			}
		}
	}()
}

// cleanupExpiredStreams removes expired stream information
func (p *Processor) cleanupExpiredStreams() {
	p.streamMutex.Lock()
	defer p.streamMutex.Unlock()

	now := time.Now()
	for streamID, streamInfo := range p.streams {
		var shouldCleanup bool
		var reason string

		if streamInfo.IsWebSocket {
			if now.Sub(streamInfo.LastActivity) > types.WebSocketTimeout {
				shouldCleanup = true
				reason = "WebSocket inactive timeout"
			}
		} else {
			if now.Sub(streamInfo.CreatedAt) > types.HTTPRequestTimeout {
				shouldCleanup = true
				reason = "HTTP request timeout"
			}
		}

		if shouldCleanup {
			slog.Debug("Cleaning up expired stream",
				slog.String("streamID", streamID),
				slog.String("reason", reason))

			if streamInfo.Transaction != nil {
				streamInfo.Transaction.ProcessLogging()
				streamInfo.Transaction.Close()
			}
			delete(p.streams, streamID)
		}
	}
}

// logActiveStreams logs debug information about active streams
func (p *Processor) logActiveStreams() {
	p.streamMutex.RLock()
	defer p.streamMutex.RUnlock()

	slog.Debug("=== Active Streams Debug ===")
	if len(p.streams) == 0 {
		slog.Debug("No active streams")
		return
	}

	for streamID, info := range p.streams {
		slog.Debug("Stream detail",
			slog.String("streamID", streamID),
			slog.String("authority", info.Authority),
			slog.Bool("hasTransaction", info.Transaction != nil),
			slog.Duration("age", time.Since(info.CreatedAt)))
	}
	slog.Debug("=== End Active Streams ===")
}
