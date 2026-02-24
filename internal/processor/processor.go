package processor

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"coraza-extproc/internal/config"
	"coraza-extproc/internal/types"

	"github.com/corazawaf/coraza/v3"
	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
)

// Processor handles external processing requests from Envoy
type Processor struct {
	envoy_service_ext_proc_v3.UnimplementedExternalProcessorServer

	// WAF engines by domain
	wafEngines map[string]coraza.WAF
	wafMutex   sync.RWMutex

	// Active streams
	streams     map[string]*types.StreamInfo
	streamMutex sync.RWMutex

	// Configuration
	configLoader *config.Loader
	shutdownChan chan struct{}
}

// New creates a new processor instance
func New() (*Processor, error) {
	baseDir := getEnvOrDefault("BASE_DIR", types.DefaultBaseDir)
	confDir := getEnvOrDefault("CONF_DIR", baseDir+"conf")

	// Ensure trailing slashes
	if !strings.HasSuffix(baseDir, "/") {
		baseDir = baseDir + "/"
	}
	if !strings.HasSuffix(confDir, "/") {
		confDir = confDir + "/"
	}

	processor := &Processor{
		wafEngines:   make(map[string]coraza.WAF),
		streams:      make(map[string]*types.StreamInfo),
		shutdownChan: make(chan struct{}),
	}

	// Create config loader with callback
	loader, err := config.NewLoader(baseDir, confDir, processor.onConfigChange)
	if err != nil {
		return nil, fmt.Errorf("failed to create config loader: %w", err)
	}
	processor.configLoader = loader

	// Load initial configuration
	if err := loader.LoadInitial(); err != nil {
		slog.Error("Failed to load initial config", slog.Any("err", err))
	}

	// Start config watching
	loader.StartWatching()

	// Start cleanup routine
	processor.startCleanupRoutine()

	slog.Info("Processor initialized",
		slog.String("baseDir", baseDir),
		slog.String("confDir", confDir))

	return processor, nil
}

// onConfigChange is called when configuration changes
func (p *Processor) onConfigChange(newEngines map[string]coraza.WAF) {
	p.wafMutex.Lock()
	oldEngines := p.wafEngines
	p.wafEngines = newEngines
	p.wafMutex.Unlock()

	// Clean up old engines if needed
	for domain := range oldEngines {
		slog.Debug("Cleaned up old WAF engine", slog.String("domain", domain))
	}

	slog.Info("WAF engines updated", slog.Int("count", len(newEngines)))
}

// Process handles the main gRPC stream processing
func (p *Processor) Process(stream envoy_service_ext_proc_v3.ExternalProcessor_ProcessServer) error {
	slog.Debug("=== New gRPC stream connection ===")

	var streamID string

	// Ensure cleanup when stream ends
	defer func() {
		if streamID != "" {
			// Only log and cleanup if stream still exists
			if info := p.getStreamInfo(streamID); info != nil {
				slog.Debug("Stream ending - cleaning up",
					slog.String("streamID", streamID),
					slog.Bool("wasWebSocket", info.IsWebSocket))
				p.removeStreamInfo(streamID)
			}
		}
	}()

	for {
		req, err := stream.Recv()
		if err != nil {
			// Check if this is a context cancellation (client disconnected or stream closed)
			errStr := err.Error()
			if errStr != "EOF" && !strings.Contains(errStr, "context canceled") && !strings.Contains(errStr, "Canceled") {
				if streamID != "" {
					slog.Error("Error receiving from stream", slog.String("streamID", streamID), slog.Any("error", err))
				} else {
					slog.Error("Error receiving from stream", slog.Any("error", err))
				}
			}
			// Context cancellations are normal gRPC stream lifecycle events and don't indicate a problem
			return err
		}

		// Get stream ID from first request
		if streamID == "" {
			streamID = p.getStreamID(req)
			slog.Debug("Stream ID determined", slog.String("streamID", streamID))
		}

		slog.Debug("Processing request",
			slog.String("streamID", streamID),
			slog.String("type", fmt.Sprintf("%T", req.Request)))

		// Route request to appropriate handler
		var resp *envoy_service_ext_proc_v3.ProcessingResponse

		switch r := req.Request.(type) {
		case *envoy_service_ext_proc_v3.ProcessingRequest_RequestHeaders:
			resp = p.processRequestHeaders(r.RequestHeaders, streamID)
		case *envoy_service_ext_proc_v3.ProcessingRequest_RequestBody:
			resp = p.processRequestBody(r.RequestBody, streamID)
		case *envoy_service_ext_proc_v3.ProcessingRequest_ResponseHeaders:
			resp = p.processResponseHeaders(r.ResponseHeaders, streamID)
		case *envoy_service_ext_proc_v3.ProcessingRequest_ResponseBody:
			resp = p.processResponseBody(r.ResponseBody, streamID)
		default:
			slog.Warn("Unknown request type", slog.String("streamID", streamID))
			resp = p.continueRequest()
		}

		// Send response
		if err := stream.Send(resp); err != nil {
			slog.Error("Error sending response", slog.String("streamID", streamID), slog.Any("error", err))
			return err
		}

		slog.Debug("Response sent",
			slog.String("streamID", streamID),
			slog.String("type", fmt.Sprintf("%T", req.Request)))
	}
}

// Close shuts down the processor
func (p *Processor) Close() error {
	close(p.shutdownChan)

	// Clean up all streams
	p.streamMutex.Lock()
	for streamID, info := range p.streams {
		if info.Transaction != nil {
			info.Transaction.ProcessLogging()
			info.Transaction.Close()
		}
		delete(p.streams, streamID)
	}
	p.streamMutex.Unlock()

	// Close config loader
	if p.configLoader != nil {
		return p.configLoader.Close()
	}

	slog.Info("Processor shut down")
	return nil
}

// Helper function to get environment variable with default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
