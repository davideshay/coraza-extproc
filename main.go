package main

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/fsnotify/fsnotify"
	"google.golang.org/grpc"
)

type CorazaExtProc struct {
	envoy_service_ext_proc_v3.UnimplementedExternalProcessorServer
	wafEngines   map[string]coraza.WAF        // domain -> WAF engine
	transactions map[string]types.Transaction // stream ID -> transaction
	streamData   map[string]*StreamInfo       // stream ID -> stream info
	mutex        sync.RWMutex
	txMutex      sync.RWMutex
	baseDir      string
	confDir      string
	watcher      *fsnotify.Watcher
}

type StreamInfo struct {
	StreamID     string
	Authority    string
	Transaction  types.Transaction
	CreatedAt    time.Time
	IsWebSocket  bool
	LastActivity time.Time
}

func NewCorazaExtProc() (*CorazaExtProc, error) {
	baseDir := os.Getenv("BASE_DIR")
	if baseDir == "" {
		baseDir = "/etc/coraza/"
	}

	if !strings.HasSuffix(baseDir, "/") {
		baseDir = baseDir + "/"
	}

	confDir := os.Getenv("CONF_DIR")
	if confDir == "" {
		confDir = baseDir + "conf"
	}

	if !strings.HasSuffix(confDir, "/") {
		confDir = confDir + "/"
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %v", err)
	}

	processor := &CorazaExtProc{
		wafEngines:   make(map[string]coraza.WAF),
		transactions: make(map[string]types.Transaction),
		streamData:   make(map[string]*StreamInfo),
		baseDir:      baseDir,
		confDir:      confDir,
		watcher:      watcher,
	}

	// Load initial configurations
	if err := processor.loadConfigFromDirectory(); err != nil {
		slog.Error("Failed to load initial config:", slog.Any("err", err))
	}

	// Start watching for file changes
	go processor.watchConfigDirectory()

	// Start cleanup routine for orphaned transactions
	go processor.cleanupRoutine()

	return processor, nil
}

func (c *CorazaExtProc) loadConfigFromDirectory() error {
	// Clear existing engines
	c.mutex.Lock()
	c.wafEngines = make(map[string]coraza.WAF)
	c.mutex.Unlock()

	// Walk through the conf directory
	return filepath.WalkDir(c.confDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			slog.Error("Error accessing path:", slog.String("path", path), slog.Any("err", err))
			return nil // Continue walking
		}

		// Skip processing ALL files and the tree inside hidden directories (k8s config mounts)
		if d.IsDir() && strings.HasPrefix(d.Name(), ".") && path != c.confDir {
			return filepath.SkipDir
		}

		// Skip directories and non-.conf files
		if d.IsDir() || strings.HasPrefix(d.Name(), ".") || !strings.HasSuffix(d.Name(), ".conf") {
			return nil
		}

		// Extract domain from filename (e.g., "example.com.conf" -> "example.com")
		domain := strings.TrimSuffix(d.Name(), ".conf")

		// Read conf file
		confContent, err := os.ReadFile(path)
		if err != nil {
			slog.Error("Failed to read config file:", slog.String("path", path), slog.Any("err", err))
			return nil
		}

		// Create WAF engine
		waf, err := coraza.NewWAF(coraza.NewWAFConfig().
			WithRootFS(os.DirFS(c.baseDir)).
			WithDirectives(string(confContent)))
		if err != nil {
			slog.Error("Failed to create WAF for domain:", slog.String("domain", domain), slog.Any("err", err))
			return nil
		}

		c.mutex.Lock()
		c.wafEngines[domain] = waf
		c.mutex.Unlock()

		slog.Info("Loaded WAF rules for domain and file:", slog.String("domain", domain), slog.String("path", path))
		return nil
	})
}

func (c *CorazaExtProc) watchConfigDirectory() {
	previousHashes := make(map[string][32]byte)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		changed := false

		filepath.WalkDir(c.confDir, func(path string, d fs.DirEntry, err error) error {
			if d.IsDir() && strings.HasPrefix(d.Name(), ".") && path != c.confDir {
				return filepath.SkipDir
			}

			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".conf") {
				return nil
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			hash := sha256.Sum256(content)
			if oldHash, exists := previousHashes[path]; !exists || oldHash != hash {
				slog.Info("Detected config file change:", slog.String("path", path))
				previousHashes[path] = hash
				changed = true
			}
			return nil
		})

		if changed {
			if err := c.loadConfigFromDirectory(); err != nil {
				slog.Error("Failed to reload config:", slog.Any("error", err))
			}
		}
	}
}

func (c *CorazaExtProc) cleanupRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		c.txMutex.Lock()
		now := time.Now()
		for streamID, streamInfo := range c.streamData {
			var shouldCleanup bool
			var reason string

			if streamInfo.IsWebSocket {
				// WebSocket connections can be long-lived, use different timeout
				if now.Sub(streamInfo.LastActivity) > 30*time.Minute {
					shouldCleanup = true
					reason = "WebSocket inactive for 30 minutes"
				}
			} else {
				// Regular HTTP requests should complete quickly
				if now.Sub(streamInfo.CreatedAt) > 5*time.Minute {
					shouldCleanup = true
					reason = "HTTP request older than 5 minutes"
				}
			}

			if shouldCleanup {
				slog.Debug("Cleaning up stream:", slog.String("streamID", streamID), slog.String("reason", reason))
				if streamInfo.Transaction != nil {
					streamInfo.Transaction.ProcessLogging()
					streamInfo.Transaction.Close()
				}
				delete(c.streamData, streamID)
				delete(c.transactions, streamID)
			}
		}
		c.txMutex.Unlock()
	}
}

func (c *CorazaExtProc) logAvailableEngines() {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	slog.Debug("Available WAF engines:")
	for domain := range c.wafEngines {
		slog.Debug("  Domain:", slog.String("domain", domain))
	}
	if len(c.wafEngines) == 0 {
		slog.Error("No WAF engines loaded!")
	}
}

func (c *CorazaExtProc) getWAFEngine(authority string) coraza.WAF {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// Try exact match first
	if waf, exists := c.wafEngines[authority]; exists {
		slog.Debug("Found exact match for:", slog.String("authority", authority))
		return waf
	}

	// Try wildcard matches
	for domain, waf := range c.wafEngines {
		if strings.HasPrefix(domain, "*.") {
			wildcard := strings.TrimPrefix(domain, "*.")
			if strings.HasSuffix(authority, wildcard) {
				slog.Debug("Found wildcard match:", slog.String("authority", authority), slog.String("domain", domain))
				return waf
			}
		}
	}

	// Return default WAF if exists
	if waf, exists := c.wafEngines["default"]; exists {
		slog.Debug("Using default WAF engine for:", slog.String("authority", authority))
		return waf
	}

	slog.Error("No WAF engine found for:", slog.String("authority", authority))
	return nil
}

// Get stream ID from request attributes or fallback methods
func (c *CorazaExtProc) getStreamIDFromRequest(req *envoy_service_ext_proc_v3.ProcessingRequest) string {
	if req != nil {
		switch r := req.Request.(type) {
		case *envoy_service_ext_proc_v3.ProcessingRequest_RequestHeaders:
			if r.RequestHeaders != nil {
				if r.RequestHeaders.Headers != nil {
					for _, header := range r.RequestHeaders.Headers.Headers {
						if header != nil {
							headerKey := strings.ToLower(header.Key)
							headerValue := string(header.RawValue)
							if headerKey == "x-request-id" || headerKey == "x-trace-id" {
								slog.Debug("Found potential request ID in headers:", slog.String("key", header.Key), slog.String("value", headerValue))
								return headerValue
							}
						}
					}
				}
			}
		}
	}
	return ""
}

// Improved stream ID generation with multiple fallback methods
func (c *CorazaExtProc) getStreamID(stream envoy_service_ext_proc_v3.ExternalProcessor_ProcessServer, req *envoy_service_ext_proc_v3.ProcessingRequest) string {
	// Method 1: Try request attributes first
	if streamID := c.getStreamIDFromRequest(req); streamID != "" {
		return streamID
	}

	ctx := stream.Context()

	// Method 2: Use context pointer as consistent identifier
	streamPtr := fmt.Sprintf("%p", ctx)
	slog.Info("Using context pointer as stream ID:", slog.String("streamPtr", streamPtr))
	return streamPtr
}

func (c *CorazaExtProc) getStreamInfo(streamID string) *StreamInfo {
	c.txMutex.RLock()
	defer c.txMutex.RUnlock()
	return c.streamData[streamID]
}

func (c *CorazaExtProc) setStreamInfo(streamID string, info *StreamInfo) {
	c.txMutex.Lock()
	defer c.txMutex.Unlock()
	info.LastActivity = time.Now()
	c.streamData[streamID] = info
	c.transactions[streamID] = info.Transaction
	slog.Debug("Stored stream info for ID:", slog.String("streamID", streamID), slog.Bool("IsWebSocket", info.IsWebSocket), slog.Int("streamlen", len(c.streamData)))
}

func (c *CorazaExtProc) removeStreamInfo(streamID string) {
	c.txMutex.Lock()
	defer c.txMutex.Unlock()
	if info, exists := c.streamData[streamID]; exists {
		if info.Transaction != nil {
			info.Transaction.ProcessLogging()
			info.Transaction.Close()
		}
		delete(c.streamData, streamID)
		delete(c.transactions, streamID)
		slog.Debug("Removed stream info for ID :", slog.String("streamID", streamID), slog.Int("remainingStreams", len(c.streamData)))
	}
}

func (c *CorazaExtProc) logAllStreams() {
	c.txMutex.RLock()
	defer c.txMutex.RUnlock()
	slog.Debug("=== Active Streams Debug ===")
	if len(c.streamData) == 0 {
		slog.Debug("No active streams")
		return
	}
	for streamID, info := range c.streamData {
		slog.Debug("Stream Detail",
			slog.String("streamID", streamID), slog.String("authority", info.Authority),
			slog.Bool("HasTransaction", info.Transaction != nil),
			slog.Any("age", time.Since(info.CreatedAt)))
	}
	slog.Debug("=== End Active Streams ===")
}

func (c *CorazaExtProc) Process(stream envoy_service_ext_proc_v3.ExternalProcessor_ProcessServer) error {
	slog.Debug("=== New gRPC stream connection ===")

	// We'll determine the stream ID from the first request
	var streamID string

	// Ensure cleanup happens when stream ends
	defer func() {
		if streamID != "" {
			slog.Debug("Stream ending - cleaning up", slog.String("streamID", streamID))
			c.removeStreamInfo(streamID)
		}
	}()

	for {
		req, err := stream.Recv()
		if err != nil {
			if err.Error() != "EOF" {
				if streamID != "" {
					slog.Error("Error receiving from stream", slog.String("streamID", streamID), slog.Any("error", err))
				} else {
					slog.Error("Error receiving from stream:", slog.Any("error", err))
				}
			}
			return err
		}

		// Get stream ID from the first request if we don't have it yet
		if streamID == "" {
			streamID = c.getStreamID(stream, req)
			slog.Debug("Stream ID:", slog.String("streamID", streamID))
		}

		slog.Debug("Received request type for stream", slog.String("streamID", streamID), slog.Any("request", req.Request))

		var resp *envoy_service_ext_proc_v3.ProcessingResponse

		switch r := req.Request.(type) {
		case *envoy_service_ext_proc_v3.ProcessingRequest_RequestHeaders:
			slog.Debug("Processing RequestHeaders for stream", slog.String("streamID", streamID))
			resp = c.processRequestHeaders(r.RequestHeaders, streamID)
		case *envoy_service_ext_proc_v3.ProcessingRequest_RequestBody:
			slog.Debug("Processing RequestBody for stream ", slog.String("streamID", streamID))
			c.logAllStreams() // Debug active streams
			resp = c.processRequestBody(r.RequestBody, streamID)
		case *envoy_service_ext_proc_v3.ProcessingRequest_ResponseHeaders:
			slog.Debug("Processing ResponseHeaders for stream", slog.String("streamID", streamID))
			resp = c.processResponseHeaders(r.ResponseHeaders, streamID)
		default:
			slog.Error("Unknown request type for stream, sending continue response", slog.String("streamID", streamID))
			resp = &envoy_service_ext_proc_v3.ProcessingResponse{
				Response: &envoy_service_ext_proc_v3.ProcessingResponse_ImmediateResponse{
					ImmediateResponse: &envoy_service_ext_proc_v3.ImmediateResponse{
						Status: &envoy_type_v3.HttpStatus{Code: envoy_type_v3.StatusCode_Continue},
					},
				},
			}
		}

		slog.Debug("Sending response type for stream", slog.String("streamID", streamID), slog.Any("response", resp.Response))
		if err := stream.Send(resp); err != nil {
			slog.Error("Error sending response for stream", slog.String("streamID", streamID), slog.Any("error", err))
			return err
		}
		slog.Debug("Response sent successfully for stream", slog.String("streamID", streamID))
	}
}

func (c *CorazaExtProc) processRequestHeaders(headers *envoy_service_ext_proc_v3.HttpHeaders, streamID string) *envoy_service_ext_proc_v3.ProcessingResponse {
	slog.Debug("=== Processing Request Headers for stream  ===", slog.String("streamID", streamID))

	if headers == nil || headers.Headers == nil {
		slog.Error("ERROR: headers structure is nil")
		return c.continueRequest()
	}

	// Extract authority/host and detect WebSocket upgrade
	var authority string
	var isWebSocket bool
	var connection, upgrade string

	for _, header := range headers.Headers.Headers {
		if header == nil {
			continue
		}
		headerKeyLower := strings.ToLower(header.Key)
		headerValue := strings.ToLower(string(header.RawValue))

		switch headerKeyLower {
		case ":authority", "host":
			authority = string(header.RawValue)
		case "connection":
			connection = headerValue
		case "upgrade":
			upgrade = headerValue
		}
	}

	// Detect WebSocket upgrade request
	if strings.Contains(connection, "upgrade") && upgrade == "websocket" {
		isWebSocket = true
		slog.Info("Detected WebSocket upgrade request for authority:", slog.String("authority", authority))
	}

	if authority == "" {
		slog.Error("No authority found in headers - continuing request")
		return c.continueRequest()
	}

	// Get WAF engine for this domain
	waf := c.getWAFEngine(authority)
	if waf == nil {
		slog.Error("No WAF engine found for authority - continuing request", slog.String("authority", authority))
		c.logAvailableEngines()
		return c.continueRequest()
	}

	// Create transaction and store stream info with WebSocket detection
	tx := waf.NewTransaction()
	streamInfo := &StreamInfo{
		StreamID:     streamID,
		Authority:    authority,
		Transaction:  tx,
		CreatedAt:    time.Now(),
		IsWebSocket:  isWebSocket,
		LastActivity: time.Now(),
	}
	c.setStreamInfo(streamID, streamInfo)

	// Extract method, URI, protocol
	var method, uri, protocol string
	for _, header := range headers.Headers.Headers {
		if header == nil {
			continue
		}
		headerKeyLower := strings.ToLower(header.Key)
		switch headerKeyLower {
		case ":method":
			method = string(header.RawValue)
		case ":path":
			uri = string(header.RawValue)
		case ":scheme":
			protocol = string(header.RawValue)
		}
	}

	if method == "" || uri == "" || protocol == "" {
		slog.Error("Missing required pseudo-headers", slog.String("method", method), slog.String("uri", uri), slog.String("protocol", protocol))
		return c.continueRequest()
	}

	// Set request line
	tx.ProcessURI(uri, method, protocol)

	// Process headers
	for _, header := range headers.Headers.Headers {
		if strings.HasPrefix(header.Key, ":") {
			continue // Skip pseudo headers
		}
		tx.AddRequestHeader(header.Key, string(header.RawValue))
	}

	// Check if request should be blocked
	if it := tx.ProcessRequestHeaders(); it != nil {
		slog.Error("WAF BLOCKED REQUEST", slog.String("action", it.Action), slog.Int("ruleID:", it.RuleID))
		c.removeStreamInfo(streamID)
		return c.createBlockResponse(it)
	}

	slog.Debug("WAF allowed request headers", slog.String("authority", authority), slog.Bool("isWebSocket", isWebSocket))
	return c.continueRequest()
}

// Update activity timestamp when processing body
func (c *CorazaExtProc) processRequestBody(body *envoy_service_ext_proc_v3.HttpBody, streamID string) *envoy_service_ext_proc_v3.ProcessingResponse {
	slog.Debug("=== Processing Request Body for stream ===", slog.String("streamID", streamID))

	// Update activity timestamp
	if streamInfo := c.getStreamInfo(streamID); streamInfo != nil {
		streamInfo.LastActivity = time.Now()
	}

	if body == nil {
		slog.Error("ERROR: body is nil")
		return c.continueRequestBody()
	}

	streamInfo := c.getStreamInfo(streamID)
	if streamInfo == nil {
		slog.Error("ERROR: No stream info found for stream", slog.String("streamID", streamID))
		return c.continueRequestBody()
	}

	if streamInfo.Transaction == nil {
		slog.Error("ERROR: Stream info exists but transaction is nil for stream", slog.String("streamID", streamID))
		return c.continueRequestBody()
	}

	tx := streamInfo.Transaction
	slog.Debug("Processing body chunk of size", slog.Int("size", len(body.Body)), slog.Bool("websocket", streamInfo.IsWebSocket))

	if len(body.Body) > 0 {
		if _, _, err := tx.WriteRequestBody(body.Body); err != nil {
			slog.Error("Failed to write request body", slog.Any("error", err))
			c.removeStreamInfo(streamID)
			return c.continueRequestBody()
		}
	}

	if body.EndOfStream {
		slog.Debug("End of stream reached for stream", slog.String("streamID", streamID))
		if it, err := tx.ProcessRequestBody(); err != nil {
			slog.Error("Failed to process request body", slog.Any("error", err))
		} else if it != nil {
			slog.Error("WAF BLOCKED REQUEST BODY", slog.String("action", it.Action), slog.Int("ruleID", it.RuleID))
			c.removeStreamInfo(streamID)
			return c.createBlockResponse(it)
		}

		// For WebSocket connections, don't remove stream info immediately
		// as the connection might stay open for data exchange
		if !streamInfo.IsWebSocket {
			slog.Debug("Removing stream info for completed HTTP request")
			c.removeStreamInfo(streamID)
		} else {
			slog.Debug("Keeping WebSocket stream info active")
			streamInfo.LastActivity = time.Now()
		}
	}

	return c.continueRequestBody()
}

func (c *CorazaExtProc) processResponseHeaders(headers *envoy_service_ext_proc_v3.HttpHeaders, streamID string) *envoy_service_ext_proc_v3.ProcessingResponse {
	// Clean up any remaining stream info for this stream
	c.removeStreamInfo(streamID)

	return &envoy_service_ext_proc_v3.ProcessingResponse{
		Response: &envoy_service_ext_proc_v3.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &envoy_service_ext_proc_v3.HeadersResponse{
				Response: &envoy_service_ext_proc_v3.CommonResponse{
					Status: envoy_service_ext_proc_v3.CommonResponse_CONTINUE,
				},
			},
		},
	}
}

func (c *CorazaExtProc) continueRequest() *envoy_service_ext_proc_v3.ProcessingResponse {
	return &envoy_service_ext_proc_v3.ProcessingResponse{
		Response: &envoy_service_ext_proc_v3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &envoy_service_ext_proc_v3.HeadersResponse{
				Response: &envoy_service_ext_proc_v3.CommonResponse{
					Status: envoy_service_ext_proc_v3.CommonResponse_CONTINUE,
				},
			},
		},
	}
}

func (c *CorazaExtProc) continueRequestBody() *envoy_service_ext_proc_v3.ProcessingResponse {
	return &envoy_service_ext_proc_v3.ProcessingResponse{
		Response: &envoy_service_ext_proc_v3.ProcessingResponse_RequestBody{
			RequestBody: &envoy_service_ext_proc_v3.BodyResponse{
				Response: &envoy_service_ext_proc_v3.CommonResponse{
					Status: envoy_service_ext_proc_v3.CommonResponse_CONTINUE,
				},
			},
		},
	}
}

func (c *CorazaExtProc) createBlockResponse(it *types.Interruption) *envoy_service_ext_proc_v3.ProcessingResponse {
	slog.Error("*** REQUEST BLOCKED ***", slog.String("action", it.Action), slog.Int("ruleID", it.RuleID), slog.Any("data", it.Data))

	return &envoy_service_ext_proc_v3.ProcessingResponse{
		Response: &envoy_service_ext_proc_v3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &envoy_service_ext_proc_v3.ImmediateResponse{
				Status: &envoy_type_v3.HttpStatus{
					Code: envoy_type_v3.StatusCode_Forbidden,
				},
				Body: fmt.Sprintf("Request blocked by WAF - Rule ID: %d, Action: %s", it.RuleID, it.Action),
				Headers: &envoy_service_ext_proc_v3.HeaderMutation{
					SetHeaders: []*envoy_config_core_v3.HeaderValueOption{
						{
							Header: &envoy_config_core_v3.HeaderValue{
								Key:   "content-type",
								Value: "text/plain",
							},
						},
					},
				},
			},
		},
	}
}

func (c *CorazaExtProc) Close() error {
	// Clean up all stream info and transactions
	c.txMutex.Lock()
	for streamID, info := range c.streamData {
		if info.Transaction != nil {
			info.Transaction.ProcessLogging()
			info.Transaction.Close()
		}
		delete(c.streamData, streamID)
		delete(c.transactions, streamID)
	}
	c.txMutex.Unlock()

	if c.watcher != nil {
		return c.watcher.Close()
	}
	return nil
}

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

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9000"
	}

	level := getLogLevelFromEnv("LOG_LEVEL")
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})
	slog.SetDefault(slog.New(handler))

	slog.Info("=== Starting Coraza ext_proc server 8/7 3:15PM ===")
	slog.Info("Port", slog.String("port", port))
	slog.Info("Go version", slog.String("version", strings.TrimPrefix(runtime.Version(), "go")))

	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		slog.Error("Failed to listen", slog.Any("error", err))
	}
	slog.Info("TCP listener created successfully", slog.String("port", port))

	processor, err := NewCorazaExtProc()
	if err != nil {
		slog.Error("Failed to create processor", slog.Any("error", err))
	}
	defer processor.Close()
	slog.Info("Coraza processor created successfully")

	s := grpc.NewServer()
	envoy_service_ext_proc_v3.RegisterExternalProcessorServer(s, processor)
	slog.Info("gRPC server created and ext_proc service registered")

	slog.Info("Watching config directory", slog.String("dir", processor.confDir))
	processor.logAvailableEngines()

	slog.Info("=== Server ready - waiting for connections ===")
	if err := s.Serve(lis); err != nil {
		slog.Error("Failed to serve", slog.Any("error", err))
	}
}
