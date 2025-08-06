package main

import (
	"fmt"
	"io/fs"
	"log"
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
	"google.golang.org/grpc/metadata"
)

type CorazaExtProc struct {
	envoy_service_ext_proc_v3.UnimplementedExternalProcessorServer
	wafEngines   map[string]coraza.WAF        // domain -> WAF engine
	transactions map[string]types.Transaction // stream ID -> transaction
	streamData   map[string]*StreamInfo       // stream ID -> stream info
	mutex        sync.RWMutex
	txMutex      sync.RWMutex
	rulesDir     string
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
	rulesDir := os.Getenv("RULES_DIR")
	if rulesDir == "" {
		rulesDir = "/etc/coraza/rules"
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %v", err)
	}

	processor := &CorazaExtProc{
		wafEngines:   make(map[string]coraza.WAF),
		transactions: make(map[string]types.Transaction),
		streamData:   make(map[string]*StreamInfo),
		rulesDir:     rulesDir,
		watcher:      watcher,
	}

	// Load initial configurations
	if err := processor.loadRulesFromDirectory(); err != nil {
		log.Printf("Failed to load initial rules: %v", err)
	}

	// Start watching for file changes
	go processor.watchRulesDirectory()

	// Start cleanup routine for orphaned transactions
	go processor.cleanupRoutine()

	return processor, nil
}

func (c *CorazaExtProc) loadRulesFromDirectory() error {
	// Clear existing engines
	c.mutex.Lock()
	c.wafEngines = make(map[string]coraza.WAF)
	c.mutex.Unlock()

	// Walk through the rules directory
	return filepath.WalkDir(c.rulesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Printf("Error accessing path %s: %v", path, err)
			return nil // Continue walking
		}

		// Skip processing ALL files and the tree inside hidden directories (k8s config mounts)
		if d.IsDir() && strings.HasPrefix(d.Name(), ".") && path != c.rulesDir {
			return filepath.SkipDir
		}

		// Skip directories and non-.conf files
		if d.IsDir() || strings.HasPrefix(d.Name(), ".") || !strings.HasSuffix(d.Name(), ".conf") {
			return nil
		}

		// Extract domain from filename (e.g., "example.com.conf" -> "example.com")
		domain := strings.TrimSuffix(d.Name(), ".conf")

		// Read rules file
		rulesContent, err := os.ReadFile(path)
		if err != nil {
			log.Printf("Failed to read rules file %s: %v", path, err)
			return nil
		}

		// Create WAF engine
		waf, err := coraza.NewWAF(coraza.NewWAFConfig().
			WithDirectives(string(rulesContent)))
		if err != nil {
			log.Printf("Failed to create WAF for domain %s: %v", domain, err)
			return nil
		}

		c.mutex.Lock()
		c.wafEngines[domain] = waf
		c.mutex.Unlock()

		log.Printf("Loaded WAF rules for domain: %s from file: %s", domain, path)
		return nil
	})
}

func (c *CorazaExtProc) watchRulesDirectory() {
	// Add the rules directory to the watcher
	if err := c.watcher.Add(c.rulesDir); err != nil {
		log.Printf("Failed to add rules directory to watcher: %v", err)
		return
	}

	// Start a ticker to periodically reload rules (fallback in case fsnotify misses events)
	ticker := time.NewTicker(600 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case event, ok := <-c.watcher.Events:
			if !ok {
				return
			}

			// Only process .conf files
			if !strings.HasSuffix(event.Name, ".conf") {
				continue
			}

			log.Printf("Rules file change detected: %s (%s)", event.Name, event.Op)

			// Reload all rules after a short delay to batch multiple changes
			time.Sleep(100 * time.Millisecond)
			if err := c.loadRulesFromDirectory(); err != nil {
				log.Printf("Failed to reload rules: %v", err)
			}

		case err, ok := <-c.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Watcher error: %v", err)

		case <-ticker.C:
			// Periodic reload as fallback
			if err := c.loadRulesFromDirectory(); err != nil {
				log.Printf("Failed to reload rules during periodic check: %v", err)
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
				log.Printf("Cleaning up stream %s: %s", streamID, reason)
				if streamInfo.Transaction != nil {
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

	log.Printf("Available WAF engines:")
	for domain := range c.wafEngines {
		log.Printf("  - %s", domain)
	}
	if len(c.wafEngines) == 0 {
		log.Printf("  No WAF engines loaded!")
	}
}

func (c *CorazaExtProc) getWAFEngine(authority string) coraza.WAF {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// Try exact match first
	if waf, exists := c.wafEngines[authority]; exists {
		log.Printf("Found exact match for: %s", authority)
		return waf
	}

	// Try wildcard matches
	for domain, waf := range c.wafEngines {
		if strings.HasPrefix(domain, "*.") {
			wildcard := strings.TrimPrefix(domain, "*.")
			if strings.HasSuffix(authority, wildcard) {
				log.Printf("Found wildcard match: %s matches %s", authority, domain)
				return waf
			}
		}
	}

	// Return default WAF if exists
	if waf, exists := c.wafEngines["default"]; exists {
		log.Printf("Using default WAF engine for: %s", authority)
		return waf
	}

	log.Printf("No WAF engine found for: %s", authority)
	return nil
}

// Get stream ID from request attributes or fallback methods
func (c *CorazaExtProc) getStreamIDFromRequest(req *envoy_service_ext_proc_v3.ProcessingRequest) string {
	if req != nil {
		switch r := req.Request.(type) {
		case *envoy_service_ext_proc_v3.ProcessingRequest_RequestHeaders:
			if r.RequestHeaders != nil {
				// Log headers for debugging
				log.Printf("=== DEBUG: Request Headers Analysis ===")
				if r.RequestHeaders.Headers != nil {
					for _, header := range r.RequestHeaders.Headers.Headers {
						if header != nil {
							log.Printf("Header: %s = %s", header.Key, string(header.RawValue))
						}
					}
				}
				
				// Check attributes in detail
				if r.RequestHeaders.Attributes != nil {
					log.Printf("=== DEBUG: Attributes Analysis ===")
					log.Printf("Attributes map has %d entries", len(r.RequestHeaders.Attributes))
					
					for attrKey, attrStruct := range r.RequestHeaders.Attributes {
						log.Printf("Attribute key: '%s'", attrKey)
						if attrStruct != nil {
							log.Printf("  Struct is not nil")
							if attrStruct.Fields != nil {
								log.Printf("  Fields map has %d entries", len(attrStruct.Fields))
								for fieldKey, fieldValue := range attrStruct.Fields {
									log.Printf("    Field: '%s'", fieldKey)
									if fieldValue != nil {
										log.Printf("      Type: %T", fieldValue)
										// Try to get string value using the getter method
										if stringVal := fieldValue.GetStringValue(); stringVal != "" {
											log.Printf("      String value: '%s'", stringVal)
											// Check for request.id variations
											if attrKey == "request.id" || attrKey == "request_id" || 
											   strings.Contains(attrKey, "request") && strings.Contains(attrKey, "id") {
												log.Printf("Using attribute '%s' field '%s' as stream ID: %s", attrKey, fieldKey, stringVal)
												return stringVal
											}
										} else if numVal := fieldValue.GetNumberValue(); numVal != 0 {
											log.Printf("      Number value: %f", numVal)
										} else {
											log.Printf("      Other type or nil value")
										}
									}
								}
							} else {
								log.Printf("  Fields is nil")
							}
						} else {
							log.Printf("  Struct is nil")
						}
					}
				} else {
					log.Printf("No attributes found in request headers")
				}
				
				// Also check if there are any headers that might contain request ID
				if r.RequestHeaders.Headers != nil {
					for _, header := range r.RequestHeaders.Headers.Headers {
						if header != nil {
							headerKey := strings.ToLower(header.Key)
							headerValue := string(header.RawValue)
							if strings.Contains(headerKey, "request") && strings.Contains(headerKey, "id") ||
							   headerKey == "x-request-id" || headerKey == "x-trace-id" {
								log.Printf("Found potential request ID in headers: %s = %s", header.Key, headerValue)
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

	// Method 2: Try gRPC metadata
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		// Look for x-request-id first
		if requestIds, exists := md["x-request-id"]; exists && len(requestIds) > 0 {
			log.Printf("Using x-request-id as stream ID: %s", requestIds[0])
			return requestIds[0]
		}

		// Look for x-trace-id
		if traceIds, exists := md["x-trace-id"]; exists && len(traceIds) > 0 {
			log.Printf("Using x-trace-id as stream ID: %s", traceIds[0])
			return traceIds[0]
		}

		// Look for any other unique identifier in metadata
		for key, values := range md {
			if strings.Contains(key, "request") || strings.Contains(key, "trace") || strings.Contains(key, "id") {
				if len(values) > 0 && values[0] != "" {
					log.Printf("Using metadata %s as stream ID: %s", key, values[0])
					return values[0]
				}
			}
		}
	}

	// Method 3: Use context pointer as consistent identifier
	streamPtr := fmt.Sprintf("%p", ctx)
	log.Printf("Using context pointer as stream ID: %s", streamPtr)
	return streamPtr
}

func getAttributeKeys(attrs map[string]*envoy_config_core_v3.HeaderValue) []string {
	keys := make([]string, 0, len(attrs))
	for key := range attrs {
		keys = append(keys, key)
	}
	return keys
}

func getMetadataKeys(md metadata.MD) []string {
	keys := make([]string, 0, len(md))
	for key := range md {
		keys = append(keys, key)
	}
	return keys
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
	log.Printf("Stored stream info for ID: %s (WebSocket: %t), total streams: %d", streamID, info.IsWebSocket, len(c.streamData))
}

func (c *CorazaExtProc) removeStreamInfo(streamID string) {
	c.txMutex.Lock()
	defer c.txMutex.Unlock()
	if info, exists := c.streamData[streamID]; exists {
		if info.Transaction != nil {
			info.Transaction.Close()
		}
		delete(c.streamData, streamID)
		delete(c.transactions, streamID)
		log.Printf("Removed stream info for ID: %s, remaining streams: %d", streamID, len(c.streamData))
	}
}

func (c *CorazaExtProc) logAllStreams() {
	c.txMutex.RLock()
	defer c.txMutex.RUnlock()
	log.Printf("=== Active Streams Debug ===")
	if len(c.streamData) == 0 {
		log.Printf("No active streams")
		return
	}
	for streamID, info := range c.streamData {
		log.Printf("Stream %s: Authority=%s, HasTransaction=%t, Age=%v",
			streamID, info.Authority, info.Transaction != nil, time.Since(info.CreatedAt))
	}
	log.Printf("=== End Active Streams ===")
}

func (c *CorazaExtProc) Process(stream envoy_service_ext_proc_v3.ExternalProcessor_ProcessServer) error {
	log.Printf("=== New gRPC stream connection ===")

	// We'll determine the stream ID from the first request
	var streamID string

	// Ensure cleanup happens when stream ends
	defer func() {
		if streamID != "" {
			log.Printf("Stream %s ending - cleaning up", streamID)
			c.removeStreamInfo(streamID)
		}
	}()

	for {
		req, err := stream.Recv()
		if err != nil {
			if streamID != "" {
				log.Printf("Error receiving from stream %s: %v", streamID, err)
			} else {
				log.Printf("Error receiving from stream: %v", err)
			}
			return err
		}

		// Get stream ID from the first request if we don't have it yet
		if streamID == "" {
			streamID = c.getStreamID(stream, req)
			log.Printf("Stream ID: %s", streamID)
		}

		log.Printf("Received request type for stream %s: %T", streamID, req.Request)

		var resp *envoy_service_ext_proc_v3.ProcessingResponse

		switch r := req.Request.(type) {
		case *envoy_service_ext_proc_v3.ProcessingRequest_RequestHeaders:
			log.Printf("Processing RequestHeaders for stream %s", streamID)
			resp = c.processRequestHeaders(r.RequestHeaders, streamID)
		case *envoy_service_ext_proc_v3.ProcessingRequest_RequestBody:
			log.Printf("Processing RequestBody for stream %s", streamID)
			c.logAllStreams() // Debug active streams
			resp = c.processRequestBody(r.RequestBody, streamID)
		case *envoy_service_ext_proc_v3.ProcessingRequest_ResponseHeaders:
			log.Printf("Processing ResponseHeaders for stream %s", streamID)
			resp = c.processResponseHeaders(r.ResponseHeaders, streamID)
		default:
			log.Printf("Unknown request type for stream %s, sending continue response", streamID)
			resp = &envoy_service_ext_proc_v3.ProcessingResponse{
				Response: &envoy_service_ext_proc_v3.ProcessingResponse_ImmediateResponse{
					ImmediateResponse: &envoy_service_ext_proc_v3.ImmediateResponse{
						Status: &envoy_type_v3.HttpStatus{Code: envoy_type_v3.StatusCode_Continue},
					},
				},
			}
		}

		log.Printf("Sending response type for stream %s: %T", streamID, resp.Response)
		if err := stream.Send(resp); err != nil {
			log.Printf("Error sending response for stream %s: %v", streamID, err)
			return err
		}
		log.Printf("Response sent successfully for stream %s", streamID)
	}
}

func (c *CorazaExtProc) processRequestHeaders(headers *envoy_service_ext_proc_v3.HttpHeaders, streamID string) *envoy_service_ext_proc_v3.ProcessingResponse {
	log.Printf("=== Processing Request Headers for stream: %s ===", streamID)

	if headers == nil || headers.Headers == nil {
		log.Printf("ERROR: headers structure is nil")
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
		log.Printf("Detected WebSocket upgrade request for authority: %s", authority)
	}

	if authority == "" {
		log.Printf("No authority found in headers - continuing request")
		return c.continueRequest()
	}

	// Get WAF engine for this domain
	waf := c.getWAFEngine(authority)
	if waf == nil {
		log.Printf("No WAF engine found for authority: %s - continuing request", authority)
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
		log.Printf("Missing required pseudo-headers: method=%s uri=%s protocol=%s", method, uri, protocol)
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
		log.Printf("WAF BLOCKED REQUEST - Action: %s, RuleID: %d", it.Action, it.RuleID)
		c.removeStreamInfo(streamID)
		return c.createBlockResponse(it)
	}

	log.Printf("WAF allowed request headers for %s (WebSocket: %t)", authority, isWebSocket)
	return c.continueRequest()
}

// Update activity timestamp when processing body
func (c *CorazaExtProc) processRequestBody(body *envoy_service_ext_proc_v3.HttpBody, streamID string) *envoy_service_ext_proc_v3.ProcessingResponse {
	log.Printf("=== Processing Request Body for stream: %s ===", streamID)

	// Update activity timestamp
	if streamInfo := c.getStreamInfo(streamID); streamInfo != nil {
		streamInfo.LastActivity = time.Now()
	}

	// Rest of your existing processRequestBody logic...
	if body == nil {
		log.Printf("ERROR: body is nil")
		return c.continueRequestBody()
	}

	streamInfo := c.getStreamInfo(streamID)
	if streamInfo == nil {
		log.Printf("ERROR: No stream info found for stream %s", streamID)
		return c.continueRequestBody()
	}

	if streamInfo.Transaction == nil {
		log.Printf("ERROR: Stream info exists but transaction is nil for stream %s", streamID)
		return c.continueRequestBody()
	}

	tx := streamInfo.Transaction
	log.Printf("Processing body chunk of size: %d bytes (WebSocket: %t)", len(body.Body), streamInfo.IsWebSocket)

	if len(body.Body) > 0 {
		if _, _, err := tx.WriteRequestBody(body.Body); err != nil {
			log.Printf("Failed to write request body: %v", err)
			c.removeStreamInfo(streamID)
			return c.continueRequestBody()
		}
	}

	if body.EndOfStream {
		log.Printf("End of stream reached for stream %s", streamID)
		if it, err := tx.ProcessRequestBody(); err != nil {
			log.Printf("Failed to process request body: %v", err)
		} else if it != nil {
			log.Printf("WAF BLOCKED REQUEST BODY - Action: %s, RuleID: %d", it.Action, it.RuleID)
			c.removeStreamInfo(streamID)
			return c.createBlockResponse(it)
		}

		// For WebSocket connections, don't remove stream info immediately
		// as the connection might stay open for data exchange
		if !streamInfo.IsWebSocket {
			log.Printf("Removing stream info for completed HTTP request")
			c.removeStreamInfo(streamID)
		} else {
			log.Printf("Keeping WebSocket stream info active")
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
	log.Printf("*** REQUEST BLOCKED *** Action: %s, RuleID: %d, Data: %+v", it.Action, it.RuleID, it.Data)

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

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9000"
	}

	log.SetOutput(os.Stdout)
	log.Printf("=== Starting Coraza ext_proc server 8/6 9:00AM ===")
	log.Printf("Port: %s", port)
	log.Printf("Go version: %s", strings.TrimPrefix(runtime.Version(), "go"))

	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	log.Printf("TCP listener created successfully on :%s", port)

	processor, err := NewCorazaExtProc()
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer processor.Close()
	log.Printf("Coraza processor created successfully")

	s := grpc.NewServer()
	envoy_service_ext_proc_v3.RegisterExternalProcessorServer(s, processor)
	log.Printf("gRPC server created and ext_proc service registered")

	log.Printf("Watching rules directory: %s", processor.rulesDir)
	processor.logAvailableEngines()

	log.Printf("=== Server ready - waiting for connections ===")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
