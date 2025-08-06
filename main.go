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
	StreamID    string
	Authority   string
	Transaction types.Transaction
	CreatedAt   time.Time
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
			// Clean up streams older than 5 minutes
			if now.Sub(streamInfo.CreatedAt) > 5*time.Minute {
				log.Printf("Cleaning up orphaned stream: %s", streamID)
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

// Improved stream ID generation with multiple fallback methods
func (c *CorazaExtProc) getStreamID(stream envoy_service_ext_proc_v3.ExternalProcessor_ProcessServer) string {
	ctx := stream.Context()

	// Method 1: Try gRPC metadata
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

	// Method 2: Use context pointer as consistent identifier
	streamPtr := fmt.Sprintf("%p", ctx)
	log.Printf("Using context pointer as stream ID: %s", streamPtr)
	return streamPtr
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
	c.streamData[streamID] = info
	c.transactions[streamID] = info.Transaction
	log.Printf("Stored stream info for ID: %s, total streams: %d", streamID, len(c.streamData))
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
	streamID := c.getStreamID(stream)
	log.Printf("Stream ID: %s", streamID)

	// Ensure cleanup happens when stream ends
	defer func() {
		log.Printf("Stream %s ending - cleaning up", streamID)
		c.removeStreamInfo(streamID)
	}()

	for {
		req, err := stream.Recv()
		if err != nil {
			log.Printf("Error receiving from stream %s: %v", streamID, err)
			return err
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

	// Check if headers structure exists
	if headers == nil {
		log.Printf("ERROR: headers is nil")
		return c.continueRequest()
	}
	if headers.Headers == nil {
		log.Printf("ERROR: headers.Headers is nil")
		return c.continueRequest()
	}

	log.Printf("Total headers count: %d", len(headers.Headers.Headers))

	// Extract authority/host
	var authority string
	for _, header := range headers.Headers.Headers {
		if header == nil {
			continue
		}
		headerKeyLower := strings.ToLower(header.Key)

		if headerKeyLower == ":authority" || headerKeyLower == "host" {
			authority = string(header.RawValue)
			log.Printf("FOUND authority header: %s = '%s'", header.Key, authority)
			break
		}
	}

	log.Printf("Extracted authority: %s", authority)

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

	log.Printf("Found WAF engine for authority: %s", authority)

	// Create transaction and store stream info
	tx := waf.NewTransaction()
	streamInfo := &StreamInfo{
		StreamID:    streamID,
		Authority:   authority,
		Transaction: tx,
		CreatedAt:   time.Now(),
	}
	c.setStreamInfo(streamID, streamInfo)

	// Extract method, URI, protocol
	var method, uri, protocol string
	log.Printf("Extracting request details...")
	for _, header := range headers.Headers.Headers {
		if header == nil {
			continue
		}
		headerKeyLower := strings.ToLower(header.Key)
		switch headerKeyLower {
		case ":method":
			method = string(header.RawValue)
			log.Printf("Found method: '%s'", method)
		case ":path":
			uri = string(header.RawValue)
			log.Printf("Found path: '%s'", uri)
		case ":scheme":
			protocol = string(header.RawValue)
			log.Printf("Found scheme: '%s'", protocol)
		}
	}

	if method == "" || uri == "" || protocol == "" {
		log.Printf("Missing required pseudo-headers: method=%s uri=%s protocol=%s", method, uri, protocol)
		return c.continueRequest()
	}

	// Set request line
	log.Printf("Processing URI: %s", uri)
	tx.ProcessURI(uri, method, protocol)

	// Process headers
	for _, header := range headers.Headers.Headers {
		if strings.HasPrefix(header.Key, ":") {
			continue // Skip pseudo headers
		}
		tx.AddRequestHeader(header.Key, string(header.RawValue))
	}

	// Check if request should be blocked
	log.Printf("Processing request headers through WAF...")
	if it := tx.ProcessRequestHeaders(); it != nil {
		log.Printf("WAF BLOCKED REQUEST - Action: %s, RuleID: %d", it.Action, it.RuleID)
		// Clean up since we're blocking
		c.removeStreamInfo(streamID)
		return c.createBlockResponse(it)
	}

	log.Printf("WAF allowed request headers - checking if body processing needed")

	// Check if we need to process the request body
	hasBody := false
	for _, header := range headers.Headers.Headers {
		if header == nil {
			continue
		}
		headerKeyLower := strings.ToLower(header.Key)
		if headerKeyLower == "content-length" && string(header.RawValue) != "0" {
			hasBody = true
			log.Printf("Found Content-Length: %s - body processing needed", string(header.RawValue))
			break
		}
		if headerKeyLower == "transfer-encoding" && strings.Contains(strings.ToLower(string(header.RawValue)), "chunked") {
			hasBody = true
			log.Printf("Found chunked transfer encoding - body processing needed")
			break
		}
	}

	if hasBody {
		log.Printf("Request has body - keeping transaction alive for body processing")
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

	log.Printf("Request has no body - processing complete")
	// Clean up transaction since we don't need it anymore
	c.removeStreamInfo(streamID)
	return c.continueRequest()
}

func (c *CorazaExtProc) processRequestBody(body *envoy_service_ext_proc_v3.HttpBody, streamID string) *envoy_service_ext_proc_v3.ProcessingResponse {
	log.Printf("=== Processing Request Body for stream: %s ===", streamID)

	if body == nil {
		log.Printf("ERROR: body is nil")
		return c.continueRequestBody()
	}

	streamInfo := c.getStreamInfo(streamID)
	if streamInfo == nil {
		log.Printf("ERROR: No stream info found for stream %s", streamID)
		c.logAllStreams()
		return c.continueRequestBody()
	}

	if streamInfo.Transaction == nil {
		log.Printf("ERROR: Stream info exists but transaction is nil for stream %s", streamID)
		return c.continueRequestBody()
	}

	tx := streamInfo.Transaction
	log.Printf("Successfully retrieved transaction for stream %s", streamID)
	log.Printf("Processing body chunk of size: %d bytes", len(body.Body))
	log.Printf("End of stream: %t", body.EndOfStream)

	// Write body data to transaction
	if len(body.Body) > 0 {
		log.Printf("Writing body data to WAF transaction...")
		if _, _, err := tx.WriteRequestBody(body.Body); err != nil {
			log.Printf("Failed to write request body: %v", err)
			c.removeStreamInfo(streamID)
			return c.continueRequestBody()
		}
		log.Printf("Successfully wrote %d bytes to transaction", len(body.Body))
	}

	// If this is the end of the stream, process the complete body
	if body.EndOfStream {
		log.Printf("End of stream reached - processing complete request body through WAF...")

		// Process the complete request body
		if it, err := tx.ProcessRequestBody(); err != nil {
			log.Printf("Failed to process request body: %v", err)
		} else if it != nil {
			log.Printf("WAF BLOCKED REQUEST BODY - Action: %s, RuleID: %d", it.Action, it.RuleID)
			c.removeStreamInfo(streamID)
			return c.createBlockResponse(it)
		}

		log.Printf("WAF allowed request body - request processing complete")
		c.removeStreamInfo(streamID)
	} else {
		log.Printf("More body data expected - continuing...")
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
	log.Printf("=== Starting Coraza ext_proc server 8/5 9:47PM (FIXED) ===")
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
