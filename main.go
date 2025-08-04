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
)

type CorazaExtProc struct {
	envoy_service_ext_proc_v3.UnimplementedExternalProcessorServer
	wafEngines map[string]coraza.WAF // domain -> WAF engine
	mutex      sync.RWMutex
	rulesDir   string
	watcher    *fsnotify.Watcher
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
		wafEngines: make(map[string]coraza.WAF),
		rulesDir:   rulesDir,
		watcher:    watcher,
	}

	// Load initial configurations
	if err := processor.loadRulesFromDirectory(); err != nil {
		log.Printf("Failed to load initial rules: %v", err)
	}

	// Start watching for file changes
	go processor.watchRulesDirectory()

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

		// Skip directories and non-.conf files
		if d.IsDir() || strings.HasPrefix(d.Name(),".") || !strings.HasSuffix(d.Name(), ".conf") {
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
	ticker := time.NewTicker(30 * time.Second)
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

	log.Printf("Looking for WAF engine for authority: %s", authority)

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

func (c *CorazaExtProc) Process(stream envoy_service_ext_proc_v3.ExternalProcessor_ProcessServer) error {
	log.Printf("=== New gRPC stream connection ===")
	
	for {
		req, err := stream.Recv()
		if err != nil {
			log.Printf("Error receiving from stream: %v", err)
			return err
		}

		log.Printf("Received request type: %T", req.Request)
		
		// Log the raw request for debugging
		if req.Request != nil {
			log.Printf("Raw request details: %+v", req.Request)
		}

		var resp *envoy_service_ext_proc_v3.ProcessingResponse

		switch r := req.Request.(type) {
		case *envoy_service_ext_proc_v3.ProcessingRequest_RequestHeaders:
			log.Printf("Processing RequestHeaders")
			if r.RequestHeaders != nil {
				log.Printf("RequestHeaders object exists")
				if r.RequestHeaders.Headers != nil {
					log.Printf("Headers field exists with %d headers", len(r.RequestHeaders.Headers.Headers))
				} else {
					log.Printf("ERROR: RequestHeaders.Headers is nil")
				}
			} else {
				log.Printf("ERROR: RequestHeaders is nil")
			}
			resp = c.processRequestHeaders(r.RequestHeaders)
		case *envoy_service_ext_proc_v3.ProcessingRequest_RequestBody:
			log.Printf("Processing RequestBody")
			resp = c.processRequestBody(r.RequestBody, req)
		case *envoy_service_ext_proc_v3.ProcessingRequest_ResponseHeaders:
			log.Printf("Processing ResponseHeaders")
			resp = c.processResponseHeaders(r.ResponseHeaders)
		default:
			log.Printf("Unknown request type, sending continue response")
			resp = &envoy_service_ext_proc_v3.ProcessingResponse{
				Response: &envoy_service_ext_proc_v3.ProcessingResponse_ImmediateResponse{
					ImmediateResponse: &envoy_service_ext_proc_v3.ImmediateResponse{
						Status: &envoy_type_v3.HttpStatus{Code: envoy_type_v3.StatusCode_Continue},
					},
				},
			}
		}

		log.Printf("Sending response type: %T", resp.Response)
		if err := stream.Send(resp); err != nil {
			log.Printf("Error sending response: %v", err)
			return err
		}
		log.Printf("Response sent successfully")
	}
}

func (c *CorazaExtProc) processRequestHeaders(headers *envoy_service_ext_proc_v3.HttpHeaders) *envoy_service_ext_proc_v3.ProcessingResponse {
	log.Printf("=== Processing Request Headers ===")
	
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
	
	// Check if this is an empty header configuration issue
	emptyValueCount := 0
	for _, header := range headers.Headers.Headers {
		if header != nil && len(header.RawValue) == 0 {
			emptyValueCount++
		}
	}
	
	if emptyValueCount == len(headers.Headers.Headers) {
		log.Printf("WARNING: ALL header values are empty! This suggests a configuration issue.")
		log.Printf("Check your Envoy Gateway ExtProc configuration - you may need:")
		log.Printf("  processingMode:")
		log.Printf("    requestHeaderMode: SEND")
		log.Printf("    responseHeaderMode: SKIP")
	}
	
	// Log all headers for debugging with more detail
	for i, header := range headers.Headers.Headers {
		if header == nil {
			log.Printf("Header[%d]: NIL HEADER", i)
			continue
		}
		log.Printf("Header[%d]: Key='%s' (len=%d), Value='%s' (len=%d)", 
			i, header.Key, len(header.Key), header.RawValue, len(header.RawValue))
		
		// Only log bytes for first few headers to reduce noise
		if i < 3 {
			log.Printf("  Key bytes: %v", []byte(header.Key))
			log.Printf("  Value bytes: %v", []byte(header.RawValue))
		}
	}

	// Extract authority/host with more detailed logging
	var authority string
	log.Printf("Searching for authority/host header...")
	for i, header := range headers.Headers.Headers {
		if header == nil {
			continue
		}
		headerKeyLower := strings.ToLower(header.Key)
		log.Printf("Checking header[%d]: '%s' (lowercase: '%s')", i, header.Key, headerKeyLower)
		
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

	// Create transaction
	tx := waf.NewTransaction()
	defer func() {
		if err := tx.Close(); err != nil {
			log.Printf("Failed to close transaction: %v", err)
		}
	}()

	// Extract method, URI, protocol with detailed logging
	var method, uri, protocol string
	log.Printf("Extracting request details...")
	for i, header := range headers.Headers.Headers {
		if header == nil {
			continue
		}
		headerKeyLower := strings.ToLower(header.Key)
		log.Printf("Checking header[%d] for request details: '%s' = '%s'", i, header.Key, header.RawValue)
		
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

	log.Printf("Request details - Method: %s, URI: %s, Protocol: %s", method, uri, protocol)

	// Set request line
	if method != "" && uri != "" {
		log.Printf("Processing URI: %s", uri)
		tx.ProcessURI(uri, method, protocol)
	}

	// Process headers
	for _, header := range headers.Headers.Headers {
		if strings.HasPrefix(header.Key, ":") {
			continue // Skip pseudo headers for now
		}
		log.Printf("Adding request header: %s = %s", header.Key, string(header.RawValue))
		tx.AddRequestHeader(header.Key, string(header.RawValue))
	}

	// Check if request should be blocked
	log.Printf("Processing request headers through WAF...")
	if it := tx.ProcessRequestHeaders(); it != nil {
		log.Printf("WAF BLOCKED REQUEST - Action: %s, RuleID: %d", it.Action, it.RuleID)
		return c.createBlockResponse(it)
	}

	log.Printf("WAF allowed request - continuing")
	return c.continueRequest()
}

func (c *CorazaExtProc) processRequestBody(body *envoy_service_ext_proc_v3.HttpBody, req *envoy_service_ext_proc_v3.ProcessingRequest) *envoy_service_ext_proc_v3.ProcessingResponse {
	// For body processing, you'd need to maintain transaction state across calls
	// This is a simplified implementation that just continues
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

func (c *CorazaExtProc) processResponseHeaders(headers *envoy_service_ext_proc_v3.HttpHeaders) *envoy_service_ext_proc_v3.ProcessingResponse {
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

	log.SetOutput(os.Stdout);
	log.Printf("=== Starting Coraza ext_proc server ===")
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