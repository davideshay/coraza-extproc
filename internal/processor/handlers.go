package processor

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	logging "coraza-extproc/internal/logging"
	"coraza-extproc/internal/types"

	coraza_types "github.com/corazawaf/coraza/v3/types"
	"google.golang.org/protobuf/types/known/wrapperspb"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
)

// processRequestHeaders handles incoming request headers
func (p *Processor) processRequestHeaders(headers *envoy_service_ext_proc_v3.HttpHeaders, streamID string) *envoy_service_ext_proc_v3.ProcessingResponse {
	start := time.Now()
	slog.Debug("Processing request headers", slog.String("streamID", streamID))

	if headers == nil || headers.Headers == nil {
		slog.Error("Invalid headers structure")
		return p.continueRequest()
	}

	// Extract request information
	var authority, method, uri, protocol string
	var isWebSocket bool
	var connection, upgrade string

	for _, header := range headers.Headers.Headers {
		if header == nil {
			continue
		}

		headerKey := strings.ToLower(header.Key)
		headerValue := string(header.RawValue)
		headerValueLower := strings.ToLower(headerValue)

		switch headerKey {
		case ":authority", "host":
			authority = headerValue
		case ":method":
			method = headerValue
		case ":path":
			uri = headerValue
		case ":scheme":
			protocol = headerValue
		case "connection":
			connection = headerValueLower
		case "upgrade":
			upgrade = headerValueLower
		}
	}

	slog.Log(context.Background(), logging.LevelTrace, "Request:", slog.String("authority", authority), slog.String("uri", uri))

	// Detect WebSocket upgrade
	if strings.Contains(connection, "upgrade") && upgrade == "websocket" {
		isWebSocket = true
		slog.Info("Detected WebSocket upgrade", slog.String("authority", authority))
	}

	// Validate required fields
	if authority == "" {
		slog.Error(types.ErrNoAuthority)
		return p.continueRequest()
	}

	if method == "" || uri == "" || protocol == "" {
		slog.Error("Missing required pseudo-headers",
			slog.String("method", method),
			slog.String("uri", uri),
			slog.String("protocol", protocol))
		return p.continueRequest()
	}

	// Get WAF engine
	waf := p.getWAFEngine(authority)
	if waf == nil {
		slog.Error(types.ErrNoWAFEngine, slog.String("authority", authority))
		p.logAvailableEngines()
		return p.continueRequest()
	}

	// Create transaction
	tx := waf.NewTransaction()
	streamInfo := &types.StreamInfo{
		StreamID:     streamID,
		Authority:    authority,
		URI:          uri,
		Transaction:  tx,
		CreatedAt:    time.Now(),
		IsWebSocket:  isWebSocket,
		LastActivity: time.Now(),
	}

	slog.Debug("Created new stream info",
		slog.String("streamID", streamID),
		slog.String("authority", authority),
		slog.String("uri", uri),
		slog.Bool("isWebSocket", isWebSocket))

	p.setStreamInfo(streamID, streamInfo)

	// Process request line
	tx.ProcessURI(uri, method, protocol)

	// Add headers to transaction (skip pseudo-headers)
	for _, header := range headers.Headers.Headers {
		if !strings.HasPrefix(header.Key, ":") {
			tx.AddRequestHeader(header.Key, string(header.RawValue))
		}
	}

	// Check for WAF blocks
	if interruption := tx.ProcessRequestHeaders(); interruption != nil {
		slog.Debug("WAF blocked request at headers phase",
			slog.String("streamID", streamID),
			slog.Bool("isWebSocket", isWebSocket),
			slog.Int("ruleID", interruption.RuleID),
			slog.String("action", interruption.Action))
		savedStreamInfo := *streamInfo
		p.removeStreamInfo(streamID)
		return p.createBlockResponse(savedStreamInfo, interruption)
	}

	slog.Debug("Request headers allowed",
		slog.String("authority", authority),
		slog.Bool("isWebSocket", isWebSocket),
		slog.Duration("duration", time.Since(start)))

	return p.continueRequest()
}

// processRequestBody handles request body data
func (p *Processor) processRequestBody(body *envoy_service_ext_proc_v3.HttpBody, streamID string) *envoy_service_ext_proc_v3.ProcessingResponse {
	start := time.Now()
	slog.Debug("Processing request body", slog.String("streamID", streamID))

	if body == nil {
		slog.Error("Body is nil")
		return p.continueRequestBody()
	}

	streamInfo := p.getStreamInfo(streamID)
	if streamInfo == nil {
		slog.Debug("Stream not found - may have expired or been cleaned up",
			slog.String("streamID", streamID))
		return p.continueRequestBody()
	}

	if streamInfo.Transaction == nil {
		slog.Error(types.ErrNoTransaction, slog.String("streamID", streamID))
		return p.continueRequestBody()
	}

	// Update activity timestamp
	streamInfo.LastActivity = time.Now()

	tx := streamInfo.Transaction
	slog.Debug("Processing body chunk",
		slog.Int("size", len(body.Body)),
		slog.Bool("websocket", streamInfo.IsWebSocket))

	// Write body data to transaction
	if len(body.Body) > 0 {
		if _, _, err := tx.WriteRequestBody(body.Body); err != nil {
			slog.Error("Failed to write request body", slog.Any("error", err))
			return p.continueRequestBody()
		}
	}

	// Process end of stream
	if body.EndOfStream {
		slog.Debug("End of stream reached", slog.String("streamID", streamID))

		if interruption, err := tx.ProcessRequestBody(); err != nil {
			slog.Error("Failed to process request body", slog.Any("error", err))
		} else if interruption != nil {
			slog.Warn("WAF blocked request at body phase",
				slog.String("authority", streamInfo.Authority),
				slog.String("uri", streamInfo.URI),
				slog.String("action", interruption.Action),
				slog.Int("ruleID", interruption.RuleID))
			savedStreamInfo := *streamInfo
			p.removeStreamInfo(streamID)
			return p.createBlockResponse(savedStreamInfo, interruption)
		}

		// For WebSocket, keep the connection info for potential future use
		// For regular HTTP requests, we keep the stream active until response is complete
		if streamInfo.IsWebSocket {
			slog.Debug("Keeping WebSocket stream active",
				slog.String("streamID", streamID),
				slog.Bool("isWebSocket", streamInfo.IsWebSocket),
				slog.Duration("age", time.Since(streamInfo.CreatedAt)))
			streamInfo.LastActivity = time.Now()
		}
	}

	slog.Debug("Request body processing completed",
		slog.String("streamID", streamID),
		slog.Duration("duration", time.Since(start)))

	return p.continueRequestBody()
}

// processResponseHeaders handles response headers (cleanup phase)
func (p *Processor) processResponseHeaders(headers *envoy_service_ext_proc_v3.HttpHeaders, streamID string) *envoy_service_ext_proc_v3.ProcessingResponse {
	slog.Debug("Processing response headers", slog.String("streamID", streamID))
	slog.Log(context.Background(), logging.LevelTrace, "Response Headers", slog.String("headers", headers.String()))

	// Check if stream exists
	streamInfo := p.getStreamInfo(streamID)
	if streamInfo == nil {
		slog.Debug("Stream already cleaned up or expired (expected behavior)",
			slog.String("streamID", streamID))
	} else {
		// For WebSocket connections, keep the stream active after response headers
		// The stream will be cleaned up when the WebSocket connection closes
		if streamInfo.IsWebSocket {
			slog.Debug("Keeping WebSocket stream active after response headers",
				slog.String("streamID", streamID),
				slog.Duration("age", time.Since(streamInfo.CreatedAt)))
			streamInfo.LastActivity = time.Now()
		} else {
			// For regular HTTP requests, we'll clean up in processResponseBody
			// instead of here to handle cases where Envoy sends response body after headers
			slog.Debug("HTTP stream will be cleaned up after response body",
				slog.String("streamID", streamID),
				slog.Duration("age", time.Since(streamInfo.CreatedAt)))
		}
	}

	return &envoy_service_ext_proc_v3.ProcessingResponse{
		Response: &envoy_service_ext_proc_v3.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &envoy_service_ext_proc_v3.HeadersResponse{
				Response: &envoy_service_ext_proc_v3.CommonResponse{
					Status: envoy_service_ext_proc_v3.CommonResponse_CONTINUE,
					HeaderMutation: &envoy_service_ext_proc_v3.HeaderMutation{
						SetHeaders: []*envoy_config_core_v3.HeaderValueOption{
							{
								Header: &envoy_config_core_v3.HeaderValue{
									Key:      "x-waf-violation",
									RawValue: []byte("0"),
								},
								Append: &wrapperspb.BoolValue{Value: false},
							},
						},
					},
				},
			},
		},
	}
}

func (p *Processor) processResponseBody(body *envoy_service_ext_proc_v3.HttpBody, streamID string) *envoy_service_ext_proc_v3.ProcessingResponse {
	slog.Debug("Processing response body", slog.String("streamID", streamID))
	slog.Log(context.Background(), logging.LevelTrace, "Body Contents", slog.String("body", body.String()))

	// Clean up stream info after response body for regular HTTP requests
	streamInfo := p.getStreamInfo(streamID)
	if streamInfo != nil {
		if streamInfo.IsWebSocket {
			slog.Debug("Keeping WebSocket stream active after response body",
				slog.String("streamID", streamID),
				slog.Duration("age", time.Since(streamInfo.CreatedAt)))
			streamInfo.LastActivity = time.Now()
		} else if body.EndOfStream {
			// Only clean up when we've reached the end of the response body
			slog.Debug("Cleaning up HTTP stream after response body",
				slog.String("streamID", streamID),
				slog.Duration("age", time.Since(streamInfo.CreatedAt)))
			p.removeStreamInfo(streamID)
		}
	} else {
		slog.Debug("Stream already cleaned up or expired",
			slog.String("streamID", streamID))
	}

	return &envoy_service_ext_proc_v3.ProcessingResponse{
		Response: &envoy_service_ext_proc_v3.ProcessingResponse_ResponseBody{
			ResponseBody: &envoy_service_ext_proc_v3.BodyResponse{
				Response: &envoy_service_ext_proc_v3.CommonResponse{
					Status: envoy_service_ext_proc_v3.CommonResponse_CONTINUE,
				},
			},
		},
	}
}

// continueRequest creates a continue response for request headers
func (p *Processor) continueRequest() *envoy_service_ext_proc_v3.ProcessingResponse {
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

// continueRequestBody creates a continue response for request body
func (p *Processor) continueRequestBody() *envoy_service_ext_proc_v3.ProcessingResponse {
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

// createBlockResponse creates a block response for WAF violations
func (p *Processor) createBlockResponse(streamInfo types.StreamInfo, interruption *coraza_types.Interruption) *envoy_service_ext_proc_v3.ProcessingResponse {
	logging.LogSecurityEvent("WAF REQUEST BLOCKED", streamInfo, interruption)

	return &envoy_service_ext_proc_v3.ProcessingResponse{
		Response: &envoy_service_ext_proc_v3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &envoy_service_ext_proc_v3.ImmediateResponse{
				Status: &envoy_type_v3.HttpStatus{
					Code: envoy_type_v3.StatusCode_Forbidden,
				},
				Body: []byte(fmt.Sprintf("Request blocked by WAF - Rule ID: %d, Action: %s",
					interruption.RuleID, interruption.Action)),
				Headers: &envoy_service_ext_proc_v3.HeaderMutation{
					SetHeaders: []*envoy_config_core_v3.HeaderValueOption{
						{
							Header: &envoy_config_core_v3.HeaderValue{
								Key:      "content-type",
								RawValue: []byte("text/plain"),
							},
							Append: &wrapperspb.BoolValue{Value: false},
						},
						{
							Header: &envoy_config_core_v3.HeaderValue{
								Key:      "x-waf-violation",
								RawValue: []byte("1"),
							},
							Append: &wrapperspb.BoolValue{Value: false},
						},
					},
				},
			},
		},
	}
}
