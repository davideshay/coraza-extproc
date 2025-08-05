package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"runtime"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"google.golang.org/grpc"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	envoy_type_v3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
)

type CorazaExtProc struct {
	envoy_service_ext_proc_v3.UnimplementedExternalProcessorServer
	waf coraza.WAF
}

func NewCorazaExtProc() (*CorazaExtProc, error) {
	directives := "" +
		"SecDebugLogLevel 9\n" +
		"SecDebugLog /dev/stdout\n" +
		"SecRuleEngine On\n" +
		"SecAuditEngine On\n" +
		"SecAuditLog /dev/stdout\n" +
		"SecDefaultAction \"phase:1,log,pass\"\n" +
		"SecRule REQUEST_URI \".*\" \"id:1001,phase:1,log,msg:'Saw REQUEST_URI: %{REQUEST_URI}'\"\n" +

		// "SecRule &REQUEST_URI \"@ge 0\" \"id:9999,phase:1,log,msg:'REQUEST_URI exists'\"\n" +
		// "SecRule REQUEST_URI \".*\" \"id:1001,phase:1,log,msg:'Saw REQUEST_URI: %{REQUEST_URI}'\"\n" +
		"SecRule REQUEST_URI \"@contains admin\" \"id:1002,phase:1,block,status:403,msg:'Blocked by WAF: admin path'\"\n"

	wafConfig := coraza.NewWAFConfig().
		WithErrorCallback(logError).
		WithDirectives(directives)
	waf, err := coraza.NewWAF(wafConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create WAF: %w", err)
	}

	return &CorazaExtProc{waf: waf}, nil
}

func logError(error types.MatchedRule) {
	msg := error.ErrorLog()
	fmt.Printf("[logError][%s] %s\n", error.Rule().Severity(), msg)
}

func (c *CorazaExtProc) Process(stream envoy_service_ext_proc_v3.ExternalProcessor_ProcessServer) error {
	log.Printf("=== New gRPC stream connection ===")

	for {
		req, err := stream.Recv()
		if err != nil {
			log.Printf("Stream ended or errored: %v", err)
			return nil
		}

		var resp *envoy_service_ext_proc_v3.ProcessingResponse

		switch r := req.Request.(type) {
		case *envoy_service_ext_proc_v3.ProcessingRequest_RequestHeaders:
			log.Printf("Processing RequestHeaders")
			resp = c.processRequestHeaders(r.RequestHeaders)

		case *envoy_service_ext_proc_v3.ProcessingRequest_RequestBody:
			log.Printf("Processing RequestBody")
			resp = &envoy_service_ext_proc_v3.ProcessingResponse{
				Response: &envoy_service_ext_proc_v3.ProcessingResponse_RequestBody{
					RequestBody: &envoy_service_ext_proc_v3.BodyResponse{
						Response: &envoy_service_ext_proc_v3.CommonResponse{
							Status: envoy_service_ext_proc_v3.CommonResponse_CONTINUE,
						},
					},
				},
			}

		case *envoy_service_ext_proc_v3.ProcessingRequest_ResponseHeaders:
			log.Printf("Processing ResponseHeaders")
			resp = &envoy_service_ext_proc_v3.ProcessingResponse{
				Response: &envoy_service_ext_proc_v3.ProcessingResponse_ResponseHeaders{
					ResponseHeaders: &envoy_service_ext_proc_v3.HeadersResponse{
						Response: &envoy_service_ext_proc_v3.CommonResponse{
							Status: envoy_service_ext_proc_v3.CommonResponse_CONTINUE,
						},
					},
				},
			}

		case *envoy_service_ext_proc_v3.ProcessingRequest_ResponseBody:
			log.Printf("Processing ResponseBody")
			resp = &envoy_service_ext_proc_v3.ProcessingResponse{
				Response: &envoy_service_ext_proc_v3.ProcessingResponse_ResponseBody{
					ResponseBody: &envoy_service_ext_proc_v3.BodyResponse{
						Response: &envoy_service_ext_proc_v3.CommonResponse{
							Status: envoy_service_ext_proc_v3.CommonResponse_CONTINUE,
						},
					},
				},
			}

		default:
			log.Printf("Unknown request type: %T", req.Request)
			resp = &envoy_service_ext_proc_v3.ProcessingResponse{
				Response: &envoy_service_ext_proc_v3.ProcessingResponse_ImmediateResponse{
					ImmediateResponse: &envoy_service_ext_proc_v3.ImmediateResponse{
						Status: &envoy_type_v3.HttpStatus{Code: envoy_type_v3.StatusCode_Continue},
					},
				},
			}
		}

		if err := stream.Send(resp); err != nil {
			log.Printf("Failed to send response: %v", err)
			return err
		}
	}
}

func (c *CorazaExtProc) processRequestHeaders(headers *envoy_service_ext_proc_v3.HttpHeaders) *envoy_service_ext_proc_v3.ProcessingResponse {
	log.Printf("=== processRequestHeaders ===")

	tx := c.waf.NewTransaction()
	defer tx.Close()

	var method, uri, protocol string
	for _, h := range headers.Headers.Headers {
		switch h.Key {
		case ":method":
			method = string(h.RawValue)
		case ":path":
			uri = string(h.RawValue)
		case ":scheme":
			protocol = string(h.RawValue)
		default:
			tx.AddRequestHeader(h.Key, string(h.RawValue))
		}
	}

	if method == "" || uri == "" || protocol == "" {
		log.Printf("Missing required pseudo-headers: method=%s uri=%s protocol=%s", method, uri, protocol)
		return continueRequest()
	}

	if uri == "" {
		uri = "/"
	} else if uri[0] != '/' {
		uri = "/" + uri
	}

	log.Printf("Calling ProcessURI with: %s %s %s", method, uri, protocol)
	tx.ProcessURI(uri, method, protocol)
	log.Printf(">>> After ProcessURI: REQUEST_URI = %s", uri)

	interruption := tx.ProcessRequestHeaders()
	if interruption != nil {
		log.Printf("Blocked by WAF: %v", interruption)
		return createBlockResponse(interruption)
	}

	log.Printf("WAF allowed request")
	return continueRequest()
}

func continueRequest() *envoy_service_ext_proc_v3.ProcessingResponse {
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

func createBlockResponse(it *types.Interruption) *envoy_service_ext_proc_v3.ProcessingResponse {
	return &envoy_service_ext_proc_v3.ProcessingResponse{
		Response: &envoy_service_ext_proc_v3.ProcessingResponse_ImmediateResponse{
			ImmediateResponse: &envoy_service_ext_proc_v3.ImmediateResponse{
				Status: &envoy_type_v3.HttpStatus{Code: envoy_type_v3.StatusCode_Forbidden},
				Body:   fmt.Sprintf("Blocked by WAF: RuleID=%d", it.RuleID),
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

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9000"
	}

	log.SetOutput(os.Stdout)
	log.Printf("=== Starting WAF ext_proc server (rule-based mode) ===")
	log.Printf("Go version: %s", runtime.Version())

	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	processor, err := NewCorazaExtProc()
	if err != nil {
		log.Fatalf("Failed to initialize WAF: %v", err)
	}

	s := grpc.NewServer()
	envoy_service_ext_proc_v3.RegisterExternalProcessorServer(s, processor)
	log.Printf("Server listening on port %s", port)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Serve failed: %v", err)
	}
}
