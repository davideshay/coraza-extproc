package processor

import (
	"context"

	"coraza-ext-waf/waf"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
)

type WAFServer struct {
	extproc.UnimplementedExternalProcessorServer
}

func (s *WAFServer) ProcessRequestHeaders(ctx context.Context, req *extproc.ProcessingRequest) (*extproc.ProcessingResponse, error) {
	headerMap := req.GetRequestHeaders().GetHeaders()
	headers := headerMap.GetHeaders() // []*corev3.HeaderValue slice

	authority := getHeaderValue(headers, ":authority")

	var profileName string
	switch authority {
	case "admin.example.com":
		profileName = "admin"
	case "public.example.com":
		profileName = "public"
	default:
		profileName = "default"
	}

	wafInstance := waf.GetProfile(profileName)
	tx := wafInstance.NewTransaction()
	defer tx.Close()

	for _, hv := range headers {
		key := hv.Key
		val := hv.Value
		tx.AddRequestHeader(key, val)
	}

	tx.ProcessURI("/", "GET", "HTTP/1.1")
	tx.ProcessRequestHeaders()

	if tx.Interruption() != nil {
		return &extproc.ProcessingResponse{
			Response: &extproc.ProcessingResponse_ImmediateResponse{
				ImmediateResponse: &extproc.ImmediateResponse{
					Status: &typev3.HttpStatus{
						Code: typev3.StatusCode_Forbidden,
					},
					Body: []byte("Blocked by WAF"),
				},
			},
		}, nil
	}

	return &extproc.ProcessingResponse{
		Response: &extproc.ProcessingResponse_RequestHeaders{},
	}, nil
}

func getHeaderValue(headers []*corev3.HeaderValue, key string) string {
	for _, hv := range headers {
		if hv.Key == key {
			return hv.Value
		}
	}
	return ""
}
