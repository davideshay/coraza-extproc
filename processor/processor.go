package processor

import (
	"context"

	"coraza-ext-waf/waf" // replace with your actual module path

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
	profileName := waf.GetProfileNameForAuthority(authority)
	wafInstance := waf.GetProfile(profileName)

	tx := wafInstance.NewTransaction()
	defer tx.Close()

	for _, hv := range headers {
		tx.AddRequestHeader(hv.Key, hv.Value)
	}

	// For example purposes, using dummy URI and method. In real usage parse from request.
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
