package main

import (
	"log"
	"net"

	"coraza-ext-waf/processor"
	"coraza-ext-waf/waf"

	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
)

func main() {
	waf.LoadProfiles("waf/profiles")

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	extproc.RegisterExternalProcessorServer(s, &processor.WAFServer{})

	log.Println("Starting Coraza WAF server on :50051")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
