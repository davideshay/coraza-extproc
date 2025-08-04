package main

import (
	"log"
	"net"

	"coraza-ext-waf/processor" // replace with your actual module path
	"coraza-ext-waf/waf"

	extproc "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
)

func main() {
	// Load WAF profiles from mounted directory (ConfigMap volume)
	if err := waf.LoadProfiles("/app/waf/profiles"); err != nil {
		log.Fatalf("Failed to load WAF profiles: %v", err)
	}

	// Load authority -> profile mappings from config file (ConfigMap volume)
	if err := waf.LoadMappings("/app/waf/mapping.yaml"); err != nil {
		log.Fatalf("Failed to load authority mappings: %v", err)
	}

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	extproc.RegisterExternalProcessorServer(grpcServer, &processor.WAFServer{})

	log.Println("Starting WAF gRPC server on :50051")
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
