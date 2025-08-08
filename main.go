package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"coraza-extproc/internal/logging"
	"coraza-extproc/internal/processor"

	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	// Setup logging
	logger := logging.Setup()
	slog.SetDefault(logger)

	port := os.Getenv("PORT")
	if port == "" {
		port = "9000"
	}

	slog.Info("=== Starting Coraza ext_proc server ===", slog.String("port", port))

	// Create TCP listener
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		slog.Error("Failed to create listener", slog.Any("error", err))
		os.Exit(1)
	}
	defer lis.Close()

	// Create processor
	proc, err := processor.New()
	if err != nil {
		slog.Error("Failed to create processor", slog.Any("error", err))
		os.Exit(1)
	}
	defer proc.Close()

	// Create gRPC server
	s := grpc.NewServer()
	envoy_service_ext_proc_v3.RegisterExternalProcessorServer(s, proc)

	// Enable reflection for debugging
	if os.Getenv("GRPC_REFLECTION") == "true" {
		reflection.Register(s)
	}

	// Setup graceful shutdown
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		slog.Info("Shutting down server...")
		s.GracefulStop()
		cancel()
	}()

	slog.Info("=== Server ready - waiting for connections ===")
	if err := s.Serve(lis); err != nil {
		slog.Error("Server failed", slog.Any("error", err))
		os.Exit(1)
	}
}
