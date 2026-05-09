/*
FILE PATH: cmd/standalone-witness/main.go

DESCRIPTION:

	A minimal standalone witness HTTP server. Loads a single
	secp256k1 PEM key + the network bootstrap doc, serves
	/v1/cosign on the configured port. Designed for local-dev
	multi-instance scenarios where the writer ledger needs N
	external witnesses to drive a real K-of-N quorum without
	spinning up N full ledgers.

USAGE:

	./bin/standalone-witness \
	    -addr :8081 \
	    -key-file .run/witnesses/witness-1.pem \
	    -bootstrap .run/network-bootstrap.json

WHAT IT IS NOT:

	This is NOT a full ledger. It does NOT participate in
	gossip, hold a Postgres connection, write tiles, run a
	builder loop, or accept admissions. It exclusively serves
	cosignature requests. For a full witness deployment with
	rotation + gossip + persistence, run a regular ledger
	process configured with witness role.

ARCHITECTURE:

	The cosign handler is built via witness.BuildCosignHandler
	— the SAME wrapper the full ledger uses, including the
	monotonicity guard that refuses to cosign a tree_size
	smaller than this process's lastSignedSize. So any test
	that runs against this binary exercises the same code path
	as a production K=N witness fleet.

	Network binding: the witness's NetworkID is derived from
	the network bootstrap document (network.BootstrapDocument.IDs()).
	Requests carrying a different network_id are rejected with
	403 by the SDK handler.

GRACEFUL SHUTDOWN:

	SIGINT/SIGTERM triggers http.Server.Shutdown with a 5s
	deadline. In-flight cosign requests complete; new
	connections are rejected.
*/
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/clearcompass-ai/attesta/network"

	"github.com/clearcompass-ai/standalone-witness/internal/serve"
)

func main() {
	addr := flag.String("addr", ":8081",
		"HTTP listen address (e.g., :8081)")
	keyFile := flag.String("key-file", "",
		"path to the witness EC private key in PEM form (required)")
	bootstrapFile := flag.String("bootstrap", "",
		"path to the network BootstrapDocument JSON (required, for NetworkID)")
	flag.Parse()

	if *keyFile == "" || *bootstrapFile == "" {
		fmt.Fprintln(os.Stderr, "standalone-witness: -key-file and -bootstrap are required")
		flag.Usage()
		os.Exit(2)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	priv, err := loadECPrivateKey(*keyFile)
	if err != nil {
		logger.Error("load witness key", "path", *keyFile, "error", err)
		os.Exit(1)
	}

	doc, err := loadBootstrap(*bootstrapFile)
	if err != nil {
		logger.Error("load bootstrap", "path", *bootstrapFile, "error", err)
		os.Exit(1)
	}
	identity, err := doc.IDs()
	if err != nil {
		logger.Error("derive network identity from bootstrap", "error", err)
		os.Exit(1)
	}

	handler, err := serve.Build(serve.Config{
		WitnessKey: priv,
		NetworkID:  identity.NetworkID,
		Logger:     logger,
	})
	if err != nil {
		logger.Error("build cosign handler", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.Handle("POST /v1/cosign", handler)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	logger.Info("standalone-witness ready",
		"addr", *addr,
		"network_did", identity.DID,
		"key_file", *keyFile,
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		logger.Error("listen failed", "error", err)
		os.Exit(1)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	logger.Info("standalone-witness stopped")
}

func loadECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("decode PEM: nil block (file empty or malformed)")
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC key: %w", err)
	}
	return priv, nil
}

func loadBootstrap(path string) (network.BootstrapDocument, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return network.BootstrapDocument{}, fmt.Errorf("read: %w", err)
	}
	var doc network.BootstrapDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return network.BootstrapDocument{}, fmt.Errorf("unmarshal: %w", err)
	}
	return doc, nil
}
