// Command agent runs the MyCloud storage agent.
//
// Configuration (environment):
//
//	AGENT_LISTEN       listen address, default 127.0.0.1:8787 (put Cloudflare Tunnel in front)
//	AGENT_PUBKEY       base64 Ed25519 public key used to verify grants (required)
//	AGENT_ROOTS        comma-separated storage roots (required)
//	AGENT_ALLOW_ORIGIN web origin allowed to call the Agent from a browser, e.g. https://mycloud.example.com (optional)
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"mycloud/agent/internal/server"
	"mycloud/agent/internal/signing"
	"mycloud/agent/internal/storage"
)

func main() {
	listen := getenv("AGENT_LISTEN", "127.0.0.1:8787")
	pub := os.Getenv("AGENT_PUBKEY")
	rootsEnv := os.Getenv("AGENT_ROOTS")
	if pub == "" || rootsEnv == "" {
		log.Fatal("AGENT_PUBKEY and AGENT_ROOTS are required")
	}

	verifier, err := signing.NewVerifier(pub, signing.NewNonceStore())
	if err != nil {
		log.Fatalf("verifier: %v", err)
	}
	roots := strings.Split(rootsEnv, ",")
	store, err := storage.New(roots)
	if err != nil {
		log.Fatalf("storage: %v", err)
	}

	srv := &http.Server{
		Addr:              listen,
		Handler:           server.New(verifier, store, roots[0], os.Getenv("AGENT_ALLOW_ORIGIN")).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("agent listening on %s", listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
