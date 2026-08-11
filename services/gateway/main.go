package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/berryshield/berryshield/services/gateway/internal/api"
	"github.com/berryshield/berryshield/services/gateway/internal/config"
)

func main() {
	logger := log.New(os.Stdout, "berryshield-gateway ", log.LstdFlags|log.LUTC|log.Lmsgprefix)

	cfg, err := config.Load()
	if err != nil {
		logger.Fatalf("configuration error: %v", err)
	}
	s := api.New(cfg, logger)
	logger.Printf("starting %s", s.LogConfig())

	httpServer := &http.Server{
		Addr:              cfg.Addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatal(err)
	}
}
