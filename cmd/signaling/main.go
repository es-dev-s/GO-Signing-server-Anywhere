package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/joho/godotenv"

	"github.com/anywhere/signing-server-go/internal/config"
	"github.com/anywhere/signing-server-go/internal/db"
	"github.com/anywhere/signing-server-go/internal/hub"
)

func main() {
	_ = godotenv.Load(".env")
	_ = godotenv.Load(".env.local")

	cfg := config.Load()
	if cfg.DatabaseURL == "" {
		log.Fatal("DATABASE_URL or SUPABASE_DATABASE_URL is required")
	}
	if cfg.WsConnectToken == "" {
		log.Println("[warn] WS_CONNECT_TOKEN is empty — WebSocket connections are not token-gated")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Printf("[db] pool max=%d min=%d (Supabase session pooler cap ~15; Node default PG_POOL_MAX=10)", cfg.PgPoolMax, cfg.PgPoolMin)
	store, err := db.New(ctx, cfg.DatabaseURL, cfg.PgPoolMax, cfg.PgPoolMin, cfg.PgSSL)
	if err != nil {
		log.Fatalf("database: %v", err)
	}
	defer store.Close()

	h := hub.New(cfg, store)
	if err := h.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("server: %v", err)
	}
}
