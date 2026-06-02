//go:build ignore

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/anywhere/signing-server-go/internal/config"
	"github.com/anywhere/signing-server-go/internal/ice"
	"github.com/joho/godotenv"
)

func main() {
	_ = godotenv.Load(".env")
	_ = godotenv.Load(".env.local")
	cfg := config.Load()
	pool := ice.NewProviderPool(cfg)

	fmt.Println("=== signing-server-go media env check ===")
	fmt.Printf("PORT=%d ENABLE_CLOUDFLARE_SFU=%v\n", cfg.Port, cfg.EnableCloudflareSFU)
	fmt.Printf("WS_CONNECT_TOKEN set=%v DATABASE_URL set=%v\n", cfg.WsConnectToken != "", cfg.DatabaseURL != "")
	fmt.Printf("ICE_PHASE_ONE_MS=%d (default 5000 if unset)\n", cfg.IcePhaseOneMs)
	fmt.Printf("STREAM_TURN viewers>=%d admin>=%d | SFU viewers>=%d admin>=%d\n",
		cfg.StreamTurnViewerThreshold, cfg.StreamTurnAdminTargetsThreshold,
		cfg.StreamSFUViewerThreshold, cfg.StreamSFUAdminTargetsThreshold)

	lanes := pool.Lanes()
	fmt.Printf("Cloudflare lanes configured: %d\n", len(lanes))
	for _, l := range lanes {
		fmt.Printf("  lane %d: TURN key=%v token=%v | Realtime app=%v token=%v\n",
			l.Lane, l.TurnKeyID != "", l.TurnKeyToken != "", l.RealtimeAppID != "", l.RealtimeToken != "")
	}

	ctx := context.Background()
	for _, l := range lanes {
		if l.TurnKeyID != "" && l.TurnKeyToken != "" {
			entries, err := ice.FetchCloudflareIceServers(ctx, config.Config{
				CloudflareTurnKeyID: l.TurnKeyID, CloudflareTurnKeyAPIToken: l.TurnKeyToken,
			})
			if err != nil {
				fmt.Printf("  lane %d TURN ICE: FAIL (%v)\n", l.Lane, err)
			} else {
				fmt.Printf("  lane %d TURN ICE: OK (%d server entries)\n", l.Lane, len(entries))
			}
		}
	}

	pool.ProbeRealtime(ctx)
	avail := pool.AvailableRealtimeLanes()
	fmt.Printf("Realtime SFU healthy lanes after probe: %v (preferred=%d)\n", avail, pool.PreferredLane())

	merged := ice.FetchAllCloudflareIceServers(ctx, pool)
	fmt.Printf("Merged TURN ICE entries in welcome plan: %d\n", len(merged))

	if len(avail) == 0 && cfg.EnableCloudflareSFU {
		fmt.Println("WARN: SFU enabled but no healthy Realtime lane — multi-viewer will fall back to TURN only.")
		os.Exit(1)
	}
	if len(merged) == 0 {
		fmt.Println("WARN: No TURN ICE fetched — relay may fail unless home TURN/STUN in env.")
	}
	fmt.Println("OK — env structure looks good. Restart signaling.exe if it was already running.")
}
