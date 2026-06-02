# Production concurrency — many simultaneous viewers

One **admin** or **audit member** can watch **many clients at once** (grid / live wall). Clients can stay online **24/7**. The Go signaling server is the coordination layer; media goes **P2P → TURN → SFU** with dual Cloudflare failover.

## Capacity model

| Layer | Limit | Env |
|--------|--------|-----|
| Per admin socket | How many different clients one viewer can attach to | `MAX_ADMIN_VIEWER_TARGETS` (default 64) |
| Per client desktop | How many admins can watch the same machine | `MAX_VIEWERS_PER_CLIENT` (default 12) |
| Audit browser tab | How many live tiles stay open | `NEXT_PUBLIC_MAX_CONCURRENT_STREAMS` (default 32) |
| Parallel negotiations | Connect handshakes at once | `NEXT_PUBLIC_MAX_PARALLEL_STREAM_CONNECTS` (default 6) |
| WebSocket relay | ICE/SDP messages per second | `SIGNALING_RATE_CAPACITY` / `SIGNALING_RATE_REFILL_PER_SEC` |
| Postgres pool | DB queries under load | `PG_POOL_MAX` ≤ 12 on Supabase session pooler |

## Recommended production `.env` (signaling)

```env
MAX_ADMIN_VIEWER_TARGETS=64
MAX_VIEWERS_PER_CLIENT=12
SIGNALING_RATE_CAPACITY=800
SIGNALING_RATE_REFILL_PER_SEC=400
STREAM_SFU_VIEWER_THRESHOLD=2
STREAM_TURN_VIEWER_THRESHOLD=2
PG_POOL_MAX=10
ENABLE_CLOUDFLARE_SFU=true
# lane 1 + lane 2 Cloudflare credentials (see STREAMING.md)
```

## What the server does under load

1. **Outbound WS queue (512)** — each connection has a dedicated writer goroutine so one slow peer does not block relay to others.
2. **WebRTC + SFU exempt from rate limit** — `offer` / `answer` / `ice-candidate` / `sfu-api` are not throttled like admin API calls.
3. **SFU at 2+ viewers** on the same client — one upload to Cloudflare, many subscribers (saves client CPU and bandwidth).
4. **Dual TURN lanes merged** — ICE list includes both Cloudflare accounts when healthy.
5. **Automatic downgrade** — SFU failure → TURN mesh → P2P; lane 1 failure → lane 2.

## Browser / hardware reality

- **Audit grid 32 streams**: feasible on a strong workstation with hardware decode; reduce `NEXT_PUBLIC_MAX_CONCURRENT_STREAMS` on weaker PCs (e.g. 12–16).
- **Admin grid 4×4**: up to 16 tiles; TURN-heavy grids cap relay decodes via `VITE_MAX_RELAY_GRID_PREVIEWS` (default 4).
- **Client machine**: screen capture + up to `MAX_VIEWERS_PER_CLIENT` mesh peers (or one SFU publish for many viewers).

## 24/7 stability

- Client **heartbeat** + server stale cleanup keep roster accurate.
- **SFU publisher** re-registers on reconnect; viewers get `sfu-publisher-ready`.
- Restart signaling after `.env` changes; clients reconnect automatically.

## Verify

```powershell
cd signing-server-go
go run ./scripts/verify_media_env.go
.\bin\signaling.exe
```

Load test: open live wall with 8–16 clients, then add more gradually while watching signaling CPU and Supabase connection count.
