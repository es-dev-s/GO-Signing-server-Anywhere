# Anywhere Signaling Server (Go)

Drop-in replacement for the Node `Signing server/` with the same WebSocket protocol, Postgres schema, and HTTP ingest routes—**except browser-tab telemetry** (no `/api/browser-tab-events`, no `browser-tab-events-update` WS broadcasts, no `browser_tab_events` DB writes).

The original Node server is **not modified**; run this from `signing-server-go/` on a separate port or stop Node first when testing.

## Why Go

- Higher default Postgres pool (`PG_POOL_MAX=32`)
- Per-connection goroutines and sharded hub locks for concurrent admin↔client WebRTC relay
- Lower memory per idle WebSocket

## Build & run

Use the **same** `.env` as Node (do not edit `Signing server/`):

```powershell
cd signing-server-go
Copy-Item "..\\Signing server\\.env" .env -Force
go build -o bin/signaling.exe ./cmd/signaling
.\bin\signaling.exe
```

Smoke test (after server is up):

```powershell
go run ./scripts/smoke_ws.go
```

Dashboards already point at `ws://10.80.80.221:18085` with `WS_CONNECT_TOKEN=aw_ws_dev_token_2026` — no app changes needed once Go replaces Node on that host/port.

Health: `GET http://localhost:18085/health` → `{"ok":true,"service":"anywhere-signaling-go"}`

WebSocket: same URL as Node (`ws://host:port?token=WS_CONNECT_TOKEN` or header `X-Ws-Token`).

## Parity checklist

See [docs/E2E_VERIFICATION.md](docs/E2E_VERIFICATION.md) for a full matrix vs Node.

## Intentional differences

| Feature | Node | Go |
|--------|------|-----|
| Browser tab ingest GET/POST | Yes | **Removed** |
| Browser tab WS broadcast | Yes | **Removed** |
| Call events ingest | Yes | Yes |
| Taskbar ingest (broadcast, optional DB) | Yes | Broadcast only (no DB retention) |
| All WS admin/client/WebRTC types | Yes | Yes |

Point `client-dashboard`, `admin-dashboard`, and `Audit-dashboard` at the same `PORT` and `WS_CONNECT_TOKEN` as today to validate E2E.
