# Streaming transport (signing-server-go)

## Path priority

| Order | Mode | When | Cost |
|-------|------|------|------|
| 1 | `p2p-preferred` | 1 viewer, few admin targets | Lowest (STUN only, then direct) |
| 2 | `turn-relay` | 2+ viewers on same member, or 4+ admin grid targets, or approved stream-relay grant | Cloudflare/home TURN bandwidth |
| 3 | `sfu` | 3+ viewers (if `ENABLE_CLOUDFLARE_SFU` + `CLOUDFLARE_REALTIME_APP_ID`) | SFU egress; scales multi-view |

## WebSocket fields

**`welcome`**

- `iceServers` — full list (backward compatible)
- `streamTransport` — `{ mode, phaseOneMs, iceServersStunOnly, iceServersFull, ... }`

**`connect-response` / `start-offer` / `prepare-peer`**

- Per-session `streamTransport` based on live viewer counts

**`request-stream-transport-upgrade`** (client → server)

- Server replies with `stream-transport-upgrade` and TURN-heavy plan

## Env (signing-server-go/.env)

```env
ICE_PHASE_ONE_MS=5000
STREAM_TURN_VIEWER_THRESHOLD=2
STREAM_TURN_ADMIN_TARGETS_THRESHOLD=4
STREAM_SFU_VIEWER_THRESHOLD=3
STREAM_SFU_ADMIN_TARGETS_THRESHOLD=8
# Optional SFU (Cloudflare Realtime app — separate from TURN keys)
ENABLE_CLOUDFLARE_SFU=false
# CLOUDFLARE_REALTIME_APP_ID=
# CLOUDFLARE_REALTIME_API_TOKEN=
CLOUDFLARE_REALTIME_APP_ID=
CLOUDFLARE_REALTIME_API_TOKEN=
```

## Clients

- **Audit-dashboard** — uses `streamTransport` + two-phase ICE (`lib/auditStreamTransport.ts`)
- **admin-dashboard** — still uses full `iceServers` on welcome; honors per-session mode when Electron handler is extended
- **client-dashboard** — receives `prepare-peer` + `streamTransport`; renderer can adopt same two-phase pattern

## Cloudflare dual-lane failover

| Lane | Env prefix | Used for |
|------|------------|----------|
| 1 (primary) | `CLOUDFLARE_TURN_KEY_*`, `CLOUDFLARE_REALTIME_*` | Default TURN + SFU |
| 2 (secondary) | `CLOUDFLARE_TURN_KEY_*_2`, `CLOUDFLARE_REALTIME_*_2` | Failover when lane 1 billing/API errors |

- **TURN**: both healthy lanes are merged into `iceServersFull` so WebRTC can use either relay set.
- **SFU**: `sfu-api` tries lane 1 then 2 (or the reverse after failures). Publisher/subscriber stay on the same lane.
- **Health**: background probe + `media-provider-failed` from clients; cooldown `MEDIA_PROVIDER_COOLDOWN_MS` (default 45s).
- **Final fallback**: SFU exhausted → `turn-relay` → `p2p-preferred` (no user-facing error for lane flip).

```env
CLOUDFLARE_TURN_KEY_ID_2=
CLOUDFLARE_TURN_KEY_API_TOKEN_2=
CLOUDFLARE_REALTIME_APP_ID_2=
CLOUDFLARE_REALTIME_API_TOKEN_2=
MEDIA_PROVIDER_COOLDOWN_MS=45000
MEDIA_PROVIDER_PROBE_INTERVAL_MS=90000
```
