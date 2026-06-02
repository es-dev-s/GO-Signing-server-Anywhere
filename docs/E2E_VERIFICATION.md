# E2E verification: Node vs Go signaling server

Use the **same** Supabase/Postgres database and env tokens. Do not run Node and Go on the same `PORT` simultaneously.

## Prerequisites

1. Copy env from `Signing server/.env` → `signing-server-go/.env` (at minimum `DATABASE_URL`, `WS_CONNECT_TOKEN`, `INGEST_TOKEN_SECRET`, `PORT`).
2. Stop the Node signaling process if binding the same port.
3. Build: `go build -o bin/signaling.exe ./cmd/signaling`
4. Start Go server: `.\bin\signaling.exe`
5. Confirm health: `curl http://127.0.0.1:18085/health`

## Dashboard wiring (unchanged)

| App | Env | Must match Go server |
|-----|-----|----------------------|
| client-dashboard | signaling URL + `WS_CONNECT_TOKEN` | Yes |
| admin-dashboard | signaling URL + token | Yes |
| Audit-dashboard | signaling URL + token + audit proxy vars on **server** | Yes |

`AUDIT_DASHBOARD_URL` and `AUDIT_SUPERADMIN_SERVICE_SECRET` on the signaling host enable WS proxy types `admin-audit-*`.

## Test matrix

### WebSocket — public / auth

| Step | Message | Expected |
|------|---------|----------|
| 1 | Connect with valid `?token=` | `welcome` + `socketId` + `iceServers` |
| 2 | `public-list-orgs` | `public-list-orgs-response` with orgs |
| 3 | Client: `client-auth` | `client-auth-response` + `ingestToken` |
| 4 | Admin: `admin-login` | `admin-login-response` + token + `adminUiFeatures` |
| 5 | Admin: `admin-get-clients` | roster with live `sharing`/`online`/`offline` |

### WebRTC streaming (audit / admin)

| Step | Action | Expected |
|------|--------|----------|
| 1 | `connect-to-client` + `token` + `clientId` | `connect-response` success, client receives `prepare-peer` |
| 2 | Relay `offer` / `answer` / `ice-candidate` | Peers receive relayed payloads with `fromSocketId` |
| 3 | Dual audit panes (two view keys) | Two concurrent `connect-to-client` within `MAX_VIEWERS_PER_CLIENT` |
| 4 | `admin-stop-viewing` | `admin-stop-viewing-response`, client `agent-disconnected` |

### HTTP ingest

| Route | Auth | Expected |
|-------|------|----------|
| `POST /api/call-events` | Bearer ingest token from client-auth | `200` `{ok,true,accepted:N}` |
| `POST /api/taskbar-events` | (payload) | `200`; admins may see `taskbar-events-update` on WS |
| `GET /api/browser-tab-events` | — | **404** on Go server (by design) |
| `POST /api/browser-tab-events` | — | **404** on Go server (by design) |

### Super-admin audit proxy (optional)

| WS type | Expected |
|---------|----------|
| `admin-audit-org-access-list` | `...-response` or `AUDIT_PROXY_NOT_CONFIGURED` |
| `admin-audit-groups-get` | groups list or not configured |

### Remote access / stream relay

| WS type | Role | Expected |
|---------|------|----------|
| `remote-access-request` | org_admin | `remote-access-request-response` |
| `stream-relay-request` | org_admin | `stream-relay-request-response` |
| `approve-stream-relay` | super_admin | `approve-stream-relay-response` |

## Regression notes (Audit-dashboard streaming)

If live feed shows “Establishing stream…” forever:

- Ensure `connect-to-client`, `getStream`, and `releaseStream` use the **same** audit view key (see `Audit-dashboard/lib/auditStreamViewKey.ts`).
- Confirm client is `sharing` on signaling roster (`admin-get-clients` or `admin-clients-updated`).

## Known Go gaps (non-blocking for core streaming)

- Transfer request create/respond: list stub only; extend `internal/db` if you rely on full transfer workflow.
- Taskbar history GET: returns empty list (live WS broadcast only).
- Legacy `.env.turn` file auto-load: set TURN_* in `.env` explicitly for Go.

## Sign-off

E2E pass when:

1. Client enrolls and stays `sharing` on roster.
2. Audit/admin opens member stream and video renders within ~30s.
3. Call-event ingest returns 200 with valid ingest token.
4. Browser-tab extension/UI shows no data from signaling (expected on Go).
