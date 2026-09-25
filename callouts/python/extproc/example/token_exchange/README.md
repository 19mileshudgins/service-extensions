# Token Exchange Callout

This callout server turns a Google Cloud Application Load Balancer (ALB) into a
seamless identity broker and zero-trust boundary. It intercepts incoming HTTP
requests, extracts external client credentials (e.g., third-party JWTs) from the
`Authorization` header, and performs a real-time OAuth 2.0 Token Exchange
(RFC 8693) with Google Cloud Security Token Service (STS) via Workload Identity
Federation (WIF) or an external Identity Provider (IdP).

The newly minted token is injected into `Authorization` before forwarding to the
backend service, while preserving the original client JWT in
`x-goog-agent-user-authorization` so downstream runtimes (such as Vertex AI
Agent Engine) can reverse-swap the user credential back into `Authorization` to
enforce user-level permissions and execute on-behalf-of (OBO) tool calls.

Use this callout when you need **real-time token exchange**, **federated
identity brokering**, or **user identity context preservation** for downstream
services and agent containers.

---

## How It Works

1. The load balancer intercepts an HTTP request on `REQUEST_HEADERS` and sends a
   `ProcessingRequest` to the callout server.
2. The server extracts the Bearer token from the `Authorization` header and
   checks the in-memory TTL cache.
3. On a cache miss, the callout exchanges the incoming token:
   - **Inbound (`TOKEN_EXCHANGE_MODE=inbound`)**: Exchanges the third-party JWT
     for a federated Google Cloud STS access token (`cloud-platform` scope)
     using Workload Identity Federation (WIF).
   - **Outbound (`TOKEN_EXCHANGE_MODE=outbound`)**: Exchanges the token against
     a configured external IdP (`OUTBOUND_TOKEN_URL`).
4. If the token exchange succeeds:
   - `Authorization` is replaced with `Bearer <exchanged_token>`.
   - In `inbound` mode, the original client JWT is preserved in
     `x-goog-agent-user-authorization` and audit identity headers
     (`x-goog-authenticated-user-email`, `x-goog-authenticated-user-id`,
     `x-original-user-groups`) are injected from decoded claims (any absent
     claim headers are stripped).
5. If the token is missing, invalid, or exchange fails:
   - By default (`FAIL_CLOSED=false`), untrusted identity headers are stripped
     and the request passes through untouched.
   - When `FAIL_CLOSED=true`, the request is rejected at the edge with an
     immediate `403 Forbidden` response.

---

## Callbacks Overridden

| Callback | Behavior |
|---|---|
| `process` / `_on_request_headers` | Extracts Bearer token, exchanges via Google STS or external IdP (with TTL caching), replaces `Authorization`, injects `x-goog-agent-user-authorization` and audit headers (stripping missing claims), or returns `403` in fail-closed mode. |

---

## Configuration

| Environment Variable | Mode | Description |
|---|---|---|
| `TOKEN_EXCHANGE_MODE` | Both | `inbound` (default, Google STS / WIF) or `outbound` (external IdP). |
| `FAIL_CLOSED` | Both | `true` to reject failed exchanges at the edge with `403`; `false` (default) to fail open. |
| `WIF_PROJECT_NUMBER` | Inbound | Google Cloud project number hosting the Workload Identity Pool. |
| `WIF_POOL_ID` | Inbound | Workload Identity Pool ID. |
| `WIF_PROVIDER_ID` | Inbound | Workload Identity Provider ID. |
| `OUTBOUND_TOKEN_URL` | Outbound | External IdP RFC 8693 token endpoint URL. |
| `OUTBOUND_CLIENT_ID` | Outbound | Optional OAuth 2.0 client ID. |
| `OUTBOUND_CLIENT_SECRET` | Outbound | Optional OAuth 2.0 client secret. |

---

## Run

```bash
cd callouts/python
python -m extproc.example.token_exchange.service_callout_example
```

---

## Test

```bash
cd callouts/python
pytest extproc/tests/token_exchange_test.py
```

---

## Expected Behavior

| Scenario | Description |
|---|---|
| **Valid third-party JWT (Inbound)** | Replaces `Authorization` with the federated Google STS access token, preserves the original JWT in `x-goog-agent-user-authorization`, and populates/strips audit claim headers. |
| **Valid token (Outbound)** | Replaces `Authorization` with the exchanged external IdP token. |
| **Cached token** | Serves the exchanged token from in-memory TTL cache without calling STS/IdP. |
| **Missing/invalid token or exchange error (`FAIL_CLOSED=false`)** | Strips untrusted inbound identity headers and passes the original request through untouched. |
| **Missing/invalid token or exchange error (`FAIL_CLOSED=true`)** | Rejects the request at the edge with an immediate `403 Forbidden` response. |

---

## Deployment

- [`deploy/terraform/`](./deploy/terraform/): Global External ALB + Cloud Run echo backend verification setup.
- [`deploy/terraform_agent_engine/`](./deploy/terraform_agent_engine/README.md): Regional External HTTPS ALB + Private Service Connect (PSC) gateway for Vertex AI Agent Runtime.

---

## Available Languages

- [x] [Python](.) (this directory)

