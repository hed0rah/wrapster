# MCP transports

wrapster can serve the MCP protocol over three transports. The wire protocol and
tool surface are identical; only the framing differs.

| Transport | Flag | Endpoint(s) | Auth | Use it for |
|-----------|------|-------------|------|------------|
| stdio | `--mcp` | stdin/stdout | n/a (no network) | Local clients that spawn the binary (Claude Desktop/Code, Cursor, Cline) |
| Streamable HTTP | `--mcp-http <addr>` | `POST/DELETE /mcp` | optional bearer token | One wrapster shared by HTTP clients; the current MCP standard (2025-03-26) |
| HTTP+SSE (legacy) | `--mcp-sse <addr>` | `GET /sse`, `POST /message` | none (loopback only) | Older SSE-only clients; deprecated |

All HTTP transports bind to `127.0.0.1` when given a bare port (`:8080` becomes
`127.0.0.1:8080`).

## stdio

```
wrapster --mcp --policy ./policy.yaml
```

The client launches wrapster and speaks newline-delimited JSON-RPC over the pipe.
This is the default for local single-user setups and needs no auth because there
is no network surface.

## Streamable HTTP

```
wrapster --mcp-http :8080 --policy ./policy.yaml
```

One endpoint, `POST /mcp`. Each POST carries one JSON-RPC message; the response
comes back as `application/json`.

Session lifecycle:

1. Client `POST`s `initialize` with **no** `Mcp-Session-Id` header. The response
   includes a `Mcp-Session-Id` header with a freshly generated id.
2. Client echoes that `Mcp-Session-Id` on every subsequent request.
3. Client `POST`s the `notifications/initialized` notification; the session moves
   to the ready state and tool calls are accepted.
4. `DELETE /mcp` (with the `Mcp-Session-Id` header) ends the session. An unknown
   session id returns `404`, signalling the client to re-`initialize`.

Notes:

- Responses are JSON only; per-request SSE streaming is not implemented, so
  progress notifications are dropped (they are optional in the spec). Final tool
  results are always returned.
- `GET /mcp` (the optional server-initiated SSE stream) is not offered and
  returns `405`.
- A browser `Origin` header must be a loopback origin (`localhost`, `127.0.0.1`,
  `::1`); anything else returns `403` (DNS-rebinding protection). Non-browser
  clients send no `Origin` and are allowed.

Client config (Cursor, Claude Code `--transport http`, etc.):

```json
{
  "mcpServers": {
    "wrapster": {
      "type": "http",
      "url": "http://127.0.0.1:8080/mcp",
      "headers": { "Authorization": "Bearer <token>" }
    }
  }
}
```

## Authentication (Streamable HTTP)

Bearer token, the industry-standard minimal form. Exactly how it is built:

- **Enable it** with `--auth-token <token>`, or the `WRAPSTER_AUTH_TOKEN`
  environment variable. The env var is preferred: a token passed as a CLI flag is
  visible to other users via the process list (`ps`, Task Manager). The flag wins
  if both are set.
- **Every request** to `/mcp` (except the `OPTIONS` CORS preflight) must send
  `Authorization: Bearer <token>`.
- The supplied token is compared to the configured one with
  `crypto/subtle.ConstantTimeCompare`, so a wrong token takes the same time to
  reject regardless of how many leading characters match (no timing oracle).
- A missing or mismatched token returns `401 Unauthorized` with a
  `WWW-Authenticate: Bearer` header. No request body is parsed and no session is
  created until auth passes.
- Auth applies only to `--mcp-http`. stdio has no network surface; `--mcp-sse`
  (legacy) is loopback-only and unauthenticated.

Implementation: `internal/mcp/streamhttp.go` (`authOK`). Tests:
`internal/mcp/streamhttp_test.go` (`TestStreamableAuth`).

### Exposing beyond localhost

wrapster serves plain HTTP. If you need it reachable off the loopback interface,
put it behind a reverse proxy that terminates TLS (and keep the bearer token).
Do not expose the plain-HTTP port directly to an untrusted network.
