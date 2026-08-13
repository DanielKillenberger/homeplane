# D6 spike scratch code (disposable)

Prototype used by the D6 gateway spike (task fn-1-homeplane-walking-skeleton-install.1).
Findings and evidence live in `docs/decisions/d6-gateway.md` — this code is NOT production
and will be superseded by the real edge (task .16).

## edge-proxy

Thin authenticating/auditing reverse proxy fronting a loopback ToolHive workload
(the D13 composition shape). Reproduce the spike roughly as:

```bash
thv run fetch                          # ToolHive workload, loopback-bound proxy
thv list                               # note the http://127.0.0.1:<PORT>/mcp URL

cd spike/edge-proxy && go build -o edge-proxy .
echo '{"token-a":"claude-code","token-b":"codex"}' > /tmp/tokens.json
echo '{"fetch":"read"}' > /tmp/manifest.json      # tool -> action class; unmapped tools/call -> 403
# token values may be "<client>@<machine>" — with -whois the edge resolves the
# connecting peer's tailnet identity (tailscale whois) and rejects a bound token
# presented from any other node (403 machine_mismatch, audited).
./edge-proxy -listen <tailnet-ip>:9100 -upstream http://127.0.0.1:<PORT> \
  -tokens /tmp/tokens.json -manifest /tmp/manifest.json -whois -audit /tmp/audit.log

# MCP through the edge (streamable HTTP, protocol 2025-06-18):
curl -si -X POST http://<tailnet-ip>:9100/mcp \
  -H 'Authorization: Bearer token-a' -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}'

# Revoke = remove the token from tokens.json (re-read per request; next call → 401).
```
