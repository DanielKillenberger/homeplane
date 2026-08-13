// Command edge-proxy is a disposable D6-spike prototype of the Homeplane edge:
// a thin authenticating/auditing reverse proxy fronting a loopback ToolHive
// workload endpoint (the D13 composition shape).
//
// It demonstrates, minimally:
//   - per-client bearer tokens issued by Homeplane (not by the gateway),
//   - revocation taking effect on the next request (token file re-read per request),
//   - per-request audit attribution to the calling client identity,
//   - unknown-token rejection recorded with a token fingerprint, never misattributed.
//
// NOT production code. No TLS (tailnet-only), no WhoIs binding (needs tsnet on
// the real server), no manifest authorization. Those are the real edge's job.
//
// Usage:
//
//	edge-proxy -listen 0.0.0.0:9100 -upstream http://127.0.0.1:PORT -tokens tokens.json -audit audit.log
//
// tokens.json: {"<token>": "<client-name>", ...} — edit the file to revoke.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

func fingerprint(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])[:12]
}

func loadTokens(path string) (map[string]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := map[string]string{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func main() {
	listen := flag.String("listen", "127.0.0.1:9100", "address to listen on")
	upstream := flag.String("upstream", "", "loopback ToolHive endpoint, e.g. http://127.0.0.1:44022")
	tokensPath := flag.String("tokens", "tokens.json", "token->client JSON file (re-read every request)")
	auditPath := flag.String("audit", "audit.log", "append-only audit log (JSON lines)")
	flag.Parse()
	if *upstream == "" {
		log.Fatal("-upstream required")
	}
	up, err := url.Parse(*upstream)
	if err != nil {
		log.Fatalf("bad upstream: %v", err)
	}

	auditFile, err := os.OpenFile(*auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.Fatalf("audit log: %v", err)
	}
	audit := func(rec map[string]any) {
		rec["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
		line, _ := json.Marshal(rec)
		fmt.Fprintln(auditFile, string(line))
	}

	proxy := httputil.NewSingleHostReverseProxy(up)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		authz := r.Header.Get("Authorization")
		tok, ok := strings.CutPrefix(authz, "Bearer ")
		if !ok || tok == "" {
			audit(map[string]any{"event": "denied", "reason": "no_bearer", "path": r.URL.Path, "remote": r.RemoteAddr})
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		// Re-read per request: revocation == removing the entry from the file.
		tokens, err := loadTokens(*tokensPath)
		if err != nil {
			audit(map[string]any{"event": "error", "reason": "token_store_unreadable"})
			http.Error(w, "server error", http.StatusInternalServerError)
			return
		}
		client, ok := tokens[tok]
		if !ok {
			// Never misattribute: log a fingerprint of the presented token only.
			audit(map[string]any{"event": "denied", "reason": "unknown_or_revoked_token",
				"token_fingerprint": fingerprint(tok), "path": r.URL.Path, "remote": r.RemoteAddr})
			http.Error(w, "invalid or revoked token", http.StatusUnauthorized)
			return
		}
		audit(map[string]any{"event": "forwarded", "client": client, "method": r.Method,
			"path": r.URL.Path, "remote": r.RemoteAddr})
		// Strip the Homeplane grant token before forwarding upstream.
		r.Header.Del("Authorization")
		proxy.ServeHTTP(w, r)
	})

	log.Printf("edge-proxy listening on %s -> %s", *listen, *upstream)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
