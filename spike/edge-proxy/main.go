// Command edge-proxy is a disposable D6-spike prototype of the Homeplane edge:
// a thin authenticating/auditing reverse proxy fronting a loopback ToolHive
// workload endpoint (the D13 composition shape).
//
// It demonstrates, minimally:
//   - per-client bearer tokens issued by Homeplane (not by the gateway),
//   - revocation taking effect on the next request (token file re-read per request),
//   - per-request audit attribution to the calling client identity,
//   - unknown-token rejection recorded with a token fingerprint, never misattributed,
//   - manifest authorization: tools/call names are checked against a declarative
//     tool->action-class manifest; UNMAPPED TOOLS ARE DENIED at invocation time
//     and the denial audited as a policy violation (fail-closed),
//   - per-call audit rows carry {client, tool, action_class}.
//
// NOT production code. No TLS (tailnet-only) and no WhoIs machine binding (needs
// tsnet on the real server). Those are the real edge's job.
//
// Usage:
//
//	edge-proxy -listen 0.0.0.0:9100 -upstream http://127.0.0.1:PORT \
//	  -tokens tokens.json -manifest manifest.json -audit audit.log
//
// tokens.json:   {"<token>": "<client-name>[@<machine>]", ...} — edit the file
// to revoke. With -whois, a token bound to "<client>@<machine>" is only valid
// when the connecting peer's tailnet identity (resolved via `tailscale whois`)
// matches <machine>; a token replayed from another node is rejected (403) and
// audited as a violation carrying the OBSERVED machine, never attributed as a
// legitimate call by the token's owner.
// manifest.json: {"<tool-name>": "read|write|send|delete", ...} — tools/call to
// any name not present is denied (403) and audited. Omit -manifest to skip
// (pre-manifest spike behavior).
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
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

// rpcCall is the subset of a JSON-RPC request the edge inspects for
// manifest authorization. Only `tools/call` is policy-checked.
type rpcCall struct {
	Method string `json:"method"`
	Params struct {
		Name string `json:"name"`
	} `json:"params"`
}

// whoisMachine resolves the tailnet machine identity of a peer IP via the
// local tailscaled (`tailscale whois --json <ip>`). It returns the node's
// short name (first DNS label), e.g. "clawniel" or "daniels-macbook-pro".
// The real edge does this in-process via tsnet's WhoIs; shelling out is the
// spike-grade equivalent against the same LocalAPI data.
func whoisMachine(remoteAddr string) (string, error) {
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}
	out, err := exec.Command("tailscale", "whois", "--json", ip).Output()
	if err != nil {
		return "", fmt.Errorf("whois %s: %w", ip, err)
	}
	var payload struct {
		Node struct {
			Name         string `json:"Name"`
			ComputedName string `json:"ComputedName"`
		} `json:"Node"`
	}
	if err := json.Unmarshal(out, &payload); err != nil {
		return "", fmt.Errorf("whois parse: %w", err)
	}
	name := payload.Node.ComputedName
	if name == "" {
		name = payload.Node.Name
	}
	if i := strings.IndexByte(name, '.'); i > 0 {
		name = name[:i]
	}
	if name == "" {
		return "", fmt.Errorf("whois %s: empty node name", ip)
	}
	return name, nil
}

func main() {
	listen := flag.String("listen", "127.0.0.1:9100", "address to listen on")
	upstream := flag.String("upstream", "", "loopback ToolHive endpoint, e.g. http://127.0.0.1:44022")
	tokensPath := flag.String("tokens", "tokens.json", "token->client JSON file (re-read every request)")
	manifestPath := flag.String("manifest", "", "tool->action-class JSON manifest; unmapped tools/call denied (omit to disable)")
	whois := flag.Bool("whois", false, "resolve peer tailnet identity per request and enforce client@machine token bindings")
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
		// Machine binding: with -whois, resolve the peer's tailnet identity and
		// enforce "<client>@<machine>" bindings. A bound token presented from a
		// different node is a violation attributed to the OBSERVED machine.
		var observedMachine string
		boundMachine := ""
		if at := strings.LastIndexByte(client, '@'); at > 0 {
			boundMachine = client[at+1:]
			client = client[:at]
		}
		if *whois {
			m, err := whoisMachine(r.RemoteAddr)
			if err != nil {
				audit(map[string]any{"event": "denied", "reason": "whois_unresolvable",
					"token_fingerprint": fingerprint(tok), "remote": r.RemoteAddr, "error": err.Error()})
				http.Error(w, "peer identity unresolvable", http.StatusForbidden)
				return
			}
			observedMachine = m
			if boundMachine != "" && observedMachine != boundMachine {
				audit(map[string]any{"event": "denied", "reason": "machine_mismatch",
					"token_fingerprint": fingerprint(tok), "bound_machine": boundMachine,
					"observed_machine": observedMachine, "remote": r.RemoteAddr})
				http.Error(w, "token not valid from this machine", http.StatusForbidden)
				return
			}
		}
		// Manifest authorization: inspect the JSON-RPC body; tools/call to a
		// tool with no manifest mapping is denied fail-closed and audited as a
		// policy violation attributed to the authenticated client.
		rec := map[string]any{"event": "forwarded", "client": client, "method": r.Method,
			"path": r.URL.Path, "remote": r.RemoteAddr}
		if observedMachine != "" {
			rec["machine"] = observedMachine
		}
		if *manifestPath != "" && r.Method == http.MethodPost {
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			var call rpcCall
			if json.Unmarshal(body, &call) == nil && call.Method == "tools/call" {
				manifest, err := loadTokens(*manifestPath) // same shape: name -> string
				if err != nil {
					audit(map[string]any{"event": "error", "reason": "manifest_unreadable"})
					http.Error(w, "server error", http.StatusInternalServerError)
					return
				}
				action, mapped := manifest[call.Params.Name]
				if !mapped {
					audit(map[string]any{"event": "denied", "reason": "unmapped_tool",
						"client": client, "tool": call.Params.Name, "remote": r.RemoteAddr})
					http.Error(w, "tool not authorized by manifest", http.StatusForbidden)
					return
				}
				rec["tool"] = call.Params.Name
				rec["action_class"] = action
			}
		}
		audit(rec)
		// Strip the Homeplane grant token before forwarding upstream.
		r.Header.Del("Authorization")
		proxy.ServeHTTP(w, r)
	})

	log.Printf("edge-proxy listening on %s -> %s", *listen, *upstream)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
