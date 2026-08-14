package credflow

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// validateLoopbackRedirect enforces that a client-supplied redirect_uri is a
// genuine loopback address on the machine running the flow.
//
// Why the server validates a URI the client chose: the server BUILDS the
// authorization URL with it and repeats it at token exchange (Google requires
// the two to match exactly). So the redirect_uri is an input that decides where
// a provider will send an authorization code. A caller that could name any host
// would be asking this server to point a consent flow — carrying the human's
// real provider session — at an address of the caller's choosing.
//
// Accepted: `http://127.0.0.1:<port>` and `http://[::1]:<port>`, optionally
// with a trailing slash. Everything else is refused, and the refusals are
// specific because "invalid redirect_uri" is a miserable thing to debug.
func validateLoopbackRedirect(raw string) error {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return errors.New("redirect_uri is required")
	}
	if trimmed != raw {
		return errors.New("redirect_uri must not contain leading or trailing whitespace")
	}
	if len(raw) > 128 {
		return errors.New("redirect_uri is too long")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("redirect_uri is not a valid URL: %v", err)
	}
	if u.Scheme != "http" {
		return fmt.Errorf("redirect_uri must use the http scheme on loopback, got %q", u.Scheme)
	}
	if u.User != nil {
		return errors.New("redirect_uri must not contain userinfo")
	}
	if u.Opaque != "" {
		return errors.New("redirect_uri must be a hierarchical URL")
	}
	// Only "" and "/" are allowed. A path is not merely unnecessary here — a
	// path is where redirect-matching tricks live, and the agent's listener
	// answers the root.
	if u.EscapedPath() != "" && u.EscapedPath() != "/" {
		return errors.New("redirect_uri must not contain a path")
	}
	if u.RawQuery != "" || u.ForceQuery {
		return errors.New("redirect_uri must not contain a query string")
	}
	if u.Fragment != "" {
		return errors.New("redirect_uri must not contain a fragment")
	}

	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return errors.New("redirect_uri must include an explicit loopback port, e.g. http://127.0.0.1:53682")
	}
	// The host is compared literally rather than resolved. "localhost" is
	// deliberately refused even though it usually resolves to loopback: it is a
	// name, and what it resolves to is not this server's decision to make.
	if host != "127.0.0.1" && host != "::1" {
		return fmt.Errorf("redirect_uri host must be 127.0.0.1 or [::1], got %q", host)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("redirect_uri port %q is not a valid port number", port)
	}
	return nil
}
