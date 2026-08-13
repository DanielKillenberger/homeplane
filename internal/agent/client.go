package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultTimeout bounds every control-plane call. The agent talks to the
// server over the tailnet; a hung connection must surface as an unreachable
// server, not as a CLI that never returns.
const DefaultTimeout = 15 * time.Second

// maxResponseBytes bounds a response body. Every payload on this API is a
// handful of short fields.
const maxResponseBytes = 1 << 20

// Client is the machine-side control-plane client.
//
// It carries the machine credential for authenticated endpoints. The
// credential is sent in an Authorization header and nowhere else — never in a
// URL, never in a log line.
type Client struct {
	baseURL    string
	credential string
	http       *http.Client
}

// NewClient builds a client for the control plane at baseURL. An empty or
// non-absolute URL is refused here rather than producing a confusing transport
// error at the first call.
func NewClient(baseURL string, timeout time.Duration) (*Client, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if trimmed == "" {
		return nil, errors.New("agent: server URL is required (pass -server or set " + EnvServerURL + ")")
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("agent: invalid server URL %q: %w", baseURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("agent: server URL %q must be http or https", baseURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("agent: server URL %q has no host", baseURL)
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Client{baseURL: trimmed, http: &http.Client{Timeout: timeout}}, nil
}

// WithCredential returns a copy of the client that authenticates as the
// machine holding the given credential.
func (c *Client) WithCredential(credential string) *Client {
	clone := *c
	clone.credential = credential
	return &clone
}

// BaseURL returns the control-plane URL this client talks to.
func (c *Client) BaseURL() string { return c.baseURL }

// TransportError means the server could not be reached or did not answer —
// the failure mode that must never be reported as a capability state. It is a
// distinct type because "unreachable" and "refused" demand different words to
// the operator and different states in `status` (R2, R10).
type TransportError struct {
	Op  string
	URL string
	Err error
}

func (e *TransportError) Error() string {
	return fmt.Sprintf("%s: server at %s is unreachable: %v", e.Op, e.URL, e.Err)
}
func (e *TransportError) Unwrap() error { return e.Err }

// Unreachable reports whether err is (or wraps) a transport failure.
func Unreachable(err error) bool {
	var te *TransportError
	return errors.As(err, &te)
}

// APIError is a well-formed refusal from the server: the request arrived and
// was answered with a non-2xx status.
type APIError struct {
	Op      string
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	if e.Code != "" {
		return fmt.Sprintf("%s: server refused the request (%d %s): %s", e.Op, e.Status, e.Code, msg)
	}
	return fmt.Sprintf("%s: server refused the request (%d): %s", e.Op, e.Status, msg)
}

// EnrolResult is the server's answer to an enrolment.
type EnrolResult struct {
	MachineID         string `json:"machine_id"`
	MachineCredential string `json:"machine_credential"`
	Rotated           bool   `json:"rotated"`
	CredentialVersion int64  `json:"credential_version"`
}

// Enrol registers this machine (or rotates its credential) with the server.
func (c *Client) Enrol(ctx context.Context, machineName, osName string) (EnrolResult, error) {
	body := map[string]string{"machine_name": machineName, "os": osName}
	var out EnrolResult
	if err := c.do(ctx, "enrol", http.MethodPost, "/enrol", body, &out); err != nil {
		return EnrolResult{}, err
	}
	if out.MachineID == "" || out.MachineCredential == "" {
		return EnrolResult{}, fmt.Errorf("enrol: server response is missing machine identity or credential")
	}
	return out, nil
}

// Grant is the non-secret view of a grant as the server reports it.
type Grant struct {
	GrantID      string   `json:"grant_id"`
	Harness      string   `json:"harness"`
	Capabilities []string `json:"capabilities"`
	State        string   `json:"state"`
	CreatedAt    string   `json:"created_at"`
	RevokedAt    string   `json:"revoked_at,omitempty"`
}

// ListGrants reads the calling machine's grants from the server. This is the
// live reconcile behind `status`: the agent keeps no cached grant state to be
// wrong about.
func (c *Client) ListGrants(ctx context.Context) ([]Grant, error) {
	var out struct {
		Grants []Grant `json:"grants"`
	}
	if err := c.do(ctx, "list grants", http.MethodGet, "/grants", nil, &out); err != nil {
		return nil, err
	}
	return out.Grants, nil
}

// HealthReport is the server's /healthz payload.
type HealthReport struct {
	Status     string `json:"status"`
	Components []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Detail string `json:"detail,omitempty"`
	} `json:"components"`
}

// Health reads server-side health. A degraded server answers 503 with a body;
// that is a successful read of a degraded server, not a failed call, so the
// report is returned rather than an error.
func (c *Client) Health(ctx context.Context) (HealthReport, error) {
	var out HealthReport
	err := c.do(ctx, "healthz", http.MethodGet, "/healthz", nil, &out)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusServiceUnavailable && out.Status != "" {
		return out, nil
	}
	if err != nil {
		return HealthReport{}, err
	}
	return out, nil
}

func (c *Client) do(ctx context.Context, op, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("%s: encode request: %w", op, err)
		}
		reader = bytes.NewReader(encoded)
	}
	endpoint := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return fmt.Errorf("%s: build request: %w", op, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.credential != "" {
		req.Header.Set("Authorization", "Bearer "+c.credential)
	}

	res, err := c.http.Do(req)
	if err != nil {
		return &TransportError{Op: op, URL: c.baseURL, Err: err}
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes))
	if err != nil {
		return &TransportError{Op: op, URL: c.baseURL, Err: err}
	}

	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		// A decode failure on an error response is not worth surfacing over the
		// status itself, so it is only fatal for a 2xx.
		if decodeErr := json.Unmarshal(raw, out); decodeErr != nil && res.StatusCode/100 == 2 {
			return fmt.Errorf("%s: malformed server response: %w", op, decodeErr)
		}
	}

	if res.StatusCode/100 != 2 {
		var errBody struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &errBody)
		return &APIError{Op: op, Status: res.StatusCode, Code: errBody.Error, Message: errBody.Message}
	}
	return nil
}
