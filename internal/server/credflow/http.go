package credflow

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// The handlers here take an already-authenticated machine id rather than
// authenticating for themselves. Authentication is the control plane's job and
// lives in exactly one place (internal/server): a second implementation of
// "who is calling" is how the two eventually disagree.

// MaxRequestBytes bounds a credential-flow request body. Every field on this
// API is a short string.
const MaxRequestBytes = 16 << 10

// flowError is a refusal with a chosen HTTP shape.
type flowError struct {
	status          int
	code            string
	message         string
	unknownProvider bool
}

func (e *flowError) Error() string { return e.message }

type errorBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	// KnownProviders is present only on an unknown-provider 404: being told the
	// provider is unknown without being told what IS known is a dead end for
	// whoever typed the name.
	KnownProviders []string `json:"known_providers,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

// writeErr renders an error. A non-flowError is an internal fault: its text is
// for the server's log, never for the response.
func (s *Service) writeErr(w http.ResponseWriter, err error) {
	var fe *flowError
	if errors.Is(err, errTerminalUnrecorded) {
		// The flow has finished, but showing an outcome the audit log never
		// learned of would break the record this server is judged on. The
		// caller polls again; the write is retried each time.
		s.log.Error("credential flow terminal state unrecorded", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, errorBody{Error: "unavailable",
			Message: "this flow has finished, but the outcome could not be recorded yet (audit log unavailable); poll again"})
		return
	}
	if errors.As(err, &fe) {
		body := errorBody{Error: fe.code, Message: fe.message}
		if fe.unknownProvider {
			body.KnownProviders = s.Providers()
		}
		writeJSON(w, fe.status, body)
		return
	}
	s.log.Error("credential flow", "error", err)
	writeJSON(w, http.StatusInternalServerError, errorBody{Error: "internal", Message: "credential flow failed"})
}

func decode(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return &flowError{status: http.StatusBadRequest, code: "invalid_request",
			message: "malformed request body: " + err.Error()}
	}
	return nil
}

type startRequest struct {
	Provider    string `json:"provider"`
	Replace     bool   `json:"replace"`
	RedirectURI string `json:"redirect_uri"`
}

// HandleStart serves POST /credentials/flows.
func (s *Service) HandleStart(w http.ResponseWriter, r *http.Request, machineID string) {
	var req startRequest
	if err := decode(w, r, &req); err != nil {
		s.writeErr(w, err)
		return
	}
	provider := strings.TrimSpace(req.Provider)
	if provider == "" {
		s.writeErr(w, &flowError{status: http.StatusBadRequest, code: "invalid_request", message: "provider is required"})
		return
	}
	result, err := s.start(r.Context(), machineID, provider, req.RedirectURI, req.Replace)
	if err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

// relayRequest is the client's one-shot report of what landed on its loopback
// listener: an authorization code, or the provider's denial. Exactly one.
type relayRequest struct {
	Code  string `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
	State string `json:"state"`
}

// HandleRelay serves POST /credentials/flows/{flow_id}/code.
//
// It answers 202 as soon as the outcome is CONSUMED — usually still `pending`,
// because redeeming the code with the provider is a server-owned job. The
// machine is telling the server what the human did; what that turns into is
// learned by polling. This response deliberately promises nothing about the
// credential, so a relay response lost in transit costs the machine nothing but
// another poll.
func (s *Service) HandleRelay(w http.ResponseWriter, r *http.Request, machineID string) {
	f, ok := s.lookup(r.PathValue("flow_id"), machineID)
	if !ok {
		s.writeErr(w, &flowError{status: http.StatusNotFound, code: "not_found", message: "unknown credential flow"})
		return
	}
	// A flow whose window closed while the human was consenting is expired
	// before its code is looked at.
	if err := s.settle(r.Context(), f); err != nil {
		s.writeErr(w, err)
		return
	}
	var req relayRequest
	if err := decode(w, r, &req); err != nil {
		s.writeErr(w, err)
		return
	}
	switch {
	case req.State == "":
		s.writeErr(w, &flowError{status: http.StatusBadRequest, code: "invalid_request", message: "state is required"})
		return
	case req.Code == "" && req.Error == "":
		s.writeErr(w, &flowError{status: http.StatusBadRequest, code: "invalid_request",
			message: "exactly one of code or error is required"})
		return
	case req.Code != "" && req.Error != "":
		s.writeErr(w, &flowError{status: http.StatusBadRequest, code: "invalid_request",
			message: "code and error are mutually exclusive"})
		return
	}

	if err := s.relay(r.Context(), f, relayOutcome{Code: req.Code, Error: req.Error, State: req.State}); err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, s.view(f))
}

// HandlePoll serves GET /credentials/flows/{flow_id}.
//
// This is the authoritative way a machine learns a flow's outcome. It applies a
// due expiry and retries the audit row for any outcome that was decided but not
// yet recorded, so a poll never shows a terminal state the log does not have.
func (s *Service) HandlePoll(w http.ResponseWriter, r *http.Request, machineID string) {
	f, ok := s.lookup(r.PathValue("flow_id"), machineID)
	if !ok {
		s.writeErr(w, &flowError{status: http.StatusNotFound, code: "not_found", message: "unknown credential flow"})
		return
	}
	if err := s.settle(r.Context(), f); err != nil {
		s.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.view(f))
}
