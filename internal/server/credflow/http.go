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

// fail renders an error. A non-flowError is an internal fault: its text is for
// the server's log, never for the response.
func (s *Service) fail(w http.ResponseWriter, err error) {
	var fe *flowError
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
		s.fail(w, err)
		return
	}
	provider := strings.TrimSpace(req.Provider)
	if provider == "" {
		s.fail(w, &flowError{status: http.StatusBadRequest, code: "invalid_request", message: "provider is required"})
		return
	}
	result, err := s.start(r.Context(), machineID, provider, req.RedirectURI, req.Replace)
	if err != nil {
		s.fail(w, err)
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
// It answers 202 with the flow's state rather than 200-with-a-credential: the
// machine is telling the server what it saw, and what happens next — exchange,
// storage, or a clean failure — is the server's business, observed by polling.
func (s *Service) HandleRelay(w http.ResponseWriter, r *http.Request, machineID string) {
	f, ok := s.lookup(r.PathValue("flow_id"), machineID)
	if !ok {
		s.fail(w, &flowError{status: http.StatusNotFound, code: "not_found", message: "unknown credential flow"})
		return
	}
	var req relayRequest
	if err := decode(w, r, &req); err != nil {
		s.fail(w, err)
		return
	}
	switch {
	case req.State == "":
		s.fail(w, &flowError{status: http.StatusBadRequest, code: "invalid_request", message: "state is required"})
		return
	case req.Code == "" && req.Error == "":
		s.fail(w, &flowError{status: http.StatusBadRequest, code: "invalid_request",
			message: "exactly one of code or error is required"})
		return
	case req.Code != "" && req.Error != "":
		s.fail(w, &flowError{status: http.StatusBadRequest, code: "invalid_request",
			message: "code and error are mutually exclusive"})
		return
	}

	if err := s.relay(r.Context(), f, relayOutcome{Code: req.Code, Error: req.Error, State: req.State}); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, s.view(f))
}

// HandlePoll serves GET /credentials/flows/{flow_id}.
func (s *Service) HandlePoll(w http.ResponseWriter, r *http.Request, machineID string) {
	f, ok := s.lookup(r.PathValue("flow_id"), machineID)
	if !ok {
		s.fail(w, &flowError{status: http.StatusNotFound, code: "not_found", message: "unknown credential flow"})
		return
	}
	writeJSON(w, http.StatusOK, s.view(f))
}
