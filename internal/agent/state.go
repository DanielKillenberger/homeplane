// Package agent owns the machine side of Homeplane: the on-disk agent state
// directory, the control-plane client, enrolment, and truthful status.
//
// Two rules shape this package:
//
//   - Custody. The machine credential lives in its own 0600 file inside a 0700
//     state directory, is never written to logs, argv, or status output, and is
//     replaced atomically. Everything else the agent knows is non-secret and
//     lives in state.json.
//   - Truthfulness. Status never reports a cached belief as a live fact. Grants
//     are reconciled against the server on every call; when the server cannot be
//     reached the answer is "unknown", never a stale "active" (R10).
package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Environment overrides. Both exist so the agent can be exercised in tests and
// on machines that keep state outside $HOME.
const (
	// EnvStateDir overrides the agent state directory.
	EnvStateDir = "HOMEPLANE_AGENT_STATE_DIR"
	// EnvServerURL supplies a default control-plane URL.
	EnvServerURL = "HOMEPLANE_SERVER_URL"
)

// File names inside the state directory.
const (
	stateFileName      = "state.json"
	credentialFileName = "machine.cred"
)

// Permissions. The directory is owner-only and every file inside it is 0600 —
// the credential because it is a secret, state.json because it names the
// machine's server and identity and there is no reason for it to be readable
// by anything but the agent.
const (
	dirPerm  fs.FileMode = 0o700
	filePerm fs.FileMode = 0o600
)

// StateSchemaVersion is bumped when the on-disk shape changes incompatibly.
const StateSchemaVersion = 1

// ComponentState is the recorded state of a machine-side component that later
// tasks own (vault sync, GNO, harness configuration). The agent CLI in this
// task never writes these; it reports them, and reports their absence honestly.
type ComponentState struct {
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

// State is the non-secret machine state. The credential is deliberately NOT a
// field here: it lives in its own file so that reading, printing, or copying
// state can never leak it.
type State struct {
	SchemaVersion     int        `json:"schema_version"`
	ServerURL         string     `json:"server_url"`
	MachineID         string     `json:"machine_id"`
	MachineName       string     `json:"machine_name"`
	OS                string     `json:"os"`
	CredentialVersion int64      `json:"credential_version"`
	EnroledAt         time.Time  `json:"enroled_at"`
	RotatedAt         *time.Time `json:"rotated_at,omitempty"`

	// Owned by later tasks (.5 vault/sync, .11 GNO, .6 harnesses, .9 skills).
	// They are read and reported by status; this task never populates them.
	VaultPath string          `json:"vault_path,omitempty"`
	Sync      *ComponentState `json:"sync,omitempty"`
	GNO       *ComponentState `json:"gno,omitempty"`
	Harnesses []string        `json:"harnesses,omitempty"`
	Skills    []string        `json:"skills,omitempty"`
}

// Enroled reports whether the state names an enrolled machine.
func (s State) Enroled() bool { return s.MachineID != "" && s.ServerURL != "" }

// Store is the agent state directory.
//
// It remembers any JSON keys it did not recognise when loading and writes them
// back out unchanged. That is what lets a future task add a field to state.json
// without a re-enrol from an older agent silently deleting it.
type Store struct {
	dir     string
	unknown map[string]json.RawMessage
}

// DefaultStateDir resolves the agent state directory.
//
// `$HOMEPLANE_AGENT_STATE_DIR` wins when set. On Linux, `$XDG_STATE_HOME` is
// honoured when set (XDG systems keep mutable per-user state there); otherwise,
// and always on macOS, the directory is `~/.homeplane`.
func DefaultStateDir() (string, error) {
	if v := os.Getenv(EnvStateDir); v != "" {
		return v, nil
	}
	if runtime.GOOS == "linux" {
		if xdg := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(xdg) {
			return filepath.Join(xdg, "homeplane"), nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, ".homeplane"), nil
}

// Open prepares the state directory, creating it 0700 if absent and tightening
// the permissions of an existing directory that is too permissive.
//
// Tightening rather than merely warning is deliberate: the credential file
// below it is only as protected as the directory that holds it, and an agent
// that noticed the problem and did nothing would be theatre.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("agent: state directory is required")
	}
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("create agent state dir %s: %w", dir, err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat agent state dir %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("agent state path %s is not a directory", dir)
	}
	if info.Mode().Perm() != dirPerm {
		if err := os.Chmod(dir, dirPerm); err != nil {
			return nil, fmt.Errorf("tighten permissions on %s: %w", dir, err)
		}
	}
	return &Store{dir: dir}, nil
}

// Dir returns the state directory path.
func (s *Store) Dir() string { return s.dir }

// StatePath returns the path of the non-secret state file.
func (s *Store) StatePath() string { return filepath.Join(s.dir, stateFileName) }

// CredentialPath returns the path of the machine credential file.
func (s *Store) CredentialPath() string { return filepath.Join(s.dir, credentialFileName) }

// Load reads state.json. A missing file is not an error: it is the honest
// answer "this machine is not enrolled", which status must be able to report.
func (s *Store) Load() (State, bool, error) {
	raw, err := os.ReadFile(s.StatePath())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return State{}, false, nil
		}
		return State{}, false, fmt.Errorf("read %s: %w", s.StatePath(), err)
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		return State{}, false, fmt.Errorf("parse %s: %w", s.StatePath(), err)
	}
	all := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &all); err != nil {
		return State{}, false, fmt.Errorf("parse %s: %w", s.StatePath(), err)
	}
	for _, known := range knownStateKeys {
		delete(all, known)
	}
	s.unknown = all
	return st, true, nil
}

// knownStateKeys are the JSON keys State itself owns; anything else found in
// state.json is preserved verbatim across writes.
var knownStateKeys = []string{
	"schema_version", "server_url", "machine_id", "machine_name", "os",
	"credential_version", "enroled_at", "rotated_at",
	"vault_path", "sync", "gno", "harnesses", "skills",
}

// Save writes state.json atomically, preserving unrecognised keys.
func (s *Store) Save(st State) error {
	if st.SchemaVersion == 0 {
		st.SchemaVersion = StateSchemaVersion
	}
	encoded, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("encode agent state: %w", err)
	}
	merged := map[string]json.RawMessage{}
	for k, v := range s.unknown {
		merged[k] = v
	}
	var known map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &known); err != nil {
		return fmt.Errorf("encode agent state: %w", err)
	}
	for k, v := range known {
		merged[k] = v
	}
	out, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return fmt.Errorf("encode agent state: %w", err)
	}
	return writeFileAtomic(s.StatePath(), append(out, '\n'), filePerm)
}

// Credential reads the machine credential. ErrNotEnroled is returned when the
// file is absent so callers can tell "no credential yet" from "unreadable".
func (s *Store) Credential() (string, error) {
	raw, err := os.ReadFile(s.CredentialPath())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", ErrNotEnroled
		}
		return "", fmt.Errorf("read machine credential: %w", err)
	}
	return string(trimTrailingNewline(raw)), nil
}

// ErrNotEnroled means the machine has no stored credential.
var ErrNotEnroled = errors.New("agent: machine is not enrolled")

// SaveEnrolment persists a credential and its state.
//
// The credential is written FIRST, and atomically. By the time this is called
// the server has already rotated: the old credential is dead, so the one thing
// that must never be lost is the new secret. state.json is metadata that a
// subsequent enrol can rebuild; a lost credential can only be recovered by
// enrolling again, and a half-written one could not be recovered at all.
func (s *Store) SaveEnrolment(st State, credential string) error {
	if credential == "" {
		return errors.New("agent: refusing to persist an empty machine credential")
	}
	if err := writeFileAtomic(s.CredentialPath(), []byte(credential+"\n"), filePerm); err != nil {
		return fmt.Errorf("persist machine credential: %w", err)
	}
	if err := s.Save(st); err != nil {
		return fmt.Errorf("persist agent state (the new credential IS stored at %s; re-run `homeplane-agent enrol` to rebuild state): %w",
			s.CredentialPath(), err)
	}
	return nil
}

// writeFileAtomic writes data to path via a same-directory temporary file,
// fsynced and renamed into place, so a reader (or a crash) never observes a
// partially written credential or a truncated state file.
func writeFileAtomic(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName) // no-op once the rename succeeded
	}()

	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	// Fsync the directory so the rename itself survives a crash.
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}

func trimTrailingNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
