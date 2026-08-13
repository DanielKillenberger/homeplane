package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/DanielKillenberger/homeplane/internal/secrets"
	"github.com/DanielKillenberger/homeplane/internal/store"
)

const adminUsage = `homeplane-server admin — server-local operator surface

  admin audit [flags]              read the append-only audit log
  admin revoke-grant <grant-id>    revoke any grant, on any machine
  admin secret init-key [flags]    create the age key protecting provider secrets
  admin secret import [flags] <ref> import a provider app credential into the store
  admin secret list [flags]        list stored credential refs (metadata only)

These commands read and write the state directory directly. They are NOT
reachable over HTTP: operator authority is shell access to this host.
`

func runAdmin(args []string) error {
	if len(args) == 0 {
		fmt.Print(adminUsage)
		return errors.New("admin: no subcommand given")
	}
	switch args[0] {
	case "audit":
		return runAdminAudit(args[1:])
	case "revoke-grant":
		return runAdminRevokeGrant(args[1:])
	case "secret":
		return runAdminSecret(args[1:])
	case "-h", "--help", "help":
		fmt.Print(adminUsage)
		return nil
	default:
		fmt.Print(adminUsage)
		return fmt.Errorf("admin: unknown subcommand %q", args[0])
	}
}

// openStore opens the control-plane database for an admin command.
func openStore(stateDir string) (*store.SQLite, error) {
	path := dbPath(stateDir)
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("no Homeplane database at %s: %w", path, err)
	}
	return store.Open(path)
}

func runAdminAudit(args []string) error {
	fs := flag.NewFlagSet("admin audit", flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "Homeplane state directory")
	since := fs.String("since", "", "only events at or after this time: RFC3339 timestamp or a duration like 24h")
	limit := fs.Int("limit", 200, "maximum rows to return (0 = no limit)")
	asJSON := fs.Bool("json", false, "emit JSON lines instead of a table")
	if err := fs.Parse(args); err != nil {
		return err
	}

	sinceTime, err := parseSince(*since)
	if err != nil {
		return err
	}

	st, err := openStore(*stateDir)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx := context.Background()
	events, err := st.QueryAudit(ctx, store.AuditQuery{Since: sinceTime, Limit: *limit})
	if err != nil {
		return err
	}

	// The operator's own read is itself an audited event: an append-only log
	// that cannot show who read it is only half a record. ActorOperator with no
	// observed node is the honest attribution — there is no network caller.
	// A failure to record it fails the command: silently succeeding would leave
	// the operator believing the read was logged when it was not.
	detail := map[string]string{"limit": strconv.Itoa(*limit)}
	if !sinceTime.IsZero() {
		detail["since"] = sinceTime.UTC().Format(time.RFC3339)
	}
	if err := st.AppendAudit(ctx, store.AuditEvent{
		Event:     store.EventAuditQueried,
		ActorKind: store.ActorOperator,
		Outcome:   store.OutcomeAllowed,
		Detail:    detail,
	}); err != nil {
		return fmt.Errorf("could not record the audit-read event: %w", err)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		for _, e := range events {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tEVENT\tACTOR\tOBSERVED\tMACHINE\tHARNESS\tGRANT\tOUTCOME\tREASON\tTOKEN-FP")
	for _, e := range events {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			e.TS.UTC().Format(time.RFC3339), e.Event, e.ActorKind,
			dash(e.ObservedNodeName), dash(e.AuthMachineID), dash(e.Harness), dash(e.GrantID),
			e.Outcome, dash(e.Reason), dash(e.TokenFingerprint))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%d event(s)\n", len(events))
	return nil
}

func runAdminRevokeGrant(args []string) error {
	fs := flag.NewFlagSet("admin revoke-grant", flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "Homeplane state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: homeplane-server admin revoke-grant <grant-id>")
	}
	grantID := fs.Arg(0)

	st, err := openStore(*stateDir)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx := context.Background()
	// The revocation and its audit row commit together; if the record cannot be
	// written, the grant is not revoked either.
	g, changed, err := st.RevokeGrant(ctx, grantID, "revoked_by_operator",
		func(g store.Grant) []store.AuditEvent {
			return []store.AuditEvent{{
				Event:     store.EventGrantRevoked,
				ActorKind: store.ActorOperator,
				// AuthMachineID stays EMPTY: the actor is the local operator,
				// not the machine. The affected machine is the TARGET of the
				// action and is recorded as such — conflating the two would
				// make the log read as though that machine revoked its own
				// grant.
				Harness: g.Harness,
				GrantID: g.ID,
				Outcome: store.OutcomeAllowed,
				Reason:  "revoked_by_operator",
				Detail:  map[string]string{"target_machine_id": g.MachineID},
			}}
		})
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("unknown grant %q", grantID)
		}
		return err
	}
	if changed {
		fmt.Printf("revoked grant %s (machine %s, harness %s)\n", g.ID, g.MachineID, g.Harness)
		return nil
	}
	fmt.Printf("grant %s was already revoked at %s\n", g.ID, formatOptionalTime(g.RevokedAt))
	return nil
}

func runAdminSecret(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: homeplane-server admin secret <init-key|import|list>")
	}
	switch args[0] {
	case "init-key":
		return runAdminSecretInitKey(args[1:])
	case "import":
		return runAdminSecretImport(args[1:])
	case "list":
		return runAdminSecretList(args[1:])
	default:
		return fmt.Errorf("admin secret: unknown subcommand %q", args[0])
	}
}

func runAdminSecretInitKey(args []string) error {
	fs := flag.NewFlagSet("admin secret init-key", flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "Homeplane state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}
	kr, err := secrets.GenerateKeyFile(keyFilePath(*stateDir))
	if err != nil {
		return err
	}
	fmt.Printf("wrote %s (0600)\npublic key: %s\nBack this file up offline: without it, every stored provider secret is unrecoverable.\n",
		keyFilePath(*stateDir), kr.Recipient())
	return nil
}

// runAdminSecretImport bootstraps a provider app credential (e.g. the Google
// OAuth client secret) into the D3 store.
//
// It exists precisely so that app credentials never ride the network API: the
// value arrives on protected stdin or from a 0600 file on this host, is
// age-encrypted before it touches the database, and is never echoed, logged, or
// passed as an argv value (which would be world-readable in `ps`).
func runAdminSecretImport(args []string) error {
	fs := flag.NewFlagSet("admin secret import", flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "Homeplane state directory")
	file := fs.String("file", "", "read the secret from this file (must be a regular 0600 file) instead of stdin")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "homeplane-server admin secret import [flags] <ref>\n\n")
		fs.PrintDefaults()
		fmt.Fprintf(fs.Output(), "\nThe secret VALUE is never accepted as a command-line argument: argv is\nworld-readable via ps. Pipe it on stdin or point -file at a 0600 file.\n")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		// Flags BEFORE the ref: Go's flag parser stops at the first
		// positional argument, so `import <ref> -file x` silently leaves
		// -file unparsed and looks like a usage error for no visible reason.
		return errors.New("usage: homeplane-server admin secret import [-state-dir dir] [-file path] <ref>")
	}
	ref := strings.TrimSpace(fs.Arg(0))
	if ref == "" {
		return errors.New("secret ref is required")
	}

	plaintext, source, err := readSecretValue(*file)
	if err != nil {
		return err
	}
	if len(plaintext) == 0 {
		return errors.New("refusing to store an empty secret")
	}

	kr, err := secrets.LoadKeyFile(keyFilePath(*stateDir))
	if err != nil {
		return fmt.Errorf("%w (run `homeplane-server admin secret init-key` first)", err)
	}
	ciphertext, err := kr.Encrypt(plaintext)
	if err != nil {
		return err
	}

	st, err := openStore(*stateDir)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx := context.Background()
	generation, err := st.PutSecret(ctx, ref, ciphertext, func(generation int64) []store.AuditEvent {
		return []store.AuditEvent{{
			Event:     store.EventSecretImported,
			ActorKind: store.ActorOperator,
			Outcome:   store.OutcomeAllowed,
			Detail: map[string]string{
				"secret_ref":        ref,
				"secret_generation": strconv.FormatInt(generation, 10),
				"source":            source,
			},
		}}
	})
	if err != nil {
		return err
	}
	// Report the ref and generation only. The value is never echoed back.
	fmt.Printf("imported secret %q (generation %d, %d bytes, source %s)\n", ref, generation, len(plaintext), source)
	return nil
}

// runAdminSecretList reports WHICH credentials this server holds, and whether
// they are really encrypted — without any path that could return one.
//
// It exists because "is the credential actually in the store right now?" had no
// answer short of reading the database by hand. The audit log is not that
// answer: it records that an import HAPPENED, which is a fact about the past,
// not about the current contents of the store.
//
// The output is metadata only — ref, generation, ciphertext length, encrypted
// flag, timestamps. `encrypted: false` on any row means plaintext reached the
// secrets table and is the one thing here worth treating as an emergency.
func runAdminSecretList(args []string) error {
	fs := flag.NewFlagSet("admin secret list", flag.ContinueOnError)
	stateDir := fs.String("state-dir", defaultStateDir(), "Homeplane state directory")
	asJSON := fs.Bool("json", false, "emit JSON lines instead of a table")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "homeplane-server admin secret list [flags]\n\n")
		fs.PrintDefaults()
		fmt.Fprintf(fs.Output(), "\nSecret VALUES are never printed: this command cannot read them.\n")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	st, err := openStore(*stateDir)
	if err != nil {
		return err
	}
	defer st.Close()

	metas, err := st.ListSecretMeta(context.Background())
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		for _, m := range metas {
			if err := enc.Encode(m); err != nil {
				return err
			}
		}
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "REF\tGENERATION\tENCRYPTED\tBYTES\tUPDATED")
	for _, m := range metas {
		fmt.Fprintf(tw, "%s\t%d\t%t\t%d\t%s\n",
			m.Ref, m.Generation, m.Encrypted, m.CiphertextBytes, m.UpdatedAt.UTC().Format(time.RFC3339))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%d secret(s)\n", len(metas))
	return nil
}

// readSecretValue reads a secret from a validated file or from non-terminal
// stdin. A terminal stdin is refused: an interactive paste would land in shell
// history and scrollback.
func readSecretValue(path string) ([]byte, string, error) {
	if path != "" {
		info, err := os.Stat(path)
		if err != nil {
			return nil, "", fmt.Errorf("secret file: %w", err)
		}
		if !info.Mode().IsRegular() {
			return nil, "", fmt.Errorf("secret file %s is not a regular file", path)
		}
		if info.Mode().Perm()&0o077 != 0 {
			return nil, "", fmt.Errorf("secret file %s has mode %#o; want 0600 (not group- or world-readable)", path, info.Mode().Perm())
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, "", fmt.Errorf("secret file: %w", err)
		}
		return trimTrailingNewline(raw), "file", nil
	}

	info, err := os.Stdin.Stat()
	if err != nil {
		return nil, "", fmt.Errorf("stdin: %w", err)
	}
	if info.Mode()&os.ModeCharDevice != 0 {
		return nil, "", errors.New("stdin is a terminal: pipe the secret in (e.g. `pass show ... | homeplane-server admin secret import <ref>`) or use -file")
	}
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		return nil, "", fmt.Errorf("stdin: %w", err)
	}
	return trimTrailingNewline(raw), "stdin", nil
}

// trimTrailingNewline drops the single trailing newline a shell pipeline adds,
// which is almost never part of the secret itself.
func trimTrailingNewline(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
	}
	if n := len(b); n > 0 && b[n-1] == '\r' {
		b = b[:n-1]
	}
	return b
}

// parseSince accepts an RFC3339 timestamp or a Go duration ("24h") meaning
// "that long ago".
func parseSince(v string) (time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t.UTC(), nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return time.Time{}, fmt.Errorf("-since %q: want an RFC3339 timestamp or a duration like 24h", v)
	}
	if d < 0 {
		d = -d
	}
	return time.Now().UTC().Add(-d), nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func formatOptionalTime(t *time.Time) string {
	if t == nil {
		return "unknown"
	}
	return t.UTC().Format(time.RFC3339)
}
