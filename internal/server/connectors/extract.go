package connectors

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ArtifactUnknown is the artifact id recorded when no extractor is declared, or
// when a declared extractor finds nothing. It is a deliberate value rather than
// an empty column: "we could not identify the artifact" must be visible in the
// audit log, not indistinguishable from an unwritten field.
const ArtifactUnknown = "unknown"

// MaxArtifactIDLen bounds an extracted artifact id. Anything longer is treated
// as not extractable: an audit field is an identity slot, and a long value is
// far more likely to be payload content than an id.
const MaxArtifactIDLen = 200

// argsDigestDomain separates argument digests from every other hash in the
// system (credential hashes, token fingerprints), so a digest can never be
// compared against them.
const argsDigestDomain = "homeplane/connector-args\x00"

// ArgsDigest returns a stable, non-reversible digest of a tool call's request
// arguments. This is what the audit log records INSTEAD of the arguments: it
// lets an operator see that two calls carried the same arguments, and see
// nothing about what those arguments were.
//
// Digesting is over the canonical (key-sorted, whitespace-free) encoding when
// the arguments are valid JSON, so semantically identical requests digest
// identically regardless of formatting.
func ArgsDigest(args json.RawMessage) string {
	canonical := canonicalJSON(args)
	sum := sha256.Sum256(append([]byte(argsDigestDomain), canonical...))
	return hex.EncodeToString(sum[:])
}

func canonicalJSON(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return []byte("null")
	}
	v, err := decodeJSON(raw)
	if err != nil {
		// Not JSON: digest the bytes as given. Never parse-and-guess.
		return raw
	}
	// encoding/json marshals maps with sorted keys, which is exactly the
	// canonicalization we need.
	out, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return out
}

// decodeJSON decodes with UseNumber so numbers keep their literal form.
// Decoding into float64 would silently rewrite large integers (an id like
// 9007199254740993 comes back as ...992), which would both corrupt an extracted
// artifact id and make two different requests digest identically.
func decodeJSON(raw json.RawMessage) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// segment is one step of a parsed pointer: an object key or an array index.
type segment struct {
	key   string
	index int
	isIdx bool
}

var errBadPointer = errors.New("pointer must start with `$.` and address object keys or array indices")

// parsePointer parses the JSONPath-style subset the manifest supports:
// `$.a.b`, `$.a[0].b`, `$.a`.
func parsePointer(p string) ([]segment, error) {
	if !strings.HasPrefix(p, "$.") {
		return nil, errBadPointer
	}
	rest := p[2:]
	if rest == "" {
		return nil, errBadPointer
	}
	var segs []segment
	for _, part := range strings.Split(rest, ".") {
		if part == "" {
			return nil, errBadPointer
		}
		name := part
		var idxs []string
		if i := strings.IndexByte(part, '['); i >= 0 {
			name = part[:i]
			for rem := part[i:]; rem != ""; {
				if !strings.HasPrefix(rem, "[") {
					return nil, errBadPointer
				}
				end := strings.IndexByte(rem, ']')
				if end < 0 {
					return nil, errBadPointer
				}
				idxs = append(idxs, rem[1:end])
				rem = rem[end+1:]
			}
		}
		if name == "" {
			return nil, errBadPointer
		}
		if strings.ContainsAny(name, "[]$*") {
			return nil, errBadPointer
		}
		segs = append(segs, segment{key: name})
		for _, raw := range idxs {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 0 {
				return nil, fmt.Errorf("array index %q must be a non-negative integer", raw)
			}
			segs = append(segs, segment{index: n, isIdx: true})
		}
	}
	return segs, nil
}

// Extract resolves an extractor against a JSON document, returning the artifact
// id and whether it was found. It is deliberately total: any failure (malformed
// document, missing field, non-scalar or oversized value) returns false and the
// caller falls back to the args digest. Audit derivation never fails a call.
func Extract(e Extractor, doc json.RawMessage) (string, bool) {
	segs, err := parsePointer(e.Pointer)
	if err != nil || len(doc) == 0 {
		return "", false
	}
	v, err := decodeJSON(doc)
	if err != nil {
		return "", false
	}
	for _, s := range segs {
		if s.isIdx {
			arr, ok := v.([]any)
			if !ok || s.index >= len(arr) {
				return "", false
			}
			v = arr[s.index]
			continue
		}
		obj, ok := v.(map[string]any)
		if !ok {
			return "", false
		}
		v, ok = obj[s.key]
		if !ok {
			return "", false
		}
	}
	return scalarString(v)
}

func scalarString(v any) (string, bool) {
	var out string
	switch t := v.(type) {
	case string:
		out = t
	case bool:
		out = strconv.FormatBool(t)
	case json.Number:
		// The literal as it appeared in the document — a 64-bit id survives.
		out = t.String()
	default:
		// Objects, arrays and null are not identities.
		return "", false
	}
	if out == "" || len(out) > MaxArtifactIDLen {
		return "", false
	}
	return out, true
}
