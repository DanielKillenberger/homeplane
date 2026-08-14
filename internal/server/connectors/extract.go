package connectors

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
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

// MaxExtractInputLen bounds the text a step pipeline may run over. Tool
// responses are already bounded at the edge; this bounds them again where a
// regexp would otherwise scan an arbitrarily large body on every call.
const MaxExtractInputLen = 256 << 10

// identityRe is the shape a PIPELINE-extracted id may have. A pointer that
// lands directly on a field is the manifest naming an identity slot; a pipeline
// derives its value from free text and a base64 blob, where a sloppy pattern
// could otherwise carry prose — or bytes — into the audit log. So the derived
// value must look like an identifier or it is discarded.
var identityRe = regexp.MustCompile(`^[A-Za-z0-9._:@/+=-]+$`)

// Extract resolves an extractor against a JSON document, returning the artifact
// id and whether it was found. It is deliberately total: any failure (malformed
// document, missing field, non-scalar or oversized value, a step that matched
// nothing) returns false and the caller falls back to the args digest. Audit
// derivation never fails a call.
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
	if len(e.Steps) == 0 {
		return scalarString(v)
	}
	return runSteps(e.Steps, v)
}

// runSteps refines the pointer's value into an id.
//
// The pointer's own value is NOT bounded by MaxArtifactIDLen here: a pipeline
// exists precisely because the identity is embedded in something bigger than
// itself (a sentence, a link). The bound moves to the pipeline's OUTPUT, which
// is what actually reaches the audit row.
func runSteps(steps []ExtractStep, v any) (string, bool) {
	s, ok := v.(string)
	if !ok {
		// A step pipeline reads text. A number or bool is already an identity
		// and needs no refining, so declaring steps over one is a manifest
		// mistake rather than something to guess at.
		return "", false
	}
	if len(s) > MaxExtractInputLen {
		return "", false
	}
	for _, step := range steps {
		if s, ok = step.apply(s); !ok {
			return "", false
		}
	}
	if s == "" || len(s) > MaxArtifactIDLen || !identityRe.MatchString(s) {
		return "", false
	}
	return s, true
}

// apply runs one step. Exactly one of Match/Decode is set (the manifest
// validator enforces it), so the zero step cannot silently pass text through.
func (st ExtractStep) apply(s string) (string, bool) {
	switch {
	case st.Match != "":
		re, err := compilePattern(st.Match)
		if err != nil {
			return "", false
		}
		m := re.FindStringSubmatch(s)
		if len(m) < 2 {
			return "", false
		}
		return m[1], true
	case st.Decode == DecodeBase64:
		out, ok := decodeBase64(s)
		if !ok || !utf8.ValidString(out) {
			return "", false
		}
		return out, true
	default:
		return "", false
	}
}

// decodeBase64 accepts the standard and URL alphabets, padded or not — a
// provider that embeds an id in a link chooses one of the four and never says
// which.
func decodeBase64(s string) (string, bool) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if out, err := enc.DecodeString(s); err == nil {
			return string(out), true
		}
	}
	return "", false
}

// patternCache keeps the manifest's compiled patterns. The key space is the
// manifest's own literals — a fixed, operator-authored set — so it is bounded
// by the file rather than by traffic.
var patternCache sync.Map

func compilePattern(pattern string) (*regexp.Regexp, error) {
	if v, ok := patternCache.Load(pattern); ok {
		if re, ok := v.(*regexp.Regexp); ok {
			return re, nil
		}
		return nil, errBadPattern
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		patternCache.Store(pattern, errBadPattern)
		return nil, errBadPattern
	}
	patternCache.Store(pattern, re)
	return re, nil
}

var errBadPattern = errors.New("match must be a valid RE2 pattern with exactly one capture group")

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
