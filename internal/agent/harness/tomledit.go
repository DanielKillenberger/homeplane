package harness

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Span-scoped TOML editing.
//
// A TOML round-trip through a decoder and an encoder is not an option here:
// every comment, every blank line, every key order and every choice of inline
// vs. sub-table in the user's config would be rewritten. R5 asks for the
// opposite — touch the managed tables, leave the file otherwise ALONE — so this
// file locates the byte span of each top-level table and edits the source text,
// which leaves every byte outside the managed spans literally unchanged.
//
// Locating a span needs less than a parser but more than a regexp: a line whose
// first non-blank character is '[' is a table header UNLESS it is inside a
// multi-line string, and '#' starts a comment UNLESS it is inside a string. So
// the scanner below tracks exactly that much lexical state and nothing else.
// Anything it cannot read confidently is an error, never a guess — and the
// result is checked afterwards by re-parsing with a real TOML decoder
// (preserve.go), so a scanner bug fails the write rather than corrupting a file.

// tomlSpan is one table's byte range: from the first byte of its header line to
// the first byte of the next table's header (or end of file).
type tomlSpan struct {
	key           []string
	arrayOfTables bool
	start         int
	end           int
}

// header renders the span's key path back into dotted form for messages.
func (s tomlSpan) header() string { return strings.Join(s.key, ".") }

// scanTOMLTables returns the spans of every table header in src, in file order.
// Content before the first header (the implicit root table) is not a span:
// nothing this package manages lives there, and leaving it out means the root
// table is structurally untouchable.
func scanTOMLTables(src []byte) ([]tomlSpan, error) {
	var spans []tomlSpan
	state := lineState{}

	line := 0
	for pos := 0; pos < len(src); {
		line++
		end := bytes.IndexByte(src[pos:], '\n')
		var lineEnd, next int
		if end < 0 {
			lineEnd, next = len(src), len(src)
		} else {
			lineEnd, next = pos+end, pos+end+1
		}
		text := src[pos:lineEnd]

		// A '[' at the start of a line is a table header only at the TOP level.
		// Inside a multi-line string it is text, and inside an unclosed array or
		// inline table it is a nested value:
		//
		//	matrix = [
		//	  [1, 2],
		//	  [3, 4],
		//	]
		//
		// Reading `[1, 2],` as a header would refuse a perfectly valid config —
		// and refuse it AFTER the grant had been superseded, leaving the harness
		// holding a dead token. Depth is what tells the two apart.
		if !state.inMulti && state.depth == 0 {
			trimmed := bytes.TrimLeft(text, " \t")
			if len(trimmed) > 0 && trimmed[0] == '[' {
				key, aot, err := parseTableHeader(trimmed)
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", line, err)
				}
				if n := len(spans); n > 0 {
					spans[n-1].end = trimAttached(src, spans[n-1].start, pos)
				}
				spans = append(spans, tomlSpan{key: key, arrayOfTables: aot, start: pos, end: len(src)})
			}
		}

		state = scanLine(text, state)
		if state.depth < 0 {
			return nil, fmt.Errorf("line %d: unbalanced ']' or '}'", line)
		}
		pos = next
	}
	if state.inMulti {
		return nil, fmt.Errorf("unterminated multi-line string (%s)", state.multiDelim)
	}
	if state.depth != 0 {
		return nil, fmt.Errorf("unterminated array or inline table (depth %d at end of file)", state.depth)
	}
	if n := len(spans); n > 0 {
		spans[n-1].end = trimAttached(src, spans[n-1].start, len(src))
	}
	return spans, nil
}

// trimAttached pulls a span's end back over the run of blank and comment-only
// lines that immediately precedes it.
//
// Those lines look like they belong to the table above them and in fact belong
// to whatever comes next — a comment written ABOVE a table header is that
// table's comment, and a blank line is a separator, not content. Without this,
// removing a managed table would take the user's comment on the FOLLOWING table
// with it: the exact class of loss the preservation contract exists to prevent.
// Erring toward leaving a stray line behind is deliberate; the other direction
// deletes something a person wrote.
//
// A line inside a multi-line string can never be mistaken for one of these: a
// multi-line string is closed by a line containing its delimiter, which is
// neither blank nor comment-only, so the backwards walk always stops there.
func trimAttached(src []byte, start, end int) int {
	for end > start {
		body := src[:end]
		if len(body) > 0 && body[len(body)-1] == '\n' {
			body = body[:len(body)-1]
		}
		lineStart := bytes.LastIndexByte(body, '\n') + 1
		if lineStart <= start {
			break
		}
		trimmed := bytes.TrimSpace(src[lineStart:end])
		if len(trimmed) != 0 && trimmed[0] != '#' {
			break
		}
		end = lineStart
	}
	return end
}

// lineState is the lexical state carried from one line to the next: whether a
// multi-line string is open, and how deep the open arrays and inline tables are
// nested. Nothing else about TOML has to be understood to locate a table header.
type lineState struct {
	inMulti    bool
	multiDelim string
	depth      int
}

// scanLine advances the state across one line and reports the state at its end.
// A comment ends the line's significance; a multi-line string and an unclosed
// bracket both carry state into the next line.
func scanLine(line []byte, s lineState) lineState {
	for j := 0; j < len(line); {
		if s.inMulti {
			if bytes.HasPrefix(line[j:], []byte(s.multiDelim)) {
				s.inMulti, s.multiDelim = false, ""
				j += 3
				continue
			}
			// Only a BASIC multi-line string honours backslash escapes; in a
			// literal ''' string a backslash is just a backslash.
			if s.multiDelim == `"""` && line[j] == '\\' {
				j += 2
				continue
			}
			j++
			continue
		}
		switch {
		case line[j] == '#':
			return s // a comment runs to end of line; brackets in it are text
		case bytes.HasPrefix(line[j:], []byte(`"""`)):
			s.inMulti, s.multiDelim = true, `"""`
			j += 3
		case bytes.HasPrefix(line[j:], []byte(`'''`)):
			s.inMulti, s.multiDelim = true, `'''`
			j += 3
		case line[j] == '"':
			j++
			for j < len(line) {
				if line[j] == '\\' {
					j += 2
					continue
				}
				if line[j] == '"' {
					j++
					break
				}
				j++
			}
		case line[j] == '\'':
			j++
			for j < len(line) && line[j] != '\'' {
				j++
			}
			j++
		case line[j] == '[' || line[j] == '{':
			s.depth++
			j++
		case line[j] == ']' || line[j] == '}':
			s.depth--
			j++
		default:
			j++
		}
	}
	return s
}

// parseTableHeader reads `[a.b.c]` or `[[a.b]]`, with quoted segments, and
// refuses anything it cannot read exactly.
func parseTableHeader(line []byte) ([]string, bool, error) {
	i := 1 // past the opening '['
	arrayOfTables := false
	if i < len(line) && line[i] == '[' {
		arrayOfTables = true
		i++
	}

	var key []string
	expectSegment := true
	for {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= len(line) {
			return nil, false, fmt.Errorf("unterminated table header %q", string(line))
		}
		if line[i] == ']' {
			if expectSegment {
				return nil, false, fmt.Errorf("empty table header %q", string(line))
			}
			break
		}
		if !expectSegment {
			if line[i] != '.' {
				return nil, false, fmt.Errorf("unexpected %q in table header %q", string(line[i]), string(line))
			}
			i++
			expectSegment = true
			continue
		}

		seg, n, err := parseKeySegment(line[i:])
		if err != nil {
			return nil, false, fmt.Errorf("table header %q: %w", string(line), err)
		}
		key = append(key, seg)
		i += n
		expectSegment = false
	}

	// Closing bracket(s).
	i++
	if arrayOfTables {
		if i >= len(line) || line[i] != ']' {
			return nil, false, fmt.Errorf("unterminated array-of-tables header %q", string(line))
		}
		i++
	}
	// Only whitespace and a comment may follow.
	rest := bytes.TrimLeft(line[i:], " \t")
	if len(rest) > 0 && rest[0] != '#' {
		return nil, false, fmt.Errorf("trailing content after table header %q", string(line))
	}
	return key, arrayOfTables, nil
}

// parseKeySegment reads one bare, basic-quoted or literal-quoted key segment
// and returns it along with the number of bytes consumed.
func parseKeySegment(b []byte) (string, int, error) {
	if len(b) == 0 {
		return "", 0, fmt.Errorf("empty key segment")
	}
	switch b[0] {
	case '"':
		for i := 1; i < len(b); i++ {
			if b[i] == '\\' {
				i++
				continue
			}
			if b[i] == '"' {
				seg, err := strconv.Unquote(string(b[:i+1]))
				if err != nil {
					return "", 0, fmt.Errorf("unreadable quoted key: %v", err)
				}
				return seg, i + 1, nil
			}
		}
		return "", 0, fmt.Errorf("unterminated quoted key")
	case '\'':
		if i := bytes.IndexByte(b[1:], '\''); i >= 0 {
			return string(b[1 : 1+i]), i + 2, nil
		}
		return "", 0, fmt.Errorf("unterminated literal key")
	default:
		i := 0
		for i < len(b) && isBareKeyByte(b[i]) {
			i++
		}
		if i == 0 {
			return "", 0, fmt.Errorf("unreadable key segment at %q", string(b))
		}
		return string(b[:i]), i, nil
	}
}

func isBareKeyByte(c byte) bool {
	return c == '-' || c == '_' ||
		(c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// ── Editing ──────────────────────────────────────────────────────────────────

// removeTOMLTables returns src with every span the predicate selects cut out,
// and the headers of the tables that were removed.
func removeTOMLTables(src []byte, spans []tomlSpan, match func(key []string) bool) ([]byte, []string) {
	var out bytes.Buffer
	var removed []string
	prev, cut := 0, -1
	for _, s := range spans {
		if !match(s.key) {
			continue
		}
		start := s.start
		// Coalesce runs of managed tables. trimAttached leaves the blank line
		// that separated two of them belonging to neither, and writing it out
		// would strand a separator with nothing left to separate — harmless
		// once, but it would accrue across re-runs and make an idempotent
		// command produce a diff every time.
		if cut == prev && prev >= 0 && len(bytes.TrimSpace(src[prev:start])) == 0 {
			start = prev
		}
		out.Write(src[prev:start])
		removed = append(removed, s.header())
		prev, cut = s.end, s.end
	}
	out.Write(src[prev:])
	return out.Bytes(), removed
}

// appendTOMLBlock joins a rendered block onto a document, keeping exactly one
// blank line between it and whatever came before and never leaving the file
// without its trailing newline.
func appendTOMLBlock(src []byte, block string) []byte {
	body := bytes.TrimRight(src, " \t\r\n")
	var out bytes.Buffer
	if len(body) > 0 {
		out.Write(body)
		out.WriteString("\n\n")
	}
	out.WriteString(strings.TrimRight(block, "\n"))
	out.WriteString("\n")
	return out.Bytes()
}

// ── Single-key editing ───────────────────────────────────────────────────────

// setTOMLKeyLiteral sets one key inside one table to a bare literal, touching
// nothing else in the document.
//
// It exists for grok's `[compat.claude] mcps = false` and `[compat.cursor]
// mcps = false` (D4/D4b): a SEMANTIC edit of exactly one cell, where the rest of
// the table — `skills`, `rules`, `agents`, `hooks`, `sessions` — and every
// comment in the file must survive. That is the same reason the managed entries
// are spliced by span rather than round-tripped, applied at key granularity.
//
// Three shapes are handled, in order of preference:
//
//   - the table exists and already assigns the key: only the VALUE bytes are
//     replaced, so a trailing comment on that line survives;
//   - the table exists and does not assign the key: the assignment is inserted
//     directly under the header, where a reader looking for the table's own
//     settings will find it;
//   - the table does not exist: it is appended as a new block.
//
// Anything else — the key expressed as a dotted key in a parent table, or the
// table written as an inline table — is NOT rewritten here. It is caught by the
// caller's post-edit assertion, which re-parses the result and refuses to write
// when the key did not actually take the value. Failing loudly beats editing a
// shape this code cannot read.
// appended reports whether the whole table had to be created, which the caller
// uses to tell "the key was not there" from "the key is there in a shape this
// editor cannot reach".
func setTOMLKeyLiteral(src []byte, table []string, key, literal string) (out []byte, appended bool, err error) {
	spans, err := scanTOMLTables(src)
	if err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrMalformedConfig, err)
	}
	for _, s := range spans {
		if s.arrayOfTables || !sameKeyPath(s.key, table) {
			continue
		}
		body := src[s.start:s.end]
		start, end, found := findKeyValueSpan(body, key)
		var edited []byte
		if found {
			edited = concatBytes(body[:start], []byte(literal), body[end:])
		} else {
			insert := len(body)
			if nl := bytes.IndexByte(body, '\n'); nl >= 0 {
				insert = nl + 1
			}
			edited = concatBytes(body[:insert], []byte(key+" = "+literal+"\n"), body[insert:])
		}
		return concatBytes(src[:s.start], edited, src[s.end:]), false, nil
	}

	block := fmt.Sprintf("[%s]\n%s = %s\n", strings.Join(table, "."), key, literal)
	return appendTOMLBlock(src, block), true, nil
}

func sameKeyPath(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func concatBytes(parts ...[]byte) []byte {
	var out bytes.Buffer
	for _, p := range parts {
		out.Write(p)
	}
	return out.Bytes()
}

// findKeyValueSpan locates the byte range of the VALUE assigned to a bare key
// at the top level of a table body, excluding any trailing comment.
//
// Header line, comment lines, multi-line strings and nested arrays are all
// skipped, using the same lexical state the table scanner carries — so a `mcps`
// appearing inside a string or inside another table's array is never mistaken
// for the assignment.
func findKeyValueSpan(body []byte, key string) (start, end int, found bool) {
	state := lineState{}
	first := true
	for pos := 0; pos < len(body); {
		lineEnd := len(body)
		next := len(body)
		if i := bytes.IndexByte(body[pos:], '\n'); i >= 0 {
			lineEnd, next = pos+i, pos+i+1
		}
		text := body[pos:lineEnd]

		if !first && !state.inMulti && state.depth == 0 {
			if s, e, ok := keyValueSpanInLine(text, key); ok {
				return pos + s, pos + e, true
			}
		}
		first = false
		state = scanLine(text, state)
		pos = next
	}
	return 0, 0, false
}

// keyValueSpanInLine reads `<key> = <value> [# comment]` and returns the span of
// <value> within the line.
func keyValueSpanInLine(line []byte, key string) (start, end int, ok bool) {
	i := 0
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	if !bytes.HasPrefix(line[i:], []byte(key)) {
		return 0, 0, false
	}
	i += len(key)
	// A bare key ends here: `mcpsx = true` must not match `mcps`.
	if i < len(line) && isBareKeyByte(line[i]) {
		return 0, 0, false
	}
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	if i >= len(line) || line[i] != '=' {
		return 0, 0, false
	}
	i++
	for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
		i++
	}
	start = i

	// The value runs to the end of the line or to a comment that is not inside a
	// string. Reusing scanLine's state machine per byte would be overkill; the
	// values this function edits are bare literals, and a value that is not one
	// is rejected by the caller's re-parse assertion rather than mangled here.
	end = len(line)
	inBasic, inLiteral := false, false
	for j := start; j < len(line); j++ {
		switch {
		case inBasic:
			if line[j] == '\\' {
				j++
			} else if line[j] == '"' {
				inBasic = false
			}
		case inLiteral:
			if line[j] == '\'' {
				inLiteral = false
			}
		case line[j] == '"':
			inBasic = true
		case line[j] == '\'':
			inLiteral = true
		case line[j] == '#':
			end = j
			j = len(line)
		}
	}
	for end > start && (line[end-1] == ' ' || line[end-1] == '\t' || line[end-1] == '\r') {
		end--
	}
	if end == start {
		return 0, 0, false
	}
	return start, end, true
}

// ── Rendering ────────────────────────────────────────────────────────────────

// tomlEntryStyle is the per-harness spelling of one managed entry. Both
// harnesses that use TOML put their MCP servers under `[mcp_servers.<name>]`,
// and then disagree about two details — which is exactly the kind of difference
// that must be DATA rather than a forked renderer, or the two copies drift.
type tomlEntryStyle struct {
	// headersTable is the sub-table HTTP headers live in: `http_headers` for
	// Codex, `headers` for grok (fn3-grok-surfaces.md §1, captured verbatim).
	headersTable string
	// writeEnabled emits `enabled = true`. grok's own `mcp add` writes it
	// explicitly and an entry lands enabled, so Homeplane renders what grok
	// renders rather than relying on grok's default staying true.
	writeEnabled bool
}

var (
	codexEntryStyle = tomlEntryStyle{headersTable: "http_headers"}
	grokEntryStyle  = tomlEntryStyle{headersTable: "headers", writeEnabled: true}
)

// renderTOMLEntry writes one managed entry as `[mcp_servers.<name>]` plus the
// sub-tables it needs. Sub-tables rather than inline tables: that is the shape
// both harnesses' own tooling writes, so a config Homeplane touched still looks
// like a config a human wrote.
func renderTOMLEntry(prefix []string, e Entry, style tomlEntryStyle) (string, error) {
	if err := e.Validate(); err != nil {
		return "", err
	}
	path := append(append([]string{}, prefix...), e.Name)
	var b strings.Builder

	fmt.Fprintf(&b, "[%s]\n", strings.Join(path, "."))
	switch e.Transport {
	case TransportHTTP:
		fmt.Fprintf(&b, "url = %s\n", quoteTOML(e.URL))
	case TransportStdio:
		fmt.Fprintf(&b, "command = %s\n", quoteTOML(e.Command))
		if len(e.Args) > 0 {
			quoted := make([]string, len(e.Args))
			for i, a := range e.Args {
				quoted[i] = quoteTOML(a)
			}
			fmt.Fprintf(&b, "args = [%s]\n", strings.Join(quoted, ", "))
		}
	}
	if style.writeEnabled {
		b.WriteString("enabled = true\n")
	}

	if len(e.Headers) > 0 {
		b.WriteString("\n")
		fmt.Fprintf(&b, "[%s.%s]\n", strings.Join(path, "."), style.headersTable)
		writeTOMLPairs(&b, e.Headers)
	}
	if len(e.Env) > 0 {
		b.WriteString("\n")
		fmt.Fprintf(&b, "[%s.env]\n", strings.Join(path, "."))
		writeTOMLPairs(&b, e.Env)
	}
	return b.String(), nil
}

// writeTOMLPairs emits key/value lines in sorted order. Sorted, not
// map-ordered: identical inputs must produce identical bytes, or the writer
// could not report honestly whether a re-run changed anything.
func writeTOMLPairs(b *strings.Builder, pairs map[string]string) {
	for _, k := range sortedKeys(pairs) {
		key := k
		if !isBareKey(k) {
			key = quoteTOML(k)
		}
		fmt.Fprintf(b, "%s = %s\n", key, quoteTOML(pairs[k]))
	}
}

func isBareKey(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isBareKeyByte(s[i]) {
			return false
		}
	}
	return true
}

// quoteTOML renders a TOML basic string. strconv.Quote is Go syntax, not TOML
// syntax — the two agree on the escapes TOML defines and disagree on the ones
// it does not, so the escaping is done here explicitly rather than borrowed.
func quoteTOML(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		default:
			if r == utf8.RuneError || (unicode.IsControl(r) && r < 0x80) {
				fmt.Fprintf(&b, `\u%04X`, r)
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}
