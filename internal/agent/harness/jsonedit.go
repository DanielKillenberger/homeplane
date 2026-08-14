package harness

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// Order-preserving JSON editing.
//
// Go's map iteration order is random and `encoding/json` sorts object keys, so
// decoding a config into a map and re-encoding it reorders the whole file. That
// is not a semantic change, but it turns a two-line edit into a whole-file diff
// in a config the user may well have in version control. So the object is kept
// as (ordered keys, raw values): every value the edit does not touch is written
// back BYTE-for-byte, in its original position, and new keys are appended.

// jsonObject is a JSON object with its key order remembered.
type jsonObject struct {
	keys   []string
	values map[string]json.RawMessage
}

func newJSONObject() *jsonObject {
	return &jsonObject{values: map[string]json.RawMessage{}}
}

// parseJSONObject decodes one JSON object, preserving key order and each
// value's exact bytes. A document that is not an object is an error: this
// package only ever edits objects, and treating anything else as empty would
// silently discard a file.
func parseJSONObject(raw []byte) (*jsonObject, error) {
	obj := newJSONObject()
	if len(bytes.TrimSpace(raw)) == 0 {
		return obj, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("expected a JSON object, found %v", tok)
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := kt.(string)
		if !ok {
			return nil, fmt.Errorf("expected an object key, found %v", kt)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		if _, seen := obj.values[key]; !seen {
			obj.keys = append(obj.keys, key)
		}
		obj.values[key] = value
	}
	if _, err := dec.Token(); err != nil { // closing '}'
		return nil, err
	}
	// Trailing content after the object means the file is not the single JSON
	// document it claims to be.
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing content after the top-level JSON object")
	}
	return obj, nil
}

func (o *jsonObject) get(key string) (json.RawMessage, bool) {
	v, ok := o.values[key]
	return v, ok
}

func (o *jsonObject) set(key string, value json.RawMessage) {
	if _, seen := o.values[key]; !seen {
		o.keys = append(o.keys, key)
	}
	o.values[key] = value
}

func (o *jsonObject) delete(key string) bool {
	if _, seen := o.values[key]; !seen {
		return false
	}
	delete(o.values, key)
	for i, k := range o.keys {
		if k == key {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
	return true
}

func (o *jsonObject) len() int { return len(o.keys) }

// marshal writes the object with its keys in their remembered order.
func (o *jsonObject) marshal() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		encoded, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		b.Write(encoded)
		b.WriteByte(':')
		b.Write(o.values[k])
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

// marshalLike renders the object with the layout of the document it came from:
// a file that was pretty-printed stays pretty-printed, a compact one stays
// compact. Formatting is not semantics, but an unrequested reformat is still an
// unrequested change to someone else's file.
func (o *jsonObject) marshalLike(original []byte) ([]byte, error) {
	compact, err := o.marshal()
	if err != nil {
		return nil, err
	}
	indent := detectJSONIndent(original)
	if indent == "" {
		return append(compact, '\n'), nil
	}
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, compact, "", indent); err != nil {
		return nil, err
	}
	return append(pretty.Bytes(), '\n'), nil
}

// detectJSONIndent reports the indent unit of an existing document, or "" when
// it is compact (or new — a file Homeplane creates is pretty-printed, because
// a human is going to read it).
func detectJSONIndent(original []byte) string {
	trimmed := bytes.TrimSpace(original)
	if len(trimmed) == 0 {
		return "  "
	}
	nl := bytes.IndexByte(trimmed, '\n')
	if nl < 0 {
		return ""
	}
	rest := trimmed[nl+1:]
	unit := 0
	for unit < len(rest) && (rest[unit] == ' ' || rest[unit] == '\t') {
		unit++
	}
	if unit == 0 {
		return ""
	}
	return string(rest[:unit])
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// jsonMarshalIndent / jsonUnmarshal exist so the record helpers read the same
// as the rest of the package without importing encoding/json in two files.
func jsonMarshalIndent(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }

func jsonUnmarshal(raw []byte, v any) error { return json.Unmarshal(raw, v) }
