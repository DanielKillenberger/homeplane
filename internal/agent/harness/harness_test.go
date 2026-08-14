package harness

import (
	"fmt"
	"strings"
	"testing"
)

// An Entry carries a grant token in its Headers. Go's %v/%+v verbs would print
// a struct field by field, so the one thing standing between an error message
// and a leaked token is Entry's own String method. This asserts it, because the
// leak it prevents would be invisible until it appeared in a log.
func TestPrintingAnEntryNeverRevealsItsToken(t *testing.T) {
	e := Entry{
		Name: ConnectorServerName, Transport: TransportHTTP,
		URL:     "https://server.ts.net/mcp",
		Headers: map[string]string{"Authorization": "Bearer s3cret-grant-token"},
	}
	for _, printed := range []string{
		fmt.Sprint(e), fmt.Sprintf("%v", e), fmt.Sprintf("%+v", e), fmt.Sprintf("%s", e),
		fmt.Sprintf("%v", []Entry{e}), fmt.Sprintf("%v", e.Redacted()),
	} {
		if strings.Contains(printed, "s3cret-grant-token") {
			t.Errorf("a grant token reached a formatted string: %s", printed)
		}
	}
	// Redaction must still say enough to debug with.
	if !strings.Contains(fmt.Sprint(e), ConnectorServerName) {
		t.Error("redaction removed the entry's identity along with its secret")
	}
}
