package app_test

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/beego/beego/v2/core/logs"
)

type captureLogger struct {
	mu   sync.Mutex
	msgs []string
}

var captured = &captureLogger{}

func (l *captureLogger) Init(string) error              { return nil }
func (l *captureLogger) Destroy()                       {}
func (l *captureLogger) Flush()                         {}
func (l *captureLogger) SetFormatter(logs.LogFormatter) {}

// beego hands adapters the unformatted template plus its args; render it the
// way beego does, or the assertions below would only see "jwt refused: %v".
func (l *captureLogger) WriteMsg(lm *logs.LogMsg) error {
	msg := lm.Msg
	if len(lm.Args) > 0 {
		msg = fmt.Sprintf(lm.Msg, lm.Args...)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, msg)
	return nil
}

func (l *captureLogger) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.msgs, "\n")
}

func init() {
	logs.Register("capture", func() logs.Logger { return captured })
}

func captureLogs(t *testing.T) *captureLogger {
	t.Helper()
	captured.mu.Lock()
	captured.msgs = nil
	captured.mu.Unlock()
	logs.Reset()
	if err := logs.SetLogger("capture"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logs.Reset() })
	return captured
}

// A refusal says WHY in the log, so a lock-out at deploy is distinguishable
// from forgeries, and never carries any part of the token itself.
func TestRefusalLogsTheReasonAndNotTheToken(t *testing.T) {
	withSecret(t)
	buf := captureLogs(t)

	forged := signed(t, "HS256", sha256.New, "not-the-secret",
		map[string]interface{}{"token": "ext-token", "expire_at": future, "user_id": 1969})
	if got := parse(forged); got != invalid {
		t.Fatalf("got %+v, want %+v", got, invalid)
	}

	got := buf.text()
	if !strings.Contains(got, "jwt refused (signature): ") {
		t.Fatalf("the refusal reason was not logged; got:\n%s", got)
	}
	for i, part := range strings.Split(forged, ".") {
		if strings.Contains(got, part) {
			t.Fatalf("the log carries segment %d of the token:\n%s", i, got)
		}
	}

	// No header is the ordinary anonymous case, not a refusal worth a line.
	before := got
	parse("")
	if buf.text() != before {
		t.Fatalf("a request with no Authorization header was logged:\n%s", buf.text())
	}
}
