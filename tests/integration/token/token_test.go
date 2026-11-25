//go:build integration

// The token route during PR 5's transition (Notion 999): the plain text still decides, exactly as
// MySQL compares it (utf8mb3_general_ci ignores case, trailing spaces and accents), and two log
// lines tell the contract step when it is safe to let the hash decide alone:
//   - "collation-only match": MySQL accepted a password an exact compare would refuse;
//   - "no password hash": a login succeeded for a credential without a password_hash.
//
// A blanked plain text logs nothing in. The model no longer maps the password column, so dropping
// it can't break GetExternalUser.
//
//	BASEAPI_TEST_MYSQL_DSN='user:pass@tcp(127.0.0.1:3306)/baseapi_token_test' go test -tags integration ./tests/integration/token/
package token

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BenMz/base_api/models"
	_ "github.com/BenMz/base_api/routers"

	"github.com/beego/beego/v2/client/orm"
	"github.com/beego/beego/v2/core/logs"
	beego "github.com/beego/beego/v2/server/web"
)

var logFile string

const ddl = `CREATE TABLE external_user (
	id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
	name VARCHAR(30) NULL,
	username VARCHAR(50) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NOT NULL,
	password VARCHAR(255) CHARACTER SET utf8mb3 COLLATE utf8mb3_general_ci NOT NULL,
	token VARCHAR(100) NOT NULL,
	password_hash VARCHAR(255) NULL,
	UNIQUE KEY external_user_username_unique (username)
)`

func TestMain(m *testing.M) {
	if !strings.HasSuffix(os.Getenv("BASEAPI_TEST_MYSQL_DSN"), "_test") {
		fmt.Println("BASEAPI_TEST_MYSQL_DSN must name a database ending in _test")
		os.Exit(1)
	}
	dir, _ := os.MkdirTemp("", "baseapi-token")
	logFile = filepath.Join(dir, "token.log")
	if err := logs.SetLogger(logs.AdapterFile, fmt.Sprintf(`{"filename":%q,"level":7}`, logFile)); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	for _, q := range []string{"DROP TABLE IF EXISTS external_user", ddl} {
		if _, err := orm.NewOrm().Raw(q).Exec(); err != nil {
			fmt.Println(q, err)
			os.Exit(1)
		}
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

var seq int

// credential inserts a credential with this stored plain text (and hash, if any), and returns its
// id and username.
func credential(t *testing.T, plaintext string, hash *string) (int64, string) {
	t.Helper()
	seq++
	username := fmt.Sprintf("integrator-%d", seq)
	var h interface{}
	if hash != nil {
		h = *hash
	}
	res, err := orm.NewOrm().Raw("INSERT INTO external_user (name, username, password, token, password_hash) VALUES (?, ?, ?, ?, ?)",
		"it", username, plaintext, fmt.Sprintf("db-token-%d", seq), h).Exec()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	return id, username
}

type envelope struct {
	Success int    `json:"success"`
	Message string `json:"message"`
	Data    *struct {
		Token string `json:"token"`
	} `json:"data"`
}

func login(t *testing.T, username, password string) envelope {
	t.Helper()
	form := url.Values{"username": {username}, "password": {password}}
	r := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	beego.BeeApp.Handlers.ServeHTTP(w, r)
	var e envelope
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("POST /token: %d %q", w.Code, w.Body.String())
	}
	return e
}

func logged(t *testing.T, line string) bool {
	t.Helper()
	logs.GetBeeLogger().Flush()
	b, _ := os.ReadFile(logFile)
	return strings.Contains(string(b), line)
}

func hashOf(s string) *string { return &s }

func TestAnExactPasswordLogsIn(t *testing.T) {
	id, user := credential(t, "Exact-pw-1", hashOf("$2a$10$placeholderplaceholderplaceholderplaceholderplacehol"))
	e := login(t, user, "Exact-pw-1")
	if e.Success != 1 || e.Data == nil || e.Data.Token == "" {
		t.Fatalf("an exact password: %+v", e)
	}
	if logged(t, fmt.Sprintf("collation-only match: external_user=%d", id)) {
		t.Error("an exact match was logged as collation-only")
	}
}

// (b), the TL's call: accepted as today, and logged, until the contract step.
func TestACollationOnlyMatchIsAcceptedAndLogged(t *testing.T) {
	for _, sent := range []string{"exact-pw-2", "EXACT-PW-2", "Exact-pw-2  ", "Exáct-pw-2"} {
		id, user := credential(t, "Exact-pw-2", nil)
		if e := login(t, user, sent); e.Success != 1 {
			t.Errorf("%q against %q: refused (%q), want today's acceptance", sent, "Exact-pw-2", e.Message)
			continue
		}
		if !logged(t, fmt.Sprintf("collation-only match: external_user=%d", id)) {
			t.Errorf("%q: not logged as a collation-only match", sent)
		}
	}
}

func TestAWrongPasswordOrUsernameIsRefused(t *testing.T) {
	_, user := credential(t, "Right-pw-3", nil)
	for _, c := range [][2]string{{user, "wrong"}, {user, ""}, {"nobody-" + user, "Right-pw-3"}} {
		if e := login(t, c[0], c[1]); e.Success != 0 || e.Message != "Invalid username or password" {
			t.Errorf("%q/%q: %+v, want today's refusal", c[0], c[1], e)
		}
	}
}

// Notion 999, as in external-api: blanking the plain text disables a credential, whatever is sent.
func TestABlankedPlaintextLogsNothingIn(t *testing.T) {
	for _, blank := range []string{"", "   "} {
		_, user := credential(t, blank, nil)
		for _, sent := range []string{"", " ", blank} {
			if e := login(t, user, sent); e.Success != 0 {
				t.Errorf("stored %q, sent %q: logged in", blank, sent)
			}
		}
	}
}

func TestALoginWithoutAHashIsLogged(t *testing.T) {
	without, user := credential(t, "No-hash-pw", nil)
	login(t, user, "No-hash-pw")
	if !logged(t, fmt.Sprintf("no password hash: external_user=%d", without)) {
		t.Error("a login without a password_hash was not logged")
	}
	with, user2 := credential(t, "Hashed-pw", hashOf("$2a$10$placeholderplaceholderplaceholderplaceholderplacehol"))
	login(t, user2, "Hashed-pw")
	if logged(t, fmt.Sprintf("no password hash: external_user=%d", with)) {
		t.Error("a credential with a hash was logged as having none")
	}
}

// A database without schoolaid-admin's password_hash migration: the route works as before.
func TestWithoutThePasswordHashColumn(t *testing.T) {
	_, user := credential(t, "Old-schema-pw", nil)
	run(t, "ALTER TABLE external_user RENAME COLUMN password_hash TO password_hash_away")
	defer run(t, "ALTER TABLE external_user RENAME COLUMN password_hash_away TO password_hash")
	if e := login(t, user, "Old-schema-pw"); e.Success != 1 {
		t.Errorf("without password_hash: %+v", e)
	}
}

// The contract step drops the plain-text column; nothing but the token route may read it.
func TestGetExternalUserDoesNotReadThePassword(t *testing.T) {
	_, _ = credential(t, "Model-pw", nil)
	run(t, "ALTER TABLE external_user RENAME COLUMN password TO password_away")
	defer run(t, "ALTER TABLE external_user RENAME COLUMN password_away TO password")
	if _, err := models.GetExternalUser(fmt.Sprintf("db-token-%d", seq)); err != nil {
		t.Errorf("GetExternalUser without the password column: %v", err)
	}
}

func run(t *testing.T, q string) {
	t.Helper()
	if _, err := orm.NewOrm().Raw(q).Exec(); err != nil {
		t.Fatal(q, err)
	}
}
