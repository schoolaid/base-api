package app_test

import (
	"crypto/sha256"
	"crypto/sha512"
	"strings"
	"testing"
	"time"

	"github.com/BenMz/base_api/app"
)

// A rotation, as the conf would do it: the key every client's token is signed
// with (testSecret, the fixtures' key) moves to previousSecretKey, and a new
// secretKey takes over.
const newSecret = "base-api-rotated-secret"

func rotated(t *testing.T, previousLine string) {
	t.Helper()
	prev := app.Secret_key
	app.Secret_key = []byte(newSecret)
	t.Cleanup(func() { app.Secret_key = prev })
	withConf(t, "prod", previousLine)
}

// The point of the feature: tokens clients hold keep working through a
// rotation, and stop once the old key is removed from the conf — no restart.
func TestPreviousKeyValidatesUntilItIsRemoved(t *testing.T) {
	rotated(t, "previousSecretKey = "+testSecret+"\n")
	check(t, "old token, previous key set", oldValidHS256, accepted1969)
	check(t, "old HS512 token, previous key set", oldValidHS512, accepted1969)
	check(t, "old padded token, previous key set", oldValidHS256+"=", accepted1969)
	check(t, "token signed with the new key", hs256WithKey(t, newSecret), accepted1969)

	// The conf is reloaded without the line: the old key is gone.
	withConf(t, "prod", "")
	check(t, "old token, previous key removed", oldValidHS256, invalid)
	check(t, "token signed with the new key, previous key removed", hs256WithKey(t, newSecret), accepted1969)
}

func TestPreviousKeyInTheRunmodeSection(t *testing.T) {
	rotated(t, "[prod]\npreviousSecretKey = "+testSecret+"\n")
	check(t, "old token", oldValidHS256, accepted1969)
}

// The previous key only replaces the signature check. Everything after it
// holds exactly as under the current key.
func TestPreviousKeyDoesNotRelaxAnyOtherCheck(t *testing.T) {
	rotated(t, "previousSecretKey = "+testSecret+"\n")
	claims := map[string]interface{}{"token": "x", "expire_at": future, "user_id": 1969}

	check(t, "expired under the previous key", oldExpired, expired)
	check(t, "exp in the past under the previous key", hs256(t, map[string]interface{}{
		"token": "x", "expire_at": future, "user_id": 1969, "exp": 1700000000}), invalid)
	check(t, "no expire_at under the previous key", hs256(t, map[string]interface{}{"user_id": 1969}), invalid)
	check(t, "string user_id under the previous key", hs256(t, map[string]interface{}{"expire_at": future, "user_id": "1969"}), invalid)

	for _, key := range []string{testSecret, newSecret} {
		which := map[string]string{testSecret: "previous", newSecret: "current"}[key]
		check(t, "alg none ("+which+" key configured)",
			segment(t, map[string]string{"alg": "none", "typ": "JWT"})+"."+segment(t, claims)+".", invalid)
		check(t, "RS256 header over an HMAC with the "+which+" key",
			signed(t, "RS256", sha256.New, key, claims), invalid)
	}
	check(t, "a third key", signed(t, "HS256", sha256.New, "not-either-secret", claims), invalid)
	check(t, "HS512 with a third key", signed(t, "HS512", sha512.New, "not-either-secret", claims), invalid)

	parts := strings.Split(oldValidHS256, ".")
	tampered := parts[0] + "." + segment(t, map[string]interface{}{"token": "ext-token", "expire_at": future, "user_id": 1}) + "." + parts[2]
	check(t, "previous-key token with its payload changed", tampered, invalid)
}

// ⚠️ HMAC ACCEPTS A ZERO-LENGTH KEY, and any blank one. An empty or blank
// previousSecretKey must switch the feature off, never become a key anyone can
// sign with. beego's ini trims only UNQUOTED values: a quoted value and an
// ${ENV} expansion keep their spaces, so blank must be judged after trimming.
func TestEmptyPreviousKeyIsDisabledNotTheEmptyKey(t *testing.T) {
	t.Setenv("BASEAPI_TEST_BLANK_KEY", " ")
	claims := map[string]interface{}{"token": "x", "expire_at": future, "user_id": 1969}

	for _, tc := range []struct {
		name, line string
		blank      string // the key the conf yields, and a forger would sign with
	}{
		{"absent", "", ""},
		{"empty", "previousSecretKey =\n", ""},
		{"unquoted blank (ini trims it)", "previousSecretKey =    \n", ""},
		{"empty in section", "[prod]\npreviousSecretKey =\n", ""},
		{"quoted blank", "previousSecretKey = \"   \"\n", "   "},
		{"env var that is blank", "previousSecretKey = ${BASEAPI_TEST_BLANK_KEY}\n", " "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rotated(t, tc.line)
			check(t, "token signed with the blank key", signed(t, "HS256", sha256.New, tc.blank, claims), invalid)
			check(t, "token signed with an empty key", signed(t, "HS256", sha256.New, "", claims), invalid)
			check(t, "old token", oldValidHS256, invalid)
		})
	}
}

// New tokens are always signed with secretKey, never the previous key, or a
// rotation would keep minting tokens that die when the old key is dropped.
func TestNewTokensAreSignedWithTheCurrentKey(t *testing.T) {
	rotated(t, "previousSecretKey = "+testSecret+"\n")

	tok, _, err := app.NewAuthToken("ext-token", 1969, time.Unix(4102444800-86400, 0))
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]interface{}{"token": "ext-token", "expire_at": future, "user_id": 1969}
	if want := signed(t, "HS256", sha256.New, newSecret, claims); tok != want {
		t.Fatalf("not signed with secretKey:\n got  %s\n want %s", tok, want)
	}
	if tok == oldValidHS256 {
		t.Fatal("signed with previousSecretKey")
	}

	// And once the previous key is removed, the new token still validates.
	withConf(t, "prod", "")
	check(t, "new token after the previous key is removed", tok, accepted1969)
}

func hs256WithKey(t *testing.T, key string) string {
	return signed(t, "HS256", sha256.New, key,
		map[string]interface{}{"token": "ext-token", "expire_at": future, "user_id": 1969})
}

// Only the SIGNATURE check sees the previous key. A token that verifies under
// the current key and then fails a claim must be refused for THAT reason: a
// second attempt under the previous key would log "signature" instead, and the
// log is the only way to tell a lock-out from a forgery during a rotation.
func TestOnlyASignatureFailureIsRetried(t *testing.T) {
	rotated(t, "previousSecretKey = "+testSecret+"\n")
	buf := captureLogs(t)

	expiredUnderCurrent := signed(t, "HS256", sha256.New, newSecret, map[string]interface{}{
		"token": "x", "expire_at": future, "user_id": 1969, "exp": 1700000000})
	if got := parse(expiredUnderCurrent); got != invalid {
		t.Fatalf("got %+v, want %+v", got, invalid)
	}
	got := buf.text()
	if !strings.Contains(got, "jwt refused (expired)") {
		t.Fatalf("the real reason was replaced by the previous-key retry's; log:\n%s", got)
	}
	if strings.Contains(got, "(signature)") {
		t.Fatalf("a token that failed on exp was retried under the previous key; log:\n%s", got)
	}
}
