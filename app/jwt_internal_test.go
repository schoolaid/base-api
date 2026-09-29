package app

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	beego "github.com/beego/beego/v2/server/web"
	jwt "github.com/golang-jwt/jwt/v5"
)

// The method allow-list is defence in depth: with a []byte key, v5 refuses
// "none" and RS256 anyway, because those methods reject the key type. So a test
// on ParseJWT's answer cannot tell whether the list is there. This one checks
// WHICH check refused the token: the list's own error, before any key is used.
func TestMethodAllowListRefusesBeforeTheKeyIsUsed(t *testing.T) {
	prev := Secret_key
	Secret_key = []byte("base-api-test-secret")
	t.Cleanup(func() { Secret_key = prev })

	b64 := base64.RawURLEncoding.EncodeToString
	payload := b64([]byte(`{"expire_at":"4102444800","user_id":1969}`))

	for _, alg := range []string{"none", "RS256", "ES256", "PS256"} {
		unsigned := b64([]byte(`{"alg":"`+alg+`","typ":"JWT"}`)) + "." + payload
		mac := hmac.New(sha256.New, Secret_key)
		mac.Write([]byte(unsigned))

		_, _, err := parseToken(unsigned + "." + b64(mac.Sum(nil)))
		if err == nil {
			t.Fatalf("%s: accepted", alg)
		}
		if want := "signing method " + alg + " is invalid"; !strings.Contains(err.Error(), want) {
			t.Errorf("%s: refused by %q, not by the allow-list (%q)", alg, err, want)
		}
	}
}

// v3's time rules at their exact boundaries, on whole seconds. v5's own
// validator would refuse exp == now and would not check iat at all.
func TestV3TimeRulesAtTheBoundary(t *testing.T) {
	const now = 4102444800
	prev := timeNow
	timeNow = func() time.Time { return time.Unix(now, 999_000_000) } // late in the second
	t.Cleanup(func() { timeNow = prev })

	for _, tc := range []struct {
		claims v3Claims
		want   error
	}{
		{v3Claims{"exp": float64(now)}, nil},
		{v3Claims{"exp": float64(now - 1)}, jwt.ErrTokenExpired},
		{v3Claims{"exp": float64(now) + 0.9}, nil},
		{v3Claims{"iat": float64(now)}, nil},
		{v3Claims{"iat": float64(now + 1)}, jwt.ErrTokenUsedBeforeIssued},
		{v3Claims{"nbf": float64(now)}, nil},
		{v3Claims{"nbf": float64(now + 1)}, jwt.ErrTokenNotValidYet},
		{v3Claims{"exp": float64(0), "iat": float64(0), "nbf": float64(0)}, nil},
		{v3Claims{"exp": "1", "iat": "9999999999", "nbf": nil}, nil},
	} {
		if got := tc.claims.Validate(); got != tc.want {
			t.Errorf("%v: got %v, want %v", tc.claims, got, tc.want)
		}
	}
}

// The allow-list still refuses first when a previous key is configured: the
// retry under the previous key must not turn a method refusal into a key-type
// one (or into an acceptance).
func TestMethodAllowListHoldsUnderThePreviousKey(t *testing.T) {
	prevSecret, prevConf := Secret_key, beego.AppConfig
	t.Cleanup(func() { Secret_key, beego.AppConfig = prevSecret, prevConf })
	Secret_key = []byte("base-api-rotated-secret")

	path := filepath.Join(t.TempDir(), "app.conf")
	if err := os.WriteFile(path, []byte("previousSecretKey = base-api-test-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := beego.LoadAppConfig("ini", path); err != nil {
		t.Fatal(err)
	}

	b64 := base64.RawURLEncoding.EncodeToString
	payload := b64([]byte(`{"expire_at":"4102444800","user_id":1969}`))
	for _, alg := range []string{"none", "RS256", "ES256", "PS256"} {
		unsigned := b64([]byte(`{"alg":"`+alg+`","typ":"JWT"}`)) + "." + payload
		mac := hmac.New(sha256.New, []byte("base-api-test-secret"))
		mac.Write([]byte(unsigned))

		_, _, err := parseToken(unsigned + "." + b64(mac.Sum(nil)))
		if err == nil {
			t.Fatalf("%s: accepted under the previous key", alg)
		}
		if want := "signing method " + alg + " is invalid"; !strings.Contains(err.Error(), want) {
			t.Errorf("%s: refused by %q, not by the allow-list", alg, err)
		}
	}
}
