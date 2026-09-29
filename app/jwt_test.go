package app_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BenMz/base_api/app"
	"github.com/beego/beego/v2/server/web/context"
)

// ⚠️ THIS FILE IMPORTS NO JWT LIBRARY, on purpose. It builds and signs every
// token by hand (crypto/hmac), so the same file runs unchanged against the old
// dgrijalva/jwt-go code and the new golang-jwt/jwt/v5 code. That run against
// the old code is the control: it shows which cases changed with the migration.

const testSecret = "base-api-test-secret"

// Minted ONCE with github.com/dgrijalva/jwt-go v3.2.0, in the exact claim shape
// controllers/auth.go produces: HS256, "expire_at" a STRING of unix seconds,
// "user_id" a number, plus the external user's "token". Committed as strings so
// the old library never enters go.mod, not even as a test dependency.
const (
	oldValidHS256  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHBpcmVfYXQiOiI0MTAyNDQ0ODAwIiwidG9rZW4iOiJleHQtdG9rZW4iLCJ1c2VyX2lkIjoxOTY5fQ.Liyl7R1Kk-xgQxTYESyDJqJePezMwHD6VyslCQcbPWo"
	oldExpired     = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHBpcmVfYXQiOiIxNzAwMDAwMDAwIiwidG9rZW4iOiJleHQtdG9rZW4iLCJ1c2VyX2lkIjoxOTY5fQ.yyFPlYMA1aG2s91rBkh5IrvudXPPKU5Mq-hVyIGIoiU"
	oldNoUserHS256 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHBpcmVfYXQiOiI0MTAyNDQ0ODAwIiwidG9rZW4iOiJleHQtdG9rZW4ifQ.KozsiNisSiVPHrzCbExwtUlxSbGIB-4UCt_9Wxyf9_Q"
	oldValidHS512  = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHBpcmVfYXQiOiI0MTAyNDQ0ODAwIiwidG9rZW4iOiJleHQtdG9rZW4iLCJ1c2VyX2lkIjoxOTY5fQ.icIVBIWYRQFwNcNrTXV5Eu08FJpWQ36UPWhHb5c1xYQwyBvXv9bNzWIDxhZziZ2pNgMtipmoNTKWIvxqnPWI-Q"
)

const (
	future = "4102444800" // 2100-01-01
	past   = "1700000000" // 2023-11-14
)

func b64(v []byte) string { return base64.RawURLEncoding.EncodeToString(v) }

func segment(t *testing.T, v interface{}) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b64(raw)
}

// signed builds header.payload and signs it with HMAC. alg is written into the
// header verbatim, so a caller can lie about it (alg confusion).
func signed(t *testing.T, alg string, h func() hash.Hash, secret string, claims map[string]interface{}) string {
	t.Helper()
	unsigned := segment(t, map[string]string{"alg": alg, "typ": "JWT"}) + "." + segment(t, claims)
	mac := hmac.New(h, []byte(secret))
	mac.Write([]byte(unsigned))
	return unsigned + "." + b64(mac.Sum(nil))
}

// signedPadded is signed() as a padding minter would do it: std base64url WITH
// "=", and the HMAC taken over the padded header.payload.
func signedPadded(t *testing.T, secret string, claims map[string]interface{}) string {
	t.Helper()
	enc := func(v interface{}) string {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.URLEncoding.EncodeToString(raw)
	}
	unsigned := enc(map[string]string{"alg": "HS256", "typ": "JWT"}) + "." + enc(claims)
	if !strings.Contains(unsigned, "=") {
		t.Fatal("fixture has no padding, so it cannot test padding")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(unsigned))
	return unsigned + "." + base64.URLEncoding.EncodeToString(mac.Sum(nil))
}

func hs256(t *testing.T, claims map[string]interface{}) string {
	return signed(t, "HS256", sha256.New, testSecret, claims)
}

type outcome struct {
	ok       bool
	userId   int64
	message  string
	panicked string
}

// parse runs app.ParseJWT exactly as ApiController.Prepare does. A panic is
// captured as an outcome rather than crashing the test binary: on the old code
// several of these inputs panic, and that is part of what the control run shows.
func parse(token string) (o outcome) {
	req := httptest.NewRequest("GET", "/api/anything", nil)
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	ctx := context.NewContext()
	ctx.Reset(httptest.NewRecorder(), req)

	defer func() {
		if r := recover(); r != nil {
			o = outcome{panicked: fmt.Sprint(r)}
		}
	}()
	o.ok, o.userId, o.message = app.ParseJWT(ctx)
	return o
}

func withSecret(t *testing.T) {
	t.Helper()
	prev := app.Secret_key
	app.Secret_key = []byte(testSecret)
	t.Cleanup(func() { app.Secret_key = prev })
}

var (
	accepted1969 = outcome{ok: true, userId: 1969, message: "Success"}
	invalid      = outcome{ok: false, userId: 0, message: "Invalid Token"}
	expired      = outcome{ok: false, userId: 0, message: "Token has expired"}
)

func check(t *testing.T, name, token string, want outcome) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		got := parse(token)
		if got.panicked != "" {
			t.Fatalf("ParseJWT PANICKED (%s); want %+v", got.panicked, want)
		}
		if got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})
}

// (a) Tokens minted by the OLD library still work, with the real claim shapes.
// These are the tokens clients hold at the moment of the deploy.
func TestTokensMintedByTheOldLibraryStillValidate(t *testing.T) {
	withSecret(t)

	check(t, "HS256, expire_at in the future", oldValidHS256, accepted1969)
	check(t, "HS256, expire_at in the past", oldExpired, expired)
	// No user_id was always accepted as user 0; the migration must not change it.
	check(t, "HS256, no user_id", oldNoUserHS256, outcome{ok: true, userId: 0, message: "Success"})
	// The key is a []byte, so the old code accepted every HMAC algorithm, not
	// only HS256. The minter of the apps' login tokens is outside this repo, so
	// HS384/HS512 stay accepted rather than risk logging every user out.
	check(t, "HS512, same secret", oldValidHS512, accepted1969)
	check(t, "HS384, same secret", signed(t, "HS384", sha512.New384, testSecret,
		map[string]interface{}{"token": "ext-token", "expire_at": future, "user_id": 1969}), accepted1969)

	// ⚠️ PADDING. v3 accepted "="-padded base64url segments; v5 refuses them
	// unless WithPaddingAllowed is set. A minter that pads (PHP's
	// base64_encode without rtrim, for one) pads EVERY HS256 signature.
	check(t, "signature segment padded", oldValidHS256+"=", accepted1969)
	check(t, "every segment padded, signed over the padded input", signedPadded(t, testSecret,
		map[string]interface{}{"token": "ext-token", "expire_at": future, "user_id": 1969}), accepted1969)
}

// (c) Tokens an attacker can produce without the secret are rejected.
func TestTokensWithoutTheSecretAreRejected(t *testing.T) {
	withSecret(t)
	claims := map[string]interface{}{"token": "x", "expire_at": future, "user_id": 1969}

	check(t, "wrong secret", signed(t, "HS256", sha256.New, "not-the-secret", claims), invalid)

	parts := strings.Split(oldValidHS256, ".")
	tampered := parts[0] + "." + segment(t, map[string]interface{}{"token": "ext-token", "expire_at": future, "user_id": 1}) + "." + parts[2]
	check(t, "payload changed, signature kept", tampered, invalid)

	check(t, "alg none, empty signature",
		segment(t, map[string]string{"alg": "none", "typ": "JWT"})+"."+segment(t, claims)+".", invalid)

	// Alg confusion: the header claims RS256 but the signature is an HMAC made
	// with the shared secret. Must fail on the header's algorithm.
	check(t, "alg RS256 header over an HMAC signature", signed(t, "RS256", sha256.New, testSecret, claims), invalid)

	check(t, "HS512 with the wrong secret", signed(t, "HS512", sha512.New, "not-the-secret", claims), invalid)
	check(t, "no Authorization header", "", invalid)
	check(t, "not a JWT", "abc", invalid)
	check(t, "Bearer prefix (never accepted)", "Bearer "+oldValidHS256, invalid)
}

// ⚠️ THE OLD KEYFUNC READ THE CLAIMS WITH BARE TYPE ASSERTIONS, and a keyfunc
// runs BEFORE the signature is checked. Any caller, with no secret at all, could
// make it panic by leaving out expire_at or sending a non-numeric user_id.
// The claims are now read only from a verified token, and a malformed one is
// refused, never a panic.
func TestMalformedClaimsAreRefusedNotPanicked(t *testing.T) {
	withSecret(t)

	check(t, "forged, no expire_at",
		signed(t, "HS256", sha256.New, "not-the-secret", map[string]interface{}{"user_id": 1969}), invalid)
	check(t, "forged, user_id is a string",
		signed(t, "HS256", sha256.New, "not-the-secret", map[string]interface{}{"expire_at": future, "user_id": "1969"}), invalid)
	check(t, "forged, expire_at is a number",
		signed(t, "HS256", sha256.New, "not-the-secret", map[string]interface{}{"expire_at": 4102444800, "user_id": 1969}), invalid)

	check(t, "signed, no expire_at", hs256(t, map[string]interface{}{"user_id": 1969}), invalid)
	check(t, "signed, user_id is a string", hs256(t, map[string]interface{}{"expire_at": future, "user_id": "1969"}), invalid)
	check(t, "signed, expire_at is a number", hs256(t, map[string]interface{}{"expire_at": 4102444800, "user_id": 1969}), invalid)
	// Unchanged: an unparseable expire_at reads as 0, which is in the past.
	check(t, "signed, expire_at not numeric", hs256(t, map[string]interface{}{"expire_at": "soon", "user_id": 1969}), expired)
}

// The registered time claims are checked by dgrijalva/jwt-go v3's rules, not
// v5's (see v3Claims): these are the inputs on which the two libraries differ,
// and every one must answer as v3 did. None of them are in the tokens base_api
// mints (token, expire_at, user_id), but an external minter could send them.
// The run against the old code passes every case here unchanged.
func TestRegisteredTimeClaims(t *testing.T) {
	withSecret(t)
	base := func(extra map[string]interface{}) map[string]interface{} {
		c := map[string]interface{}{"token": "x", "expire_at": future, "user_id": 1969}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}

	// v3 refused these; v5's defaults would refuse the first three and ACCEPT
	// the future iat (v5 checks iat only when asked).
	check(t, "exp in the past", hs256(t, base(map[string]interface{}{"exp": 1700000000})), invalid)
	check(t, "nbf in the future", hs256(t, base(map[string]interface{}{"nbf": 4102444800})), invalid)
	check(t, "iat in the future", hs256(t, base(map[string]interface{}{"iat": 4102444800})), invalid)
	check(t, "exp 0.5 (whole second 0)", hs256(t, base(map[string]interface{}{"exp": 0.5})), accepted1969)

	// v3 accepted these; v5's defaults refuse every one.
	check(t, "exp as a string", hs256(t, base(map[string]interface{}{"exp": future})), accepted1969)
	check(t, "exp null", hs256(t, base(map[string]interface{}{"exp": nil})), accepted1969)
	check(t, "exp true", hs256(t, base(map[string]interface{}{"exp": true})), accepted1969)
	check(t, "iat as a string", hs256(t, base(map[string]interface{}{"iat": "4102444800"})), accepted1969)
	check(t, "iat null", hs256(t, base(map[string]interface{}{"iat": nil})), accepted1969)
	check(t, "nbf as a string", hs256(t, base(map[string]interface{}{"nbf": "4102444800"})), accepted1969)
	check(t, "nbf null", hs256(t, base(map[string]interface{}{"nbf": nil})), accepted1969)

	// Both accept these.
	check(t, "exp in the future", hs256(t, base(map[string]interface{}{"exp": 4102444800})), accepted1969)
	check(t, "exp 0 (not set)", hs256(t, base(map[string]interface{}{"exp": 0})), accepted1969)
	check(t, "iat in the past", hs256(t, base(map[string]interface{}{"iat": 1700000000})), accepted1969)
	// base_api never checks an audience, so an aud claim changes nothing either
	// way. CVE-2020-26160 lives in the library's audience check, which base_api
	// never uses; jwt_v5_test.go pins the library fix itself.
	check(t, "aud as an array", hs256(t, base(map[string]interface{}{"aud": []string{"a", "b"}})), accepted1969)
}

// The payload is decoded as v3 decoded it: the first JSON value only, numbers
// as float64. v5 alone would refuse trailing bytes after the object.
func TestPayloadDecodedAsV3Did(t *testing.T) {
	withSecret(t)
	signRaw := func(payload string) string {
		unsigned := b64([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + b64([]byte(payload))
		mac := hmac.New(sha256.New, []byte(testSecret))
		mac.Write([]byte(unsigned))
		return unsigned + "." + b64(mac.Sum(nil))
	}
	check(t, "trailing bytes after the object", signRaw(`{"expire_at":"`+future+`","user_id":1969} trailing`), accepted1969)
	check(t, "a second object after the first", signRaw(`{"expire_at":"`+future+`","user_id":1969}{"user_id":1}`), accepted1969)
	check(t, "duplicate user_id: the last one wins", signRaw(`{"expire_at":"`+future+`","user_id":1,"user_id":1969}`), accepted1969)
	check(t, "a number that overflows float64", signRaw(`{"expire_at":"`+future+`","user_id":1969,"x":1e400}`), invalid)
	check(t, "not an object", signRaw(`["expire_at"]`), invalid)
	check(t, "large user_id loses precision as it did", signRaw(`{"expire_at":"`+future+`","user_id":9007199254740993}`),
		outcome{ok: true, userId: 9007199254740992, message: "Success"})
}
