package app_test

import (
	"testing"

	"github.com/BenMz/base_api/app"
	jwt "github.com/golang-jwt/jwt/v5"
)

// (b) What the new library mints is what the old one minted. Both marshal the
// header and the claims map with encoding/json (sorted keys), so the same
// claims under the same secret must produce the SAME BYTES as the fixture
// minted by dgrijalva/jwt-go. Any difference in claim names, claim types or
// header shape shows up here as a different string.
func TestMintJWTMatchesTheOldLibraryByteForByte(t *testing.T) {
	withSecret(t)

	got, err := app.MintJWT("ext-token", 1969, 4102444800)
	if err != nil {
		t.Fatal(err)
	}
	if got != oldValidHS256 {
		t.Fatalf("v5 minted a different token than jwt-go did for the same claims:\n got  %s\n want %s", got, oldValidHS256)
	}

	gotExpired, err := app.MintJWT("ext-token", 1969, 1700000000)
	if err != nil {
		t.Fatal(err)
	}
	if gotExpired != oldExpired {
		t.Fatalf("expired token differs from jwt-go's:\n got  %s\n want %s", gotExpired, oldExpired)
	}
}

func TestMintedTokensParseTheSameWay(t *testing.T) {
	withSecret(t)

	for _, tc := range []struct {
		name   string
		userId int64
		exp    int64
		want   outcome
	}{
		{"live", 1969, 4102444800, accepted1969},
		{"user 0", 0, 4102444800, outcome{ok: true, userId: 0, message: "Success"}},
		{"expired", 1969, 1700000000, expired},
	} {
		tok, err := app.MintJWT("ext-token", tc.userId, tc.exp)
		if err != nil {
			t.Fatal(err)
		}
		check(t, tc.name, tok, tc.want)
	}
}

// (c) CVE-2020-26160, in the library itself. dgrijalva/jwt-go read "aud" as a
// string only, so an ARRAY audience became "" and VerifyAudience(x, false)
// answered true for any x: an audience check that could be bypassed. base_api
// never checks an audience (see TestRegisteredTimeClaims), so it was never
// reachable here; this pins that the library in go.mod reads an array audience
// correctly, in case a service ever starts checking one.
func TestLibraryRejectsAnArrayAudienceThatDoesNotMatch(t *testing.T) {
	v := jwt.NewValidator(jwt.WithAudience("schoolaid"))
	if err := v.Validate(jwt.MapClaims{"aud": []interface{}{"someone-else"}}); err == nil {
		t.Fatal("an array aud that does not contain the audience was accepted (CVE-2020-26160)")
	}
	if err := v.Validate(jwt.MapClaims{"aud": []interface{}{"x", "schoolaid"}}); err != nil {
		t.Fatalf("an array aud that DOES contain the audience was refused (%v), so the check above proves nothing", err)
	}
}
