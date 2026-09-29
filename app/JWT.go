package app

import(
    jwt "github.com/golang-jwt/jwt/v5"
    "github.com/beego/beego/v2/core/logs"
    beego "github.com/beego/beego/v2/server/web"
    "github.com/beego/beego/v2/server/web/context"
    "encoding/json"
    "errors"
    "strconv"
    "strings"
    "time"
    // "fmt"
)

func hasExpiredJWT(exp string) bool{
	expire_at, _ := strconv.Atoi(exp);
	time_now := int(time.Now().UTC().Unix());
        
  return time_now>expire_at
}

// MintJWT signs the token /token hands out: HS256, "expire_at" a STRING of unix
// seconds, "user_id" a number, and the external user's own token.
//
// ⚠️ THE SHAPE IS A CONTRACT: ParseJWT, and every client holding one of these
// tokens, reads expire_at as a string. Change it only with both sides.
func MintJWT(userToken string, userId int64, expireAt int64) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"token":     userToken,
		"expire_at": strconv.FormatInt(expireAt, 10),
		"user_id":   userId,
	}).SignedString(Secret_key)
}

// DefaultTokenLifetimeSeconds is how long a /token token lives when the
// service's conf sets no tokenLifetimeSeconds: 24 h, upstream's value since
// 2025-09-25 (it was 10 h before).
const DefaultTokenLifetimeSeconds int64 = 86400

// TokenLifetimeSeconds reads tokenLifetimeSeconds from the service's conf.
//
// ⚠️ READ AT CALL TIME, NOT IN init(). Services call LoadAppConfig again after
// startup, and each load replaces AppConfig; a value captured at init would be
// the one from before that reload.
//
// A missing, unparseable, zero or negative value falls back to the default: a
// token that expires the moment it is minted locks every integration out.
func TokenLifetimeSeconds() int64 {
	v := beego.AppConfig.DefaultInt64("tokenLifetimeSeconds", DefaultTokenLifetimeSeconds)
	if v <= 0 {
		return DefaultTokenLifetimeSeconds
	}
	return v
}

// NewAuthToken mints the token /token hands out, expiring TokenLifetimeSeconds
// after now, and returns it with its expiry (unix seconds).
func NewAuthToken(userToken string, userId int64, now time.Time) (string, int64, error) {
	exp := now.UTC().Unix() + TokenLifetimeSeconds()
	token, err := MintJWT(userToken, userId, exp)
	return token, exp, err
}

// timeNow is time.Now, replaceable in tests.
var timeNow = time.Now

// hmacMethods are the algorithms the old library accepted with a []byte key:
// the HMAC family, and nothing else. Naming them keeps "none", RS*, ES* and PS*
// out before the key is even looked up.
var hmacMethods = []string{
	jwt.SigningMethodHS256.Alg(),
	jwt.SigningMethodHS384.Alg(),
	jwt.SigningMethodHS512.Alg(),
}

// parserOptions reproduce what dgrijalva/jwt-go v3 accepted, so replacing it
// changes no answer for any token (the one intended difference is that
// malformed claims are refused instead of panicking; see ParseJWT).
//
//   - WithPaddingAllowed: v3 decoded "="-padded base64url segments; v5 refuses
//     them by default. An HMAC signature always pads (HS256's 32 bytes are 44
//     characters ending in "="), so a minter that pads would otherwise lose
//     EVERY token. Minting is unaffected: v5 always encodes unpadded.
//   - WithJSONNumber: makes v5 decode the payload with a json.Decoder, which is
//     what v3 did; v3Claims.UnmarshalJSON then reads it exactly as v3 did.
var parserOptions = []jwt.ParserOption{
	jwt.WithValidMethods(hmacMethods),
	jwt.WithPaddingAllowed(),
	jwt.WithJSONNumber(),
}

// parseToken verifies the method, the signature and the registered time
// claims, and nothing else.
func parseToken(tokenString string) (*jwt.Token, v3Claims, error) {
	var claims v3Claims
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return verificationKeys(), nil
	}, parserOptions...)
	return token, claims, err
}

// verificationKeys is the key a signature is checked against: Secret_key, and
// during a rotation the previous key as well.
//
// ⚠️ TWO KEYS DURING A ROTATION. Tokens are always SIGNED with Secret_key; the
// previous key only VERIFIES, so the tokens clients already hold keep working
// while new ones are minted with the new key. A rotation becomes a conf change
// with no forced re-login: move the old key to previousSecretKey, set the new
// secretKey, and delete previousSecretKey once every old token has passed its
// expire_at.
//
// Only the SIGNATURE check sees two keys. v5 tries them in order and stops at
// the first match; the method allow-list runs before it and the claims after
// it, once, exactly as with one key.
func verificationKeys() interface{} {
	prev := previousSecretKey()
	if prev == nil {
		return Secret_key
	}
	return jwt.VerificationKeySet{Keys: []jwt.VerificationKey{Secret_key, prev}}
}

// previousSecretKey is the key tokens were signed with before the last
// rotation, from the service's conf ("previousSecretKey"). Empty means no
// rotation is in progress.
//
// ⚠️ READ PER CALL, like tokenLifetimeSeconds: dropping the old key is a conf
// change, and a value captured at startup would outlive a config reload.
//
// ⚠️ EMPTY MUST MEAN DISABLED, NEVER "THE EMPTY KEY". HMAC accepts a zero-length
// key, so treating "" as a key would let anyone sign a token with nothing.
func previousSecretKey() []byte {
	v, _ := beego.AppConfig.String("previousSecretKey")
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return []byte(v)
}

// v3Claims holds the payload the way dgrijalva/jwt-go v3's MapClaims did, and
// validates exp/iat/nbf by v3's rules instead of v5's.
//
// ⚠️ THE RULES ARE v3's ON PURPOSE. Tokens for the apps are minted outside these
// repos, so any input v3 accepted may be in the wild. v5 differs on each of:
//   - exp/iat/nbf of a non-numeric type or null: v3 ignored the claim, v5 fails;
//   - a value of 0: v3 ignored it, v5 reads exp 0 as absent too but iat/nbf
//     only when checked;
//   - exp == now: v3 accepted (now <= exp), v5 refuses (now < exp);
//   - a future iat: v3 refused, v5 only checks iat with WithIssuedAt;
//   - fractions: v3 truncated to whole seconds, v5 keeps them.
//
// The v5 getters below answer "absent" so v5's own validator checks nothing;
// Validate, which v5 calls after the signature is verified, applies v3's rules.
type v3Claims map[string]interface{}

// UnmarshalJSON decodes as v3 did: the first JSON value of the payload only
// (v3's json.Decoder ignored anything after it) and numbers as float64 (so a
// number that overflows float64 fails the token). With WithJSONNumber, v5 hands
// this method exactly that first value.
func (c *v3Claims) UnmarshalJSON(b []byte) error {
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	*c = m
	return nil
}

func (c v3Claims) GetExpirationTime() (*jwt.NumericDate, error) { return nil, nil }
func (c v3Claims) GetIssuedAt() (*jwt.NumericDate, error)       { return nil, nil }
func (c v3Claims) GetNotBefore() (*jwt.NumericDate, error)      { return nil, nil }
func (c v3Claims) GetIssuer() (string, error)                   { return "", nil }
func (c v3Claims) GetSubject() (string, error)                  { return "", nil }
func (c v3Claims) GetAudience() (jwt.ClaimStrings, error)       { return nil, nil }

// Validate is dgrijalva/jwt-go v3's MapClaims.Valid, rule for rule: whole
// seconds, a claim that is absent, non-numeric or 0 is ignored, exp passes
// while now <= exp, iat and nbf pass while now >= them.
func (c v3Claims) Validate() error {
	now := timeNow().Unix()
	if exp, ok := v3Seconds(c["exp"]); ok && now > exp {
		return jwt.ErrTokenExpired
	}
	if iat, ok := v3Seconds(c["iat"]); ok && now < iat {
		return jwt.ErrTokenUsedBeforeIssued
	}
	if nbf, ok := v3Seconds(c["nbf"]); ok && now < nbf {
		return jwt.ErrTokenNotValidYet
	}
	return nil
}

// v3Seconds reads a registered time claim as v3 did: a float64, truncated to
// whole seconds, where 0 (after truncation) means "not set".
func v3Seconds(v interface{}) (int64, bool) {
	f, ok := v.(float64)
	if !ok {
		return 0, false
	}
	s := int64(f)
	return s, s != 0
}

// refusalReason names which check refused a token, from v5's error sentinels.
func refusalReason(err error) string {
	switch {
	case errors.Is(err, jwt.ErrTokenMalformed):
		return "malformed"
	case errors.Is(err, jwt.ErrTokenUnverifiable):
		return "unverifiable"
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return "signature"
	case errors.Is(err, jwt.ErrTokenExpired):
		return "expired"
	case errors.Is(err, jwt.ErrTokenUsedBeforeIssued):
		return "used_before_issued"
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return "not_valid_yet"
	case errors.Is(err, jwt.ErrTokenInvalidClaims):
		return "claims"
	}
	return "other"
}

// ParseJWT validates the Authorization header and returns the caller's user id.
//
// ⚠️ THE CLAIMS ARE READ ONLY AFTER THE SIGNATURE IS VERIFIED. The keyfunc runs
// before verification, so reading claims there with bare type assertions let a
// caller WITHOUT the secret panic the request (no expire_at, or a non-numeric
// user_id). A verified token with malformed claims is now refused, not a panic.
func ParseJWT(ctx *context.Context) (bool, int64, string) {
	header := ctx.Input.Header("Authorization")
	token, claims, err := parseToken(header)
	if err != nil || token == nil || !token.Valid {
		// ⚠️ LOG WHY, NEVER THE TOKEN. Every refusal answers the same "Invalid
		// Token", so without the library's reason a deploy that locks real users
		// out (a minter this code cannot see) looks exactly like forgeries.
		if header != "" && err != nil {
			logs.Warn("jwt refused (%s): %v", refusalReason(err), err)
		}
		return false, 0, "Invalid Token"
	}
	expire_at, ok := claims["expire_at"].(string)
	if !ok {
		return false, 0, "Invalid Token"
	}
	// A missing user_id has always been accepted as user 0; keep that.
	var userId int64
	if val, present := claims["user_id"]; present {
		f, isNumber := val.(float64)
		if !isNumber {
			return false, 0, "Invalid Token"
		}
		userId = int64(f)
	}
	if hasExpiredJWT(expire_at) {
		return false, 0, "Token has expired"
	}
	return true, userId, "Success"
}
