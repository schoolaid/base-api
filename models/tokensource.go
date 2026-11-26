package models

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/beego/beego/v2/core/logs"
)

// ClassifyTokenSource says where a token login came from, for the transition line, without ever
// logging the address itself:
//   - a configured label, from TOKEN_LOGIN_KNOWN_SOURCES (comma-separated label=IP-or-CIDR pairs,
//     set per deployment; labels are [a-z0-9_-], up to 32 characters; spaces around `=` and `,`
//     are trimmed; a malformed entry is ignored and logged by its position, never its value);
//   - else "vpc" for a private or loopback address, "external" for any other, "unknown" if it
//     doesn't parse.
//
// Only the RIGHTMOST X-Forwarded-For hop is used: that is the one a load balancer in front appends
// for the connection it received; anything to its left came from the client and can say anything.
// With no header (a call inside the network), the peer address. Telemetry only: it decides nothing.
func ClassifyTokenSource(r *http.Request) string {
	ip := tokenClientIP(r)
	if ip == nil {
		return "unknown"
	}
	for _, s := range knownTokenSources() {
		if s.network.Contains(ip) {
			return s.label
		}
	}
	if ip.IsPrivate() || ip.IsLoopback() {
		return "vpc"
	}
	return "external"
}

// tokenClientIP is the address a load balancer in front saw: the rightmost hop of the last
// X-Forwarded-For line (anything to its left came from the client), or the peer with no header.
// nil if it doesn't parse.
func tokenClientIP(r *http.Request) net.IP {
	hop := ""
	if values := r.Header.Values("X-Forwarded-For"); len(values) > 0 {
		parts := strings.Split(values[len(values)-1], ",")
		hop = strings.TrimSpace(parts[len(parts)-1])
	}
	if hop == "" {
		hop = r.RemoteAddr
		if host, _, err := net.SplitHostPort(hop); err == nil {
			hop = host
		}
	}
	return net.ParseIP(hop)
}

// TokenSourceTag is a pseudonymous tag of the login's source address, for counting how many users
// one source mints: the first 8 hex characters of HMAC-SHA256(TOKEN_LOGIN_SRC_KEY, address). The
// address is never logged, and without the key the tag can't be recomputed from a list of
// addresses.
//   - "unkeyed" when the key is missing or shorter than 16 characters: never a weak hash;
//   - "unknown" when the address doesn't parse.
//
// Telemetry only: it decides nothing.
func TokenSourceTag(r *http.Request) string {
	ip := tokenClientIP(r)
	if ip == nil {
		return "unknown"
	}
	key := tokenSourceKey()
	if key == nil {
		return "unkeyed"
	}
	// ip.String() already writes a mapped IPv4 as plain IPv4, so both spellings tag alike.
	m := hmac.New(sha256.New, key)
	m.Write([]byte(ip.String()))
	return hex.EncodeToString(m.Sum(nil))[:8]
}

var (
	tokenSourceKeyOnce sync.Once
	tokenSourceKeyVal  []byte
)

func tokenSourceKey() []byte {
	tokenSourceKeyOnce.Do(func() {
		if k := strings.TrimSpace(os.Getenv("TOKEN_LOGIN_SRC_KEY")); len(k) >= 16 {
			tokenSourceKeyVal = []byte(k)
		}
	})
	return tokenSourceKeyVal
}

type tokenSource struct {
	label   string
	network *net.IPNet
}

var (
	tokenSourcesOnce sync.Once
	tokenSources     []tokenSource
	sourceLabel      = regexp.MustCompile(`^[a-z0-9_-]{1,32}$`)
)

func knownTokenSources() []tokenSource {
	tokenSourcesOnce.Do(func() {
		for i, entry := range strings.Split(os.Getenv("TOKEN_LOGIN_KNOWN_SOURCES"), ",") {
			if strings.TrimSpace(entry) == "" {
				continue
			}
			label, address, ok := strings.Cut(entry, "=")
			label, address = strings.TrimSpace(label), strings.TrimSpace(address)
			// A malformed entry is skipped and logged by its position only: never its value.
			if !ok || !sourceLabel.MatchString(label) {
				logs.Warn("TOKEN_LOGIN_KNOWN_SOURCES entry %d ignored (malformed)", i+1)
				continue
			}
			if !strings.Contains(address, "/") {
				if ip := net.ParseIP(address); ip != nil && ip.To4() != nil {
					address += "/32"
				} else {
					address += "/128"
				}
			}
			_, network, err := net.ParseCIDR(address)
			if err != nil {
				logs.Warn("TOKEN_LOGIN_KNOWN_SOURCES entry %d ignored (malformed)", i+1)
				continue
			}
			tokenSources = append(tokenSources, tokenSource{label: label, network: network})
		}
	})
	return tokenSources
}

// ResetTokenSourcesForTest makes the next login read TOKEN_LOGIN_KNOWN_SOURCES and
// TOKEN_LOGIN_SRC_KEY again.
func ResetTokenSourcesForTest() {
	tokenSourcesOnce = sync.Once{}
	tokenSources = nil
	tokenSourceKeyOnce = sync.Once{}
	tokenSourceKeyVal = nil
}
