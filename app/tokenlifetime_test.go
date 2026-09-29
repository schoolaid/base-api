package app_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BenMz/base_api/app"
	beego "github.com/beego/beego/v2/server/web"
)

// withConf loads a real conf file through beego.LoadAppConfig, exactly as a
// service does at startup, and restores the previous config afterwards.
func withConf(t *testing.T, runMode, body string) {
	t.Helper()
	prevConf, prevB := beego.AppConfig, *beego.BConfig
	t.Cleanup(func() { beego.AppConfig, *beego.BConfig = prevConf, prevB })

	path := filepath.Join(t.TempDir(), "app.conf")
	if err := os.WriteFile(path, []byte("runmode = "+runMode+"\n"+body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := beego.LoadAppConfig("ini", path); err != nil {
		t.Fatalf("LoadAppConfig: %v", err)
	}
}

// The expiry /token hands out is the service's to choose. schoolaid-api has
// always handed out 10 h tokens (it pins an older base_api); moving it to this
// fork must not silently make them 24 h.
func TestTokenLifetimeComesFromTheServiceConf(t *testing.T) {
	for _, tc := range []struct {
		name string
		conf string
		want int64
	}{
		{"unset: today's default", "", 86400},
		{"top level", "tokenLifetimeSeconds = 36000\n", 36000},
		{"runmode section", "[prod]\ntokenLifetimeSeconds = 36000\n", 36000},
		{"zero falls back", "tokenLifetimeSeconds = 0\n", 86400},
		{"negative falls back", "tokenLifetimeSeconds = -5\n", 86400},
		{"not a number falls back", "tokenLifetimeSeconds = ten hours\n", 86400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withConf(t, "prod", tc.conf)
			if got := app.TokenLifetimeSeconds(); got != tc.want {
				t.Fatalf("TokenLifetimeSeconds() = %d, want %d", got, tc.want)
			}
		})
	}
}

// ⚠️ A LATER RELOAD MUST WIN. Services call LoadAppConfig again after startup
// and each load replaces AppConfig, so the value is read per call, not cached.
func TestTokenLifetimeFollowsAConfigReload(t *testing.T) {
	withConf(t, "prod", "tokenLifetimeSeconds = 36000\n")
	if got := app.TokenLifetimeSeconds(); got != 36000 {
		t.Fatalf("before reload: got %d, want 36000", got)
	}
	withConf(t, "prod", "tokenLifetimeSeconds = 7200\n")
	if got := app.TokenLifetimeSeconds(); got != 7200 {
		t.Fatalf("after reload: got %d, want 7200 — the value was captured before the reload", got)
	}
}

// NewAuthToken is what AuthController calls: its expiry and the token's
// expire_at claim must both follow the conf.
func TestNewAuthTokenUsesTheConfiguredLifetime(t *testing.T) {
	withSecret(t)
	withConf(t, "prod", "tokenLifetimeSeconds = 36000\n")
	now := time.Unix(4102408800, 0) // 2099-12-31 14:00 UTC

	tok, exp, err := app.NewAuthToken("ext-token", 1969, now)
	if err != nil {
		t.Fatal(err)
	}
	if exp != 4102444800 {
		t.Fatalf("exp = %d, want now+36000 = 4102444800", exp)
	}
	// Same claims, same secret → the jwt-go fixture, whose expire_at is
	// "4102444800". Proves the claim carries the configured expiry too.
	if tok != oldValidHS256 {
		t.Fatalf("token's expire_at does not match its returned expiry:\n got  %s\n want %s", tok, oldValidHS256)
	}
}
