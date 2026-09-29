# base_api

Shared Beego v2 base for SchoolAid's Go services: the `/token` endpoint
(`controllers.AuthController`), JWT minting and validation (`app/JWT.go`), and
`controllers.ApiController`, whose `Prepare` authenticates every request of the
controllers that embed it.

## This is the schoolaid org's fork

The upstream is [`github.com/BenMz/base_api`](https://github.com/BenMz/base_api),
a personal-account repository. This copy was forked into the `schoolaid` org on
2026-09-29 so the services' authentication code is maintained here.

The module path is still `github.com/BenMz/base_api`. Services consume this fork
through a `replace` directive:

```
replace github.com/BenMz/base_api => github.com/schoolaid/base_api <pseudo-version>
```

Renaming the module path to `github.com/schoolaid/base_api` is a separate,
later step.

Used by `schoolaid-positions-api`, `schoolaid-api` and `menu-api`.

## Configuration (read from the service's `conf/app.conf`)

| key | meaning | default |
|---|---|---|
| `secretKey` | HMAC key that signs and verifies tokens | none. base_api does not check it is set; positions-api and schoolaid-api refuse to start without it |
| `previousSecretKey` | during a key rotation, the old `secretKey`: tokens signed with it still verify; nothing is signed with it | empty (off); an empty or blank value never counts as a key |
| `tokenLifetimeSeconds` | lifetime of a token minted by `/token` | `86400` (24 h); a missing, non-numeric, zero or negative value uses the default |

`tokenLifetimeSeconds` and `previousSecretKey` are read on every call, so a
later `LoadAppConfig` in the service takes effect. Either may sit in the runmode
section (`[prod]`) or at the top level.

### Rotating `secretKey` without logging anyone out

1. In the service's conf: `previousSecretKey = <the current secretKey>`, then
   `secretKey = <the new key>`. Rebuild and deploy. Every party that SIGNS
   tokens this service verifies must switch to the new key in the same step.
2. Once the longest-lived token signed with the old key has passed its
   `expire_at`, delete `previousSecretKey`. Rebuild and deploy.

Until step 2 the old key still verifies tokens, so a leaked old key stays
usable for that window: step 2 is what completes the rotation.

## Tests

```sh
go test ./app/ ./controllers/ ./models/ ./routers/
```

`./tests` does not compile on `master` (it imports `base_api/routers`, not the
module path, and uses Beego v1), so `go test ./...` fails there independently of
any change.
