# Serving Sentro in production: loopback, behind an HTTPS reverse proxy

The backend does not speak TLS. In production it listens on the loopback interface only,
and a reverse proxy on the same host terminates HTTPS and forwards to it. Anything else
can reach the backend only through the proxy.

```
browser ──HTTPS──> reverse proxy (this host, :443) ──HTTP──> 127.0.0.1:8000  python main.py serve
```

Two configurations are here; use one:

- [`Caddyfile`](Caddyfile): Caddy 2, one binary, Windows or Linux.
- [`nginx.conf`](nginx.conf): nginx.

IIS with Application Request Routing works too, as long as it follows the header rules below.

## The backend's side

```powershell
$env:DSPM_ENV = "production"
$env:DSPM_TRUSTED_HOSTS = "sentro.corp.example"   # the name users type; the proxy passes it through
$env:DSPM_TRUSTED_PROXIES = "127.0.0.1"           # the proxy - believed about who its client was
# DSPM_CORS_ORIGINS stays unset: the console is served by the backend itself
# ...plus DSPM_SECRET_KEY, DSPM_ADMIN_PASSWORD, DSPM_VAULT_KEY and DSPM_DB_URL (see .env.example)
python main.py serve --host 127.0.0.1 --port 8000
```

## What production refuses to start with (C5)

Each of these configurations has been seen to fail open, so the install stops and says
why instead of logging a warning:

| Refused | Why |
|---|---|
| `DSPM_TRUSTED_HOSTS` empty, or with a `*` | The Host header would decide what the console believes its own name is. |
| A `DSPM_CORS_ORIGINS` entry that is `*`, local (`localhost`, `127.0.0.1`, `::1`, `*.localhost`) or `http://` | The API sends credentials to every listed origin. |
| A `DSPM_TRUSTED_PROXIES` entry that is not an address or network, or `0.0.0.0/0` / `::/0` | Any client could then choose the address it is audited and throttled as. |
| `serve --host` other than loopback | The backend has no TLS. If TLS ends on a load balancer that alone can reach this host, say so with `DSPM_ALLOW_EXTERNAL_BIND=1`. |
| `serve --host 127.0.0.1` with no trusted proxy covering it | Every request would come from the proxy: every audit row would name it, and one attacker's failed sign-ins would lock every user out. |

## Rules for the proxy

- **Replace `X-Forwarded-For` with the address you saw**, or append to it. Never pass on a
  client's header as the only one. The backend reads the header from the right and
  believes it only from `DSPM_TRUSTED_PROXIES`, so a client's own entries on the left are
  ignored either way.
- **Set `X-Forwarded-Proto: https`.** The backend believes it only from a trusted proxy.
- **Pass the `Host` header through unchanged.** It must match `DSPM_TRUSTED_HOSTS`.
- **Don't buffer responses.** Inventory exports stream.
- **Allow request bodies up to `DSPM_MAX_BODY_BYTES`** (25 MB by default); the backend
  enforces its own limit as well.

The backend is started with uvicorn's own forwarded-header handling turned off
(`proxy_headers=False` in `main.py serve`). uvicorn would otherwise believe
`X-Forwarded-For` from 127.0.0.1 whatever `DSPM_TRUSTED_PROXIES` says, and any program on
the host could claim a fresh address for every sign-in attempt.
`tests/test_deployment_boundary.py` tries exactly that against a real server.
