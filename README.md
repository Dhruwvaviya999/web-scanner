# Web Scanner

A web application for running and tracking HTTP reconnaissance scans against sites you own.

**This is the Phase 3 release: a basic security-configuration scanner.** It provides
authentication, scan management, one bounded HTTP request per scan, and analysis of that
response's security headers and cookies, recorded as structured findings.

**It performs no vulnerability testing.** No payloads are sent. There is no crawling, no TLS
inspection, no XSS, SQL-injection, CSRF, SSRF or IDOR testing, no CORS analysis and no risk
scoring.

> The scanner currently performs basic HTTP and security-configuration analysis. **It does not
> guarantee that a website is secure.** A scan with no findings means the specific checks listed
> below found nothing on a single response — not that the site is safe.

---

## Architecture

```
Browser
   |  HTTPS / cookies
Next.js frontend (App Router, TypeScript)     :3000
   |  Axios, withCredentials
FastAPI REST API                              :8000
   |  SQLAlchemy 2.0 ORM
PostgreSQL                                    :5432
```

The frontend and backend are two independent applications with no shared runtime. The only
contract between them is the JSON REST API and the session cookie.

Inside the backend, the scanning engine is deliberately isolated:

```
routers/  ->  services/  ->  scanner/   (never imports back into the app)
                 |
              models/  ->  PostgreSQL
```

`app/scanner/` never imports `app.models`, `app.routers` or `app.core.database`. It accepts a URL
and returns a plain `ScanReport` dataclass. `services/scan_service.py` is the single translation
layer that turns that report into database rows. This is what allows the scanner to grow into a
full crawling and analysis pipeline in later phases without touching the API or the schema.

---

## Technology stack

| Layer    | Technology |
| -------- | ---------- |
| Frontend | Next.js 16 (App Router), React 19, TypeScript, Tailwind CSS 4, shadcn/ui, Axios, react-hook-form, Zod, pnpm |
| Backend  | Python 3.14, FastAPI, Pydantic v2, SQLAlchemy 2.0, Alembic, PyJWT, argon2-cffi, httpx |
| Database | PostgreSQL 18 |

---

## Folder structure

```
web-scanner/
├── README.md
├── .gitignore
│
├── backend/
│   ├── .env.example
│   ├── requirements.txt
│   ├── alembic.ini
│   ├── alembic/
│   │   ├── env.py                     # reads DATABASE_URL from app settings
│   │   └── versions/
│   │       ├── 0001_initial_schema.py
│   │       ├── 0002_scan_response_analysis.py
│   │       └── 0003_findings.py
│   └── app/
│       ├── main.py                    # app wiring, CORS, exception handlers
│       ├── core/
│       │   ├── config.py              # environment-driven settings
│       │   ├── database.py            # engine, session factory, Base
│       │   ├── security.py            # Argon2id hashing + JWT
│       │   ├── cookies.py             # httpOnly auth cookie
│       │   ├── deps.py                # get_current_user, DbSession
│       │   └── errors.py              # error types + structured payload
│       ├── models/                    # user.py, scan.py, finding.py
│       ├── schemas/                   # auth.py, user.py, scan.py, finding.py, common.py
│       ├── routers/                   # auth.py, users.py, scans.py
│       ├── services/                  # auth_service.py, scan_service.py, finding_service.py
│       └── scanner/                   # isolated engine
│           ├── types.py               # dataclasses + ScanModule protocol
│           ├── url_validator.py       # parsing + SSRF protection
│           ├── http_scanner.py        # transport: request, redirects, bounded read
│           ├── response_analyzer.py   # interpretation: title, type, size (pure)
│           ├── scanner.py             # orchestrator
│           └── security/              # detectors, all pure
│               ├── types.py           # FindingData + severity/confidence/category
│               ├── headers.py         # security-header rules
│               ├── cookies.py         # Set-Cookie parsing + cookie rules
│               └── module.py          # glue: response -> findings
│   └── tests/                         # pytest: headers, cookies, findings API
│
└── frontend/
    ├── .env.example
    └── src/
        ├── proxy.ts                   # cookie-presence route redirects
        ├── app/
        │   ├── layout.tsx             # AuthProvider + Toaster
        │   ├── page.tsx               # public landing page
        │   ├── login/  register/
        │   └── dashboard/
        │       ├── layout.tsx         # AuthGuard + sidebar + header
        │       ├── page.tsx           # overview + stats
        │       ├── scans/page.tsx     # history, filter, pagination
        │       ├── scans/[id]/page.tsx
        │       └── profile/page.tsx
        ├── components/
        │   ├── ui/                    # shadcn/ui primitives
        │   ├── layout/                # sidebar, header, user menu, mobile nav
        │   ├── auth/                  # login/register forms, AuthGuard
        │   ├── scans/                 # table, badges, result sections, create form
        │   ├── findings/               # findings section, severity badges
        │   ├── dashboard/             # stat card
        │   └── common/                # page header, empty/error states
        ├── hooks/                     # use-auth.tsx, use-async-data.ts
        ├── lib/                       # api-client.ts, errors.ts, format.ts
        ├── services/                  # auth.service.ts, user.service.ts, scan.service.ts
        └── types/                     # user.ts, scan.ts, finding.ts, api.ts
```

---

## Environment variables

Secrets are never hardcoded. Both applications read configuration from `.env` files, which are
gitignored; only the `.env.example` templates are committed.

### backend/.env

| Variable | Required | Default | Purpose |
| -------- | -------- | ------- | ------- |
| `DATABASE_URL` | **yes** | — | `postgresql+psycopg://user:password@host:5432/dbname` |
| `JWT_SECRET_KEY` | **yes** | — | Signing key, minimum 32 characters |
| `JWT_ALGORITHM` | no | `HS256` | JWT signature algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | no | `60` | Session lifetime |
| `ENVIRONMENT` | no | `development` | `production` disables `/docs` |
| `AUTH_COOKIE_NAME` | no | `ws_access_token` | Must match the frontend value |
| `AUTH_COOKIE_SECURE` | no | `false` | **Set to `true` under HTTPS** |
| `AUTH_COOKIE_SAMESITE` | no | `lax` | CSRF protection for state-changing requests |
| `AUTH_COOKIE_DOMAIN` | no | *(empty)* | Set to a shared parent domain when API and UI use different subdomains |
| `CORS_ORIGINS` | no | `http://localhost:3000` | Comma-separated allowed frontend origins |
| `SCANNER_TIMEOUT_SECONDS` | no | `10` | Per-request timeout |
| `SCANNER_TOTAL_TIMEOUT_SECONDS` | no | `30` | Whole-scan ceiling |
| `SCANNER_MAX_REDIRECTS` | no | `5` | Redirect hops followed |
| `SCANNER_ALLOW_PRIVATE_NETWORKS` | no | `false` | **Leave `false`.** Enabling it permits SSRF to internal hosts |

Generate a signing key with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

### frontend/.env.local

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` | Backend base URL, no trailing slash and no `/api` suffix |
| `NEXT_PUBLIC_AUTH_COOKIE_NAME` | `ws_access_token` | Must match `AUTH_COOKIE_NAME` |

---

## PostgreSQL setup

Create a dedicated role and database — do not run the application as the superuser:

```sql
CREATE ROLE webscanner WITH LOGIN PASSWORD 'a-strong-password';
CREATE DATABASE webscanner OWNER webscanner;
```

From a shell:

```bash
psql -U postgres -c "CREATE ROLE webscanner WITH LOGIN PASSWORD 'a-strong-password';"
psql -U postgres -c "CREATE DATABASE webscanner OWNER webscanner;"
```

Then set the matching `DATABASE_URL` in `backend/.env`.

---

## Backend setup

```bash
cd backend

# 1. Virtual environment (requires a standard CPython 3.12+ build)
python -m venv .venv
.venv\Scripts\activate            # Windows
# source .venv/bin/activate       # macOS / Linux

# 2. Dependencies
pip install -r requirements.txt

# 3. Configuration
copy .env.example .env            # Windows  (use cp on macOS/Linux)
#    then set DATABASE_URL and JWT_SECRET_KEY

# 4. Database schema
alembic upgrade head

# 5. Run
uvicorn app.main:app --reload --port 8000
```

The API is then at <http://localhost:8000>, interactive docs at <http://localhost:8000/docs>,
health probe at <http://localhost:8000/api/health>.

### Alembic commands

```bash
alembic upgrade head           # apply all migrations
alembic downgrade -1           # roll back one migration
alembic current                # show the applied revision
alembic history --verbose      # list the migration chain
alembic revision --autogenerate -m "describe the change"
```

Always change the schema through a migration; never edit the database by hand.

---

## Tests

```bash
cd backend
.venv\Scripts\python -m pytest          # 52 tests
```

`tests/test_security_headers.py` and `tests/test_cookies.py` cover the detectors as pure
functions — no network, no database. `tests/test_findings_api.py` drives the real app through
FastAPI's `TestClient` against the configured database, registering a fresh user per test and
cleaning up afterwards.

---

## Frontend setup

```bash
cd frontend
pnpm install
copy .env.example .env.local      # Windows  (use cp on macOS/Linux)
pnpm dev                          # http://localhost:3000
```

Production build:

```bash
pnpm build
pnpm start
```

---

## Running the application

Three processes, started in this order:

| # | Component  | Command | URL |
| - | ---------- | ------- | --- |
| 1 | PostgreSQL | (system service) | `localhost:5432` |
| 2 | Backend    | `cd backend && .venv\Scripts\activate && uvicorn app.main:app --reload --port 8000` | <http://localhost:8000> |
| 3 | Frontend   | `cd frontend && pnpm dev` | <http://localhost:3000> |

---

## What the scanner does (Phase 2)

Each scan issues **one HTTP GET to the exact URL supplied** — the site is not crawled and no
paths are guessed.

### Pipeline

```
Router   (app/routers/scans.py)             auth, ownership, request shape
  |
Service  (app/services/scan_service.py)     PENDING -> RUNNING -> COMPLETED / FAILED, persistence
  |
Scanner  (app/scanner/scanner.py)           orchestrates modules, applies the total timeout
  |
HTTP     (app/scanner/http_scanner.py)      connects, follows redirects, reads a bounded body
  |
Analyzer (app/scanner/response_analyzer.py) interprets the response - pure, no I/O
```

`http_scanner` produces a `RawHttpResponse` (status, headers, timing, body prefix);
`response_analyzer` turns it into an `HttpProbeResult`. Splitting fetching from interpretation
keeps the analyzer testable without a network, and lets either side change independently.

### What is collected

| Field | Source |
| ----- | ------ |
| `http_status_code` | Status of the final response |
| `final_url` | URL after following redirects |
| `response_time_ms` | Measured to headers-received, across the whole redirect chain |
| `content_type` | `Content-Type` header, whitespace-normalised, capped at 255 chars |
| `server_header` | `Server` header when the target discloses one, else `null` |
| `page_title` | `<title>`, only when the response is HTML |
| `redirect_count` | Number of hops followed |
| `content_length` | `Content-Length`, else bytes read when the body was read in full |
| `is_https` | Scheme of the final URL |
| `error_message` | Set only when the scan is `FAILED` |

### Example

`POST /api/scans` with `{"target_url": "https://example.com"}` returns:

```json
{
  "id": "b06ee43d-94ab-43c6-97db-050251f4a0c7",
  "target_url": "https://example.com/",
  "status": "COMPLETED",
  "http_status_code": 200,
  "final_url": "https://example.com/",
  "response_time_ms": 236,
  "content_type": "text/html",
  "server_header": "cloudflare",
  "is_https": true,
  "page_title": "Example Domain",
  "redirect_count": 0,
  "content_length": 559,
  "error_message": null
}
```

### Bounds and safety

* **Only the given URL is requested.** No crawling, no directory or subdomain guessing, no port
  scanning, no brute forcing, no exploitation.
* **Bodies are barely read.** Non-HTML responses are never downloaded. HTML is read only up to
  `SCANNER_MAX_RESPONSE_BYTES` (256 KiB), purely to recover the `<title>`. Response bodies are
  never stored in PostgreSQL.
* **Redirects are bounded** by `SCANNER_MAX_REDIRECTS` (5), and every hop is re-validated against
  the SSRF rules before connecting — so a public URL cannot redirect the scanner onto
  `127.0.0.1` or `169.254.169.254`. Redirect destinations are not themselves crawled.
* **Two timeouts:** per-request `SCANNER_TIMEOUT_SECONDS` (10 s) and whole-scan
  `SCANNER_TOTAL_TIMEOUT_SECONDS` (30 s). A scan cannot hang indefinitely.
* **Only `http://` and `https://`** targets are accepted. `javascript:`, `file:`, `data:` and URLs
  carrying credentials are rejected before any connection is attempted.
* **A failing target never fails the request.** Unreachable hosts, DNS failures, TLS errors and
  timeouts are recorded as a `FAILED` scan with a readable message; the API still returns `201`
  and the application does not crash.

### URL validation

A bare host (`example.com`) is treated as `https://example.com/`. Anything else that is not a
valid `http(s)` URL is rejected with `422` and a per-field message, rather than being silently
rewritten into something unintended. Hostnames are lower-cased and internationalised domains are
punycode-encoded.

---

## Security analysis (Phase 3)

Every check runs against the response the HTTP probe already collected. **No additional requests
are made to the target**, which is what keeps this phase passive.

### The Finding model

A scan has zero or many findings. Each records what was seen and what to do about it:

| Field | Meaning |
| ----- | ------- |
| `code` | Stable rule identifier, e.g. `missing_csp` — correlate across scans without matching prose |
| `title` | Short summary |
| `category` | `SECURITY_HEADER` or `COOKIE` in this phase; `TLS`, `INFORMATION_DISCLOSURE`, `OTHER` reserved |
| `severity` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO` |
| `confidence` | `HIGH` / `MEDIUM` / `LOW` |
| `description` | What was observed and why it matters |
| `evidence` | The specific observation. **Never contains a secret or a cookie value.** |
| `impact` | What could follow, stated conditionally where nothing was confirmed |
| `remediation` | The concrete fix |

**Severity** is about consequence if confirmed. Missing security headers are defence-in-depth
configuration observations, so nothing in this phase is emitted above `MEDIUM` — a test asserts
this. **Confidence** is about certainty: `HIGH` when the response was observed directly (a header
is present or absent), `MEDIUM` when a heuristic was involved (inferring a cookie's purpose from
its name).

### Architecture

```
Router -> Scan Service -> Scanner -> HttpScanner -> ResponseAnalyzer
                                          |
                                          +-> SecurityAnalysisModule
                                                |-> headers.py   (pure)
                                                +-> cookies.py   (pure)
                                                      |
                                                 FindingData
                                                      |
                                          finding_service -> database
```

The detectors are pure functions: headers and cookies in, `FindingData` out. They hold no session
and import no model, so every rule is testable without a network or a database. `finding_service`
is the only place findings become rows, and it writes them in the same transaction as the scan
result — a scan is never left `COMPLETED` with its findings missing.

### Security header rules

| Check | When missing | Severity | Notes |
| ----- | ------------ | -------- | ----- |
| `Strict-Transport-Security` | HTTPS only | MEDIUM | **Never reported for an HTTP target** — browsers ignore the header there, so flagging it would be a false positive. `max-age=0` -> LOW, a short `max-age` -> INFO |
| `Content-Security-Policy` | document responses | MEDIUM | Present but containing `unsafe-inline` / `unsafe-eval` / wildcard `default-src` -> INFO. No full CSP parser is attempted |
| `X-Content-Type-Options` | any response | LOW | `nosniff` accepted case-insensitively; any other value is reported |
| `X-Frame-Options` | document responses | LOW | `DENY` / `SAMEORIGIN` accepted. **Not reported when CSP sets `frame-ancestors`**, which supersedes it |
| `Referrer-Policy` | document responses | LOW | |
| `Permissions-Policy` | document responses | INFO | Hardening opportunity rather than a weakness |

Two rules keep the output honest rather than merely long:

* **HSTS is HTTPS-only**, as above.
* **Document-scoped headers are only checked on documents.** CSP, X-Frame-Options,
  Referrer-Policy and Permissions-Policy govern how a page is rendered, so reporting them missing
  on a JSON API endpoint is noise. A response with no `Content-Type` at all is treated as a
  document, so a misconfigured server is not silently exempted.

### Cookie rules

Every `Set-Cookie` header is parsed for name, `Secure`, `HttpOnly`, `SameSite`, `Domain` and
`Path`.

**Cookie values are discarded during parsing.** `CookieInfo` has no `value` field at all, so there
is no path by which a session identifier could reach a finding, a log or the database. This is
structural, not a convention, and is covered by a test.

| Check | Severity | Notes |
| ----- | -------- | ----- |
| Missing `Secure` on HTTPS | MEDIUM session-like / LOW otherwise | Not reported over HTTP, where the attribute is ignored anyway |
| Session-like cookie missing `HttpOnly` | MEDIUM, MEDIUM confidence | **Only for session-like names.** Many cookies are read by scripts by design |
| Missing `SameSite` | LOW session-like / INFO otherwise | Browsers default to Lax, so this is mostly a portability concern |
| `SameSite=None` without `Secure` | MEDIUM, HIGH confidence | Browsers reject this outright, so the cookie is likely never stored |

A cookie is treated as "session-like" by name — `session`, `sessionid`, `PHPSESSID`,
`JSESSIONID`, `connect.sid`, `laravel_session`, `access_token`, `jwt` and similar, plus fragments
such as `auth`, `token` and `login`. Short fragments like `sid` only match as whole words, so
`sidebar_state` is not mistaken for a session cookie. Because this is a heuristic, findings that
depend on it carry MEDIUM confidence and say so in their description.

### False-positive philosophy

The goal is a scanner worth trusting, not one that produces a large number of findings.

* Missing headers are described as configuration observations, never as exploitable
  vulnerabilities.
* Impact is stated conditionally: "if a cross-site scripting flaw exists" — because this phase
  performs no injection testing and cannot know.
* A well-configured site produces few findings. Scanning `github.com` yields two, both INFO.
* An empty result is reported as *"No findings were detected by the checks performed in this
  scan"*, never as "this site is secure".

---

## API overview

All endpoints are prefixed with `/api`. Every non-2xx response uses one shape:

```json
{
  "error": {
    "code": "email_already_registered",
    "message": "An account with this email already exists.",
    "details": []
  }
}
```

### Authentication

| Method | Path | Auth | Description |
| ------ | ---- | ---- | ----------- |
| POST | `/api/auth/register` | — | Create an account; returns 201 and sets the session cookie |
| POST | `/api/auth/login` | — | Exchange credentials for a session cookie |
| POST | `/api/auth/logout` | — | Clear the session cookie |
| GET  | `/api/auth/me` | yes | The currently authenticated user |

### Users

| Method | Path | Auth | Description |
| ------ | ---- | ---- | ----------- |
| GET   | `/api/users/me` | yes | Read the caller's profile |
| PATCH | `/api/users/me` | yes | Update the caller's display name |

### Scans

| Method | Path | Auth | Description |
| ------ | ---- | ---- | ----------- |
| POST   | `/api/scans` | yes | Create a scan, run the probe, return the result |
| GET    | `/api/scans` | yes | List the caller's scans (`limit`, `offset`, `status`) |
| GET    | `/api/scans/stats` | yes | Scan counts by status |
| GET    | `/api/scans/{scan_id}` | yes | Read one scan |
| GET    | `/api/scans/{scan_id}/findings` | yes | Security findings for one scan, most severe first |
| DELETE | `/api/scans/{scan_id}` | yes | Delete one scan |

### System

| Method | Path | Auth | Description |
| ------ | ---- | ---- | ----------- |
| GET | `/api/health` | — | Service and database status |

### Status codes

`400` malformed request, `401` missing/invalid/expired session, `403` forbidden,
`404` not found (also returned for another user's scan), `409` duplicate email,
`422` failed field validation, `500` unexpected server error (logged, never detailed to the client).

---

## How authentication works

1. **Registration** validates the payload (name, email, password, confirmation), rejects a
   duplicate email with `409`, and hashes the password with **Argon2id** (RFC 9106 low-memory
   profile: 64 MiB, `t=3`, `p=4`). Plaintext passwords are never stored or logged.
2. **Login** looks the user up by normalised email and verifies the hash. When the email is
   unknown, verification still runs against a dummy hash, so response timing does not reveal
   which addresses are registered. Both failure modes return the same message.
3. On success the API mints a **JWT** (`sub`, `iat`, `nbf`, `exp`, `jti`, `typ=access`) and returns
   it in an **httpOnly, SameSite=Lax cookie**. The token never appears in the response body, so
   page scripts — and therefore any XSS payload — cannot read it. `SameSite=Lax` also stops other
   origins from issuing state-changing requests with the cookie attached (CSRF).
4. **Protected routes** depend on `get_current_user`, which reads the cookie, verifies signature
   and expiry, and loads the active user. Anything else is a `401`.
5. **Logout** clears the cookie. It is deliberately unauthenticated so that signing out works even
   after the token has expired.
6. **Frontend**: `src/proxy.ts` redirects to `/login` when the cookie is absent — a convenience,
   not a security boundary. The real check is `AuthGuard`, which trusts the API's answer to
   `GET /api/auth/me`. A `401` on any later request tears down client state and returns the user
   to the sign-in page.

Password rules: at least 10 characters, containing a letter and a number. Enforced by Pydantic on
the server and mirrored by Zod in the browser; the server is authoritative.

---

## Security notes

* Passwords are Argon2id hashes; stored hashes are transparently upgraded when parameters change.
* Every scan query is filtered by `user_id` in SQL, so another user's scan returns `404` rather
  than `403` — the response never confirms that an id exists. Scan ids are UUIDv4, not sequential.
* **SSRF protection**: targets are resolved before connecting and rejected when *any* resolved
  address is private, loopback, link-local, multicast, reserved or unspecified. Redirects are
  followed manually so every hop is re-validated — a public URL that redirects to
  `http://169.254.169.254/` is refused. IPv4-mapped IPv6 addresses are unwrapped before checking.
* Only `http` and `https` targets are accepted. `javascript:`, `file:` and `data:` URLs are
  rejected, as are URLs containing credentials.
* Unhandled exceptions are logged server-side and returned as an opaque `500`; tracebacks, SQL and
  driver messages never reach the client.
* CORS is restricted to the configured origins with credentials enabled — never `*`.
* `/docs` and `/openapi.json` are disabled when `ENVIRONMENT=production`.
* Scan responses are streamed and discarded; only headers are read.

---

## Current limitations

* **No vulnerability testing.** A scan is one HTTP request. Security headers and cookies on that
  response are assessed; nothing is probed, and no payload is ever sent.
* **Findings are configuration observations.** Their absence does not mean a site is secure — it
  means these particular checks found nothing on one response.
* **Cookie classification is name-based.** A session cookie with an unusual name will not be
  recognised as one; a non-session cookie named `auth_pref` would be. Findings that depend on this
  carry MEDIUM confidence.
* **Only cookies set on the scanned response are seen.** Cookies set after login, or by
  JavaScript, are invisible to this scanner.
* **Header analysis reflects one URL.** Another path on the same site may send different headers.
* **No crawling.** Only the exact URL submitted is requested. Links, sitemaps and redirect
  destinations are not followed for discovery.
* Scans run **inline in the request**, so creating a scan blocks until the probe finishes
  (bounded by `SCANNER_TOTAL_TIMEOUT_SECONDS`, default 30 s). There is no background worker, so
  `PENDING` and `RUNNING` are transient in practice — they exist so that moving execution to a
  queue later needs no schema change.
* A target with an invalid TLS certificate fails the scan rather than being reported as a finding.
* `page_title` is only recovered from HTML present in the response body. Titles set by client-side
  JavaScript are not seen, because no browser engine is used.
* `content_length` is `null` when a target uses chunked encoding and its body exceeded the read
  limit — the scanner reports nothing rather than reporting its own cap as the page size.
* DNS rebinding between validation and connection is not defended against; closing that requires
  pinning the resolved address into the connection, planned alongside the crawler.
* Sessions cannot be revoked server-side before the token expires (no token denylist).
* Email addresses cannot be changed; there is no password reset or email verification.
* No automated test suite yet.

---

## Future scanner phases

Planned, in order. Everything from Phase 3 onward is unimplemented.

| Phase | Scope | State |
| ----- | ----- | ----- |
| 1 | Auth, dashboard, scan management, basic HTTP probe | done |
| 2 | Response analysis: page title, content type, size, redirect chain | done |
| 3 | `Finding` model, security-header and cookie analysis | **done - current release** |
| 4 | Crawler, endpoint discovery, TLS inspection, CORS policy, risk scoring | planned |
| 5 | Active testing: XSS, SQL injection, open redirect, API security checks | planned |
| 6 | Reporting and export, background execution for long-running scans | planned |

Each becomes a `ScanModule` behind the protocol already defined in
`backend/app/scanner/types.py`, registered in the `WebScanner` orchestrator. The API and database
layers do not need to change to accommodate them.

---

## Legal

Only scan systems you own or have explicit written authorisation to test. Unauthorised scanning
may be illegal in your jurisdiction.
