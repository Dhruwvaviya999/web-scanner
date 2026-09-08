# Web Scanner

A web application for running and tracking HTTP reconnaissance scans against sites you own.

**This is the Phase 7 release: the active-probe framework.** Phase 6's reflected-XSS
detector now runs on reusable infrastructure — a probe engine that owns scope, budget, timeouts
and error handling, so a future detector inherits all of it rather than reimplementing it.
XSS behaviour is unchanged by the refactor.

**Reflected XSS remains the only active detector.** There is no SQL-injection, stored-XSS,
DOM-XSS, CSRF, SSRF, IDOR or open-redirect detection.

Phase 6 introduced that detector: It provides authentication, scan management, a bounded HTTP probe, a
bounded same-origin crawler, security-header and cookie analysis of every endpoint the crawl
reached, and **reflected cross-site-scripting detection** on discovered query parameters — all
deduplicated by rule identity, linked to the endpoints they affect, and reported with explicit
coverage numbers.

Active testing is limited to **reflected XSS on GET query parameters**, using an inert marker.
There is no stored or DOM XSS detection, no SQL-injection, CSRF, SSRF or IDOR testing, no TLS
inspection, no CORS analysis, no form submission and no risk scoring.

> **A clean result does not prove an application is secure.** A static reflected-XSS detector
> misses application-specific cases by construction — anything requiring authentication, a form
> submission, a second request, or JavaScript to manifest is invisible to it.

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
│   │       ├── 0003_findings.py
│   │       ├── 0004_attack_surface.py
│   │       ├── 0005_scan_intelligence.py
│   │       └── 0006_xss_category.py
│   └── app/
│       ├── main.py                    # app wiring, CORS, exception handlers
│       ├── core/
│       │   ├── config.py              # environment-driven settings
│       │   ├── database.py            # engine, session factory, Base
│       │   ├── security.py            # Argon2id hashing + JWT
│       │   ├── cookies.py             # httpOnly auth cookie
│       │   ├── deps.py                # get_current_user, DbSession
│       │   └── errors.py              # error types + structured payload
│       ├── models/                    # user, scan, finding, attack_surface
│       ├── schemas/                   # auth, user, scan, finding, attack_surface, common
│       ├── routers/                   # auth.py, users.py, scans.py
│       ├── services/                  # auth, scan, finding, attack_surface
│       └── scanner/                   # isolated engine
│           ├── types.py               # dataclasses + ScanModule protocol
│           ├── url_validator.py       # parsing + SSRF protection
│           ├── http_scanner.py        # transport: request, redirects, bounded read
│           ├── response_analyzer.py   # interpretation: title, type, size (pure)
│           ├── scanner.py             # orchestrator
│           ├── security/              # detectors, all pure
│           │   ├── types.py           # FindingData + severity/confidence/category
│           │   ├── headers.py         # security-header rules
│           │   ├── cookies.py         # Set-Cookie parsing + cookie rules
│           │   └── module.py          # glue: response -> findings
│           ├── analysis/              # phase 5 pipeline stage
│           │   ├── types.py           # coverage + aggregated findings
│           │   ├── endpoint_analyzer.py  # eligibility + per-endpoint run (pure)
│           │   ├── aggregator.py      # deduplication by rule identity (pure)
│           │   └── module.py          # glue: captured responses -> findings
│           ├── active/               # active-probe framework
│           │   ├── types.py           # ProbeTarget/Request/Outcome, detector protocol
│           │   ├── budget.py          # nested probe budgets, fails closed
│           │   ├── requests.py        # URL construction + marker generation (pure)
│           │   ├── comparison.py      # generic response comparison (pure)
│           │   ├── engine.py          # the only route to the network
│           │   └── module.py          # runs registered detectors
│           ├── vulnerabilities/       # active detectors
│           │   └── xss/
│           │       ├── types.py       # contexts, encoding states, probe
│           │       ├── payloads.py    # inert marker generation
│           │       ├── analyzer.py    # context + encoding analysis (pure)
│           │       ├── findings.py    # severity/confidence rules (pure)
│           │       ├── detector.py    # probe strategy, injectable fetcher
│           │       └── module.py      # glue: transport -> observations
│           └── crawler/               # attack-surface discovery
│               ├── types.py           # CrawlConfig + discovered resources
│               ├── url_normalizer.py  # normalisation + same-origin rules (pure)
│               ├── html_parser.py     # link + form extraction (pure)
│               ├── crawler.py         # bounded BFS, injectable fetcher
│               └── module.py          # glue: network fetcher -> CrawlResult
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
        │   ├── attack-surface/         # endpoints, forms, parameters
        │   ├── dashboard/             # stat card
        │   └── common/                # page header, empty/error states
        ├── hooks/                     # use-auth.tsx, use-async-data.ts
        ├── lib/                       # api-client.ts, errors.ts, format.ts
        ├── services/                  # auth.service.ts, user.service.ts, scan.service.ts
        └── types/                     # user, scan, finding, attack-surface, api
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
.venv\Scripts\python -m pytest          # 270 tests
```

| Suite | Covers |
| ----- | ------ |
| `test_security_headers.py` | Header rules, as pure functions |
| `test_cookies.py` | Cookie parsing and rules, including the no-values guarantee |
| `test_url_normalizer.py` | Normalisation, same-origin scoping, canonical URLs |
| `test_html_parser.py` | Link and form extraction |
| `test_crawler.py` | Crawl limits, cycles, redirects, non-HTML, failures |
| `test_finding_identity.py` | Rule identity and deduplication |
| `test_endpoint_analysis.py` | Eligibility, coverage, failure isolation |
| `test_finding_association.py` | Finding-to-endpoint linking and cascade behaviour |
| `test_xss_analyzer.py` | Reflection contexts, encoding, false-positive control |
| `test_xss_detector.py` | Probe budget, scope, non-HTML skipping, failure handling |
| `test_xss_integration.py` | XSS findings inside the existing finding architecture |
| `test_active_framework.py` | Probe building, budgets, comparison, engine scope and errors |
| `test_findings_api.py` | Findings API ownership and isolation |
| `test_attack_surface_api.py` | Endpoint/form API ownership and isolation |

The detector and crawler suites need no network: the crawler's page fetcher is injected, so
limits, cycles and failure handling are deterministic. The API suites drive the real app through
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

## Attack-surface discovery (Phase 4)

After the probe and the security detectors run, a crawler walks the target origin to map what
the application exposes: reachable URLs, the query parameters they accept, and the forms on each
page.

### Architecture

```
Router -> Scan Service -> Scanner -> HttpScanner -> ResponseAnalyzer
                                          |
                                          |-> SecurityAnalysisModule (headers, cookies)
                                          |
                                          +-> CrawlModule
                                                 |-> Crawler          (bounded BFS)
                                                 |-> url_normalizer   (pure)
                                                 |-> html_parser      (pure)
                                                       |
                                            Endpoints / Parameters / Forms
                                                       |
                                          attack_surface_service -> database
```

The crawler shares `HttpFetcher` with the single-page probe, so crawled pages get identical
redirect, SSRF-revalidation, timeout and body-size handling from one implementation. Its page
fetcher is injected, which is what lets the whole algorithm be tested against canned pages with
no network involved.

`url_normalizer` and `html_parser` are pure functions. Neither holds a session nor imports a
model.

### Crawl limits

Configurable in `backend/.env`; nothing is hardcoded in the crawler.

| Setting | Default | Purpose |
| ------- | ------- | ------- |
| `CRAWLER_ENABLED` | `true` | Turn crawling off entirely |
| `CRAWLER_MAX_PAGES` | `50` | Hard cap on pages fetched |
| `CRAWLER_MAX_DEPTH` | `3` | Link hops from the seed URL |
| `CRAWLER_TIME_BUDGET_SECONDS` | `90` | Wall-clock budget for the whole crawl |
| `CRAWLER_MAX_REDIRECTS_PER_PAGE` | `3` | Redirects followed per crawled page |

Termination is guaranteed three ways — the page cap, the depth cap and the time budget — and the
visited set is keyed on the canonical URL, so circular links cannot loop. **Reaching a limit is
normal completion, not a failure:** the scan is still `COMPLETED`, and `crawl_limit_reached`
records that it stopped early.

The crawl runs inline in the scan request, so `SCANNER_TOTAL_TIMEOUT_SECONDS` was raised to 150
and the frontend's axios timeout to 180 s, keeping the server's limit the one that ends a slow
scan.

### Scope: strictly same-origin

The origin is taken from the probe's **final** URL, so a target that redirects
`http://example.com` to `https://example.com` is crawled where it actually landed — and the lock
is taken from there, so no later redirect can widen the scope.

Same-origin means an exact scheme, host and port match. Deliberately strict:

| From `https://example.com` | Crawled? |
| -------------------------- | -------- |
| `https://example.com/login` | yes |
| `http://example.com/` | **no** — a scheme change is an origin change |
| `https://sub.example.com/` | **no** — a different host |
| `https://example.com:8443/` | **no** — a different port |
| `https://google.com/` | **no** |

A redirect that leaves the origin is refused rather than followed, so the crawler cannot be
walked onto another host by a hostile target.

### URL normalisation

Two forms of every URL matter:

* **fetch form** — what is actually requested, query values intact, because `/search?q=phone`
  and `/search?q=` return different pages.
* **canonical form** — what is stored and de-duplicated on, with query *values* stripped and
  parameter names sorted.

So `/search?q=phone&category=shoes` is fetched as written but stored as `/search?category&q`.
That gives two things at once: `/search?q=a` and `/search?q=b` count as one endpoint rather than
crawling every variant, and **no query value is ever written to the database** — a URL carrying
`?access_token=...` stores only the name `access_token`.

Normalisation also resolves relative links (`/login`, `products`, `../about`), strips fragments,
lower-cases scheme and host, drops a redundant default port, and supplies a `/` path.

### What is discovered

| Data | Detail |
| ---- | ------ |
| Endpoints | URL (canonical), path, method, status code, content type, depth, page title |
| Parameters | Query parameter **names**, per endpoint. Never values |
| Forms | Page URL, resolved action, method (GET/POST) |
| Form fields | Name, kind (input/textarea/select/button) and the `type` attribute. Never values |

Only HTML responses are parsed for links and forms. A JSON or image response is recorded as an
endpoint and otherwise left alone. Repeated control names — a radio or checkbox group — collapse
to one field, because that is one input as far as attack surface goes.

### What is never stored

* Query parameter values, including anything token-shaped in a URL.
* Form field values. A hidden input's `value` is frequently a CSRF token, so it is dropped at
  parse time; `EndpointParameter` and `FormField` have no `value` column at all.
* Cookie values (unchanged from Phase 3).

### Safety

* **Only same-origin GET requests.** No form is submitted, no payload is sent, no directory or
  subdomain is guessed, no port is scanned.
* Every request reuses the existing SSRF guard, so a link to `127.0.0.1` or `169.254.169.254` is
  refused like any other target.
* `robots.txt` is **not** consulted — see limitations.

---

## Scan pipeline (Phase 5)

```
POST /api/scans
      |
Scan Service            PENDING -> RUNNING
      |
Scanner
      |-- HttpProbeModule        fetch the seed, analyse the response
      |-- CrawlModule            crawl the origin, capture every response
      +-- EndpointAnalysisModule assess each captured response
                |
                |-- eligibility          which responses are worth analysing
                |-- headers.py           \  reused unchanged from Phase 3,
                |-- cookies.py           /  still pure, still network-free
                +-- aggregator           group by rule identity
                          |
      attack_surface_service -> endpoints, parameters, forms, analysis state
      finding_service        -> findings + occurrences
      scan summary           -> coverage and severity counters
                          |
Scan Service            COMPLETED
```

### No endpoint is fetched twice

The crawler already retrieves every page, so it keeps the analysis-relevant slice of each
response (`CapturedResponse`: status, headers, `Set-Cookie`, content type) and the analysis stage
consumes that. **The analysis stage issues no HTTP requests at all.** That halves the traffic
against the target compared with re-fetching, and leaves exactly one code path for redirects,
SSRF revalidation and timeouts rather than two that could drift apart.

The response body is deliberately *not* retained: no current detector reads page content, and not
keeping it means page content cannot leak into a finding.

When the crawler does not run — disabled, or the probe never connected — the seed response is
analysed on its own, so a scan always assesses whatever it managed to reach.

### Finding identity

Every rule has a stable identifier, and that identifier — never the display title — is what the
system keys on:

```
SECURITY_HEADER_CSP_MISSING          COOKIE_SECURE_MISSING
SECURITY_HEADER_HSTS_MISSING         COOKIE_HTTPONLY_MISSING
SECURITY_HEADER_X_FRAME_OPTIONS_MISSING   COOKIE_SAMESITE_MISSING
...                                  COOKIE_SAMESITE_NONE_WITHOUT_SECURE
```

Stored as a validated string rather than a native database enum: a scanner gains rules
constantly, and `ALTER TYPE ... ADD VALUE` on each one is friction for no benefit. The
`FindingRule` enum enforces the allowed values in code and at the schema boundary.

A finding's full identity is **`(rule_id, subject)`**. The subject is what the finding is *about*
within its rule — a cookie name, for instance. That second half matters:

| Two findings | Merge? | Why |
| ------------ | ------ | --- |
| `COOKIE_HTTPONLY_MISSING` and `COOKIE_SECURE_MISSING` | no | Different rules, despite similar titles |
| `COOKIE_SECURE_MISSING` on cookie `session` and on cookie `theme` | no | Different subjects — merging would erase which cookie was at fault |
| `SECURITY_HEADER_CSP_MISSING` on `/` and on `/login` | **yes** | Same rule, same subject, different place |

### Deduplication preserves affected endpoints

Grouping is a parent finding plus occurrence rows, so collapsing never loses information:

```
Finding: Content-Security-Policy header not set     (MEDIUM, HIGH confidence)
  rule_id: SECURITY_HEADER_CSP_MISSING
  endpoint: GET /            <- primary, the first place it was seen
  occurrence_count: 12
  occurrences:
    /            "No Content-Security-Policy header was present in the response."
    /login       "No Content-Security-Policy header was present in the response."
    /products    ...
```

Each occurrence keeps its own evidence, and `finding_occurrences.endpoint_url` holds the URL as
text alongside the foreign key — so an occurrence stays readable even if the endpoint row is
later removed. The finding's own `endpoint_id` is `ON DELETE SET NULL`, never CASCADE: losing an
endpoint row must not silently delete the security finding reported against it.

### Coverage

A scan distinguishes discovered from analysed, and says why anything was left out.

| Endpoint status | Meaning |
| --------------- | ------- |
| `ANALYZED` | Detectors ran against this response |
| `SKIPPED` | Deliberately not assessed — see `skip_reason` |
| `FAILED` | Should have been assessed but could not be. **Produces no findings** |
| `NOT_ANALYZED` | The analysis stage never reached it |

Skip reasons: `EXCLUDED_RESOURCE` (stylesheets, scripts, images, fonts, media — the current
detectors have nothing to say about them), plus `NON_HTML`, `EXTERNAL`, `DUPLICATE`,
`CRAWL_LIMIT`, `REQUEST_FAILED` and `UNSUPPORTED_SCHEME` for other cases.

JSON and other non-document responses *are* analysed — Phase 3's own guard still applies inside
the detectors, so document-scoped rules (CSP, framing, referrer, permissions) stay quiet while
HSTS and `X-Content-Type-Options` still apply.

### Failure philosophy

One bad page must not invalidate a scan. Twenty endpoints discovered, one timing out, nineteen
analysed produces a `COMPLETED` scan reporting `19 analysed, 1 could not be analysed`.

A failed endpoint yields **no findings at all**. Reporting a missing header for a page that was
never successfully read would be a fabricated result, so the pipeline refuses to do it.

### Scan summary

Written once at the end of the scan, deterministically, from what this run produced:

```
endpoints_discovered  endpoints_analyzed  endpoints_skipped  endpoints_failed
forms_discovered      parameters_discovered
total_findings  critical_count  high_count  medium_count  low_count  info_count
```

Counters stay NULL when the corresponding stage did not run, so "not attempted" remains
distinguishable from "attempted and found nothing". There is deliberately **no 0-100 risk
score** — a single number would imply a confidence this scanner has not earned.

---

## Reflected XSS detection (Phase 6)

The first active detector. It consumes the query parameters the crawler discovered and tests
whether their values come back into the page in a form a browser could act on.

### The marker is inert

The scanner never sends a working exploit. It sends a random token, four metacharacters, and a
second token:

```
ws4f1a9c3e0b7da"'><ws4f1a9c3e0b7db
└── open ────────┘└──┘└─ close ───┘
                 canary
```

No `<script>`, no event handler, no `javascript:` — nothing that does anything if the target
renders it. What it reveals is which of `"`, `'`, `>` and `<` survive the application's output
encoding, and that is the evidence everything else reasons about.

**Why the canary is bracketed:** whatever the application rendered for those four characters is
*exactly* the text between the two markers. Without brackets, a page that strips the canary would
leave the marker sitting against its own markup, and the `<` of a following `</div>` could be
misread as a surviving metacharacter. This is a real false positive that the bracketing removes
by construction, and there is a test for it.

### Request budget

Per parameter:

| Case | Requests |
| ---- | -------- |
| Parameter is not reflected | **1** — a baseline with an inert alphanumeric token. If it does not come back, the probe is never sent |
| Parameter is reflected | **2** — baseline, then the encoding probe |

No payload lists, no mutation, no retries. Caps: `XSS_MAX_PARAMETERS_PER_ENDPOINT` (8),
`XSS_MAX_ENDPOINTS` (25), `XSS_MAX_REQUESTS_PER_SCAN` (80). `XSS_ENABLED=false` turns it off.

### Context analysis

A deterministic single-pass scan of the markup — **not a browser, and no JavaScript is executed**
— locates the marker and classifies where it landed:

`HTML_TEXT`, `ATTRIBUTE_QUOTED`, `ATTRIBUTE_UNQUOTED`, `EVENT_HANDLER`, `JAVASCRIPT_URI`,
`SCRIPT`, `STYLE`, `HTML_COMMENT`. Inside `<script>`, it also identifies the enclosing string
delimiter, so it can tell whether the canary's quote would break out of it.

### Severity and confidence

**Encoding decides first.** If every metacharacter came back encoded or stripped, there is *no
finding* — in any context.

| Context | Escapes its construct? | Severity | Confidence |
| ------- | ---------------------- | -------- | ---------- |
| Script / event handler / `javascript:` | yes | HIGH | HIGH |
| Script / event handler / `javascript:` | no | HIGH | MEDIUM |
| Unquoted attribute | — | HIGH | MEDIUM |
| Quoted attribute | quote survived | HIGH | MEDIUM |
| Quoted attribute | quote encoded | MEDIUM | LOW |
| HTML text | raw `<` present | HIGH | MEDIUM |
| HTML text | no raw `<` | MEDIUM | LOW |
| HTML comment | yes | INFO | LOW |
| HTML comment | no | *no finding* | — |
| Anything, safely encoded | — | *no finding* | — |

**Nothing is ever CRITICAL**, and a test enforces it. Confidence reaches HIGH only when the
marker demonstrably escapes its enclosing construct. "The bytes are here" is weaker evidence than
"a browser runs this", and the wording of every finding reflects that: findings say an attacker
*may be able to*, never that execution was confirmed.

### What is not stored

The probe marker, the canary and the probe URLs exist only in memory during the scan. Evidence
names the parameter and the context — never a value:

```
A controlled scanner marker supplied in the "q" query parameter was reflected into the
"value" attribute. Metacharacters returned unencoded: `"` `'` `>` `<`.
```

Finding subjects are `parameter:<name>`, so two parameters stay distinguishable while the same
parameter across several endpoints aggregates into one finding with several occurrences.

### Scope

Probes reuse the same transport as everything else, so every existing protection applies
unchanged: URL validation, the SSRF guard, the same-origin lock (re-checked on every redirect),
the request timeout and the redirect limit. Probe URLs are built by substituting one known
parameter's value into an already-validated endpoint — the scheme, host and path are never taken
from anything the target controls.

Only GET query parameters are tested. Forms are discovered but never submitted, and path
parameters are not tested.

---

## Active probe framework (Phase 7)

Active detectors need the same handful of mechanics: a baseline, a controlled probe, bounded
request counts, response comparison, scope enforcement, timeouts, and failure handling that does
not end the scan. Phase 7 extracts those from the XSS detector so the next one does not
reimplement them — and, more importantly, so the safety rules live in exactly one place.

```
Attack surface
      |
ActiveScanModule        picks targets, runs registered detectors
      |
Detector.eligible()     pure filter — no requests are sent for an ineligible target
      |
Detector.probe(engine)
      |
ProbeEngine.send()      SCOPE + BUDGET + TIMEOUT + ERROR HANDLING
      |
HttpFetcher             the same transport the probe and crawler use
      |
RawHttpResponse
      |
detector analyzer       pure interpretation (for XSS: analyzer.py)
      |
detector findings       pure judgement    (for XSS: findings.py)
      |
FindingData -> Aggregator -> database
```

### The detector interface

```python
class ActiveDetector(Protocol):
    name: str
    def eligible(self, target: ProbeTarget) -> Eligibility: ...
    async def probe(self, target: ProbeTarget, engine: ProbeEngine) -> Sequence[DetectorObservation]: ...
```

Two methods, not four. Response interpretation and finding construction are deliberately *off*
the interface: they are pure functions in their own modules that the detector calls. Keeping them
off is what stops network code and judgement code from merging back together.

**A detector receives a `ProbeEngine`, never a transport.** It cannot open a connection, choose a
host, or construct a URL of its own — it names a parameter and a value, and the framework builds
the request. There is no way to write a detector that bypasses the scanner's scope rules.

### Probe budgets

Three nested limits, all enforced in `ProbeBudget` and **shared by every detector in a scan**:

| Setting | Default | Scope |
| ------- | ------- | ----- |
| `MAX_ACTIVE_PROBES_PER_PARAMETER` | 4 | One input on one endpoint |
| `MAX_ACTIVE_PROBES_PER_ENDPOINT` | 24 | All inputs on one endpoint |
| `MAX_ACTIVE_PROBES_PER_SCAN` | 120 | The whole scan, across all detectors |
| `ACTIVE_SCAN_MAX_TARGETS` | 25 | Endpoints considered |
| `ACTIVE_SCAN_ENABLED` | true | Turns off all active probing |

The budget **fails closed**: `reserve()` returns False when any limit is reached, the engine
refuses to send, and a refused reservation consumes nothing. There is no path that treats an
exhausted budget as permission to continue.

### Baseline

The framework does not assume one baseline per test. `ProbeRequest` carries a `purpose`
(`BASELINE` or `PROBE`) and a detector issues whatever sequence it needs. Reflected XSS uses
baseline-then-probe; a future detector needing three baselines is not obstructed.

### Response comparison

Pure, generic utilities in `active/comparison.py`: `status_changed`, `content_type_changed`,
`final_url_changed`, `size_delta`, `timing_delta_ms`, `body_similarity`, `contains_marker`, and
`compare()` which returns all of them as a `ResponseDelta`.

The line is drawn deliberately: `status_changed` belongs to the framework, `is_sql_injection`
belongs to a detector. Keeping vulnerability conclusions out is what lets several detectors share
these without inheriting each other's judgement.

### Scope: unchanged and centralised

Active probes go through the same `HttpFetcher` as everything else, so every protection applies
without being restated: URL validation, the SSRF guard, the same-origin lock re-checked on each
redirect hop, allowed schemes, the redirect limit and the request timeout. The engine adds two
checks of its own — it revalidates the constructed URL before connecting, and rejects a response
whose final URL left the origin.

### Sensitive data

Probe values and markers exist only in memory for the duration of a scan. Nothing from a probe is
persisted: findings carry normalised evidence naming the parameter and the context, never a
value. Logs record the endpoint *path* and the parameter *name* only — never a probe URL, a
probe value, or a request header.

### What uses it

**Only the reflected-XSS detector.** The framework exists to be reused, but at the end of this
phase there is exactly one active detector, and adding another is future work.

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
| GET    | `/api/scans/{scan_id}/findings` | yes | Deduplicated findings with endpoint context and occurrences |
| GET    | `/api/scans/{scan_id}/endpoints` | yes | URLs the crawler reached, with parameter names |
| GET    | `/api/scans/{scan_id}/forms` | yes | Forms found on crawled pages, with their fields |
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
* **Only one vulnerability class is actively tested.** Reflected XSS on GET query parameters.
  The Phase 7 framework is built to carry more detectors, but none exist yet — there is no
  SQL-injection, CSRF, SSRF, IDOR or open-redirect testing.
* **Active probing covers GET query parameters only.** POST bodies, path segments, headers and
  cookies are not probed; extending the input surface is future work.
* **No stored XSS.** A payload that is saved and rendered on a later request is never seen: the
  detector only compares one response to the request that produced it.
* **No DOM XSS, no JavaScript execution, no browser engine.** The analysis is static. A sink
  reached only by client-side script — `innerHTML`, `document.write`, a framework template — is
  invisible. This is the largest blind spot of the current design.
* **No form submission**, so POST parameters and anything behind a form are untested.
* **Path parameters are not tested** — `/products/1` is not probed as an input.
* **Reflection is judged on one response.** An application that encodes differently depending on
  session state, `Accept` header or feature flag may be assessed on only one of its behaviours.
* **Absence of XSS findings does not prove the absence of XSS.** A static reflected-XSS detector
  misses application-specific cases by construction.
* **Analysis covers only what the crawler reached.** Pages behind a login, behind a form, or
  built by JavaScript are never seen, so they are neither analysed nor counted as skipped.
* **Cookies are only observed where they are set.** A cookie issued after authentication is
  invisible to this scanner.
* **No JavaScript.** The crawler parses server-returned HTML only. A single-page application
  that builds its routes at runtime will appear to have almost no attack surface, because no
  browser engine is used and none is planned for this phase.
* **No form submission.** Forms are discovered, never submitted, so anything reachable only
  behind a form — or behind a login — is not crawled.
* **`robots.txt` is not consulted.** Scope is controlled by the explicit target, the same-origin
  rule and the crawl limits instead. Only scan sites you are authorised to test.
* **Same-origin only.** Content on a CDN or an API subdomain is not crawled, even when it is
  part of the same application.
* **No path-parameter inference.** `/products/1` and `/products/2` are recorded as two
  endpoints; the crawler does not generalise them into `/products/{id}`.
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
| 3 | `Finding` model, security-header and cookie analysis | done |
| 4 | Crawler, endpoint / parameter / form discovery | done |
| 5 | Per-endpoint analysis, finding identity, deduplication, coverage | done |
| 6 | Reflected XSS detection on query parameters | done |
| 7 | Reusable active-probe framework; XSS migrated onto it | **done - current release** |
| 8 | TLS inspection, CORS policy, risk scoring | planned |
| 9 | Further active testing: SQL injection, open redirect, API security checks | planned |
| 10 | Reporting and export, background execution for long-running scans | planned |

The attack surface discovered in Phase 4 is what later detectors will consume: endpoints and
their parameters are the injection points an XSS or SQL-injection check needs, and forms are
what a CSRF check examines. Each detector becomes a `ScanModule` behind the protocol already
defined in
`backend/app/scanner/types.py`, registered in the `WebScanner` orchestrator. The API and database
layers do not need to change to accommodate them.

---

## Legal

Only scan systems you own or have explicit written authorisation to test. Unauthorised scanning
may be illegal in your jurisdiction.
