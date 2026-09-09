# Web Scanner

A web application for running and tracking HTTP reconnaissance scans against sites you own.

**This is the Phase 9 release: the reporting layer.** Everything the scanner has recorded is
now available as a single canonical report — an API endpoint, a dedicated results page, and a
downloadable JSON document. Reporting is strictly read-only: generating a report re-runs no
detector, sends no request to the target, and changes nothing about how scanning works.

Phase 8 added the second active detector: A second active
detector runs on the Phase 7 framework, testing discovered GET query parameters for
error-based and boolean-differential SQL injection. It shares the same probe engine, scope
rules and budget as the XSS detector; XSS behaviour is unchanged.

**Detection only — never exploitation.** Every probe is a harmless syntax probe. The scanner
does not extract data, enumerate schemas, run stacked queries, use UNION, use time-based blind
techniques, or issue any write, delete or file operation. Active detection covers **reflected
XSS and SQL injection on GET query parameters**; there is no stored/DOM XSS, CSRF, SSRF, IDOR
or open-redirect detection.

> **The scanner reports signals consistent with SQL injection; absence of a finding does not
> prove an application is not vulnerable.** A conservative static/differential detector misses
> application-specific cases by construction.

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
│       ├── reporting/                 # phase 9, read-only
│       │   ├── types.py              # canonical ScanReport
│       │   ├── builder.py            # rows -> report (pure, deterministic)
│       │   └── service.py            # ownership-scoped loading
│       ├── models/                    # user, scan, finding, attack_surface
│       ├── schemas/                   # auth, user, scan, finding, attack_surface, report, common
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
│           │   ├── xss/               # reflected XSS
│           │   │   ├── types.py       # contexts, encoding states, probe
│           │   │   ├── payloads.py    # inert marker generation
│           │   │   ├── analyzer.py    # context + encoding analysis (pure)
│           │   │   ├── findings.py    # severity/confidence rules (pure)
│           │   │   └── detector.py    # eligibility + probe sequence
│           │   └── sqli/              # SQL injection
│           │       ├── types.py       # error signals, differential signals
│           │       ├── payloads.py    # conservative syntax probes
│           │       ├── analyzer.py    # error signatures + differential (pure)
│           │       ├── findings.py    # severity/confidence rules (pure)
│           │       └── detector.py    # eligibility + probe sequence
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
        │   ├── report/                # summary, coverage, filterable findings
        │   ├── dashboard/             # stat card
        │   └── common/                # page header, empty/error states
        ├── hooks/                     # use-auth.tsx, use-async-data.ts
        ├── lib/                       # api-client.ts, errors.ts, format.ts
        ├── services/                  # auth.service.ts, user.service.ts, scan.service.ts
        └── types/                     # user, scan, finding, attack-surface, report, api
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
.venv\Scripts\python -m pytest          # 776 tests
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
| `test_sqli_analyzer.py` | Error signatures per engine, false-positive control, differential logic |
| `test_sqli_detector.py` | Probe sequence, baseline comparison, budget, scope, content types |
| `test_sqli_integration.py` | SQLi findings inside the existing finding architecture |
| `test_reporting.py` | Report construction, coverage, determinism, authorization, leakage |
| `test_findings_api.py` | Findings API ownership and isolation |
| `test_attack_surface_api.py` | Endpoint/form API ownership and isolation |
| `test_scan_lifecycle.py` | State machine, cancellation, progress, failure isolation |
| `test_authenticated_scanning.py` | Credential validation, origin scope, transport, authenticated discovery, leakage |
| `test_authorization_testing.py` | Policy matching, access comparison, horizontal/vertical/object-level checks, budget, leakage |
| `test_api_discovery.py` | API classification, JSON structure, OpenAPI/Swagger parsing, GraphQL detection, budgets, leakage |
| `test_api_security.py` | Field classification and its false-positive controls, property comparison, verbose errors, CORS, inventory, leakage |

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

## SQL-injection detection (Phase 8)

A second active detector, on the Phase 7 framework. It reuses the probe engine, scope
enforcement, budget and response-comparison utilities unchanged — the SQLi module adds only what
is specific to SQL injection.

### Two conservative techniques

**Error-based.** A lone quote (or unbalanced fragment) is appended to a parameter. A query that
concatenates the value unsafely becomes invalid and the engine emits an error; a parameterised
query treats the same input as data and does not. A finding requires a database-error signature
that is **present under the probe and absent from the baseline** — an error already in the
baseline is not evidence.

**Boolean-differential.** True-like / false-like pairs (`AND 1=1` vs `AND 1=2`, and a quoted
variant) that keep the query valid either way, so only its truth value changes. A finding
requires the true-like probe to track the baseline while the false-like probe diverges
materially — **and the pattern must reproduce** on a second independent attempt. One clean
difference is treated as noise.

### Database error signatures

Signatures are structured (`DatabaseErrorSignature`: family, strength, label, compiled pattern)
and cover MySQL/MariaDB, PostgreSQL, SQL Server, Oracle, SQLite, and generic driver/SQLSTATE
wording. Every pattern is **multi-token** — the bare word "SQL" never matches, and an ordinary
error page without database wording is ignored. The analyzer classifies a body as
`NONE` / `POSSIBLE` / `STRONG` and never draws the vulnerability conclusion itself; the detector
does that by combining the signal with the baseline.

### Content types

Unlike XSS, SQLi is not limited to HTML — an error surfaces in JSON and plain text too, so
`text/*`, `application/json` and `application/xml` responses are all analysed. Binary responses
are skipped. (This phase widened the shared transport to download textual bodies, not only HTML.)

### Rules, severity, confidence

| Rule | When | Severity | Confidence |
| ---- | ---- | -------- | ---------- |
| `SQLI_ERROR_BASED` | Engine-specific error, probe-induced | HIGH | HIGH |
| `SQLI_ERROR_BASED` | Generic driver/SQLSTATE error | HIGH | MEDIUM |
| `SQLI_BOOLEAN_DIFFERENTIAL` | Reproduced true/false divergence | HIGH | HIGH |

**Nothing is CRITICAL.** Timing is never a signal, a status-code change alone is never a signal,
and a size change alone is never a signal. The wording says "consistent with", never "confirmed".

### Safety and budget

The detector reaches the network only through the `ProbeEngine`, so it inherits every Phase 7
protection: URL validation, the SSRF guard, the same-origin lock re-checked on redirects,
allowed schemes, the redirect limit, the request timeout, and the shared `ProbeBudget`. Probe
volume is small and bounded — a baseline, up to two error probes (stopping on the first
baseline-absent error), then boolean pairs only if error-based found nothing, all within the
per-parameter / per-endpoint / per-scan ceilings. A refused probe is not an error and never
creates a finding.

Evidence names the parameter and the database family only. No query, probe value, response
content, cookie or authorization header is ever stored, and `SQLI_ENABLED=false` turns the
detector off.

---

## Reporting (Phase 9)

The scanner records a lot; Phase 9 turns it into something a person can read and a machine can
consume — without a second copy of the data.

```
PostgreSQL (existing tables)
      |
report builder          pure assembly, deterministic ordering
      |
canonical ScanReport    one representation
      |
      |-- JSON API        GET /api/scans/{id}/report
      |-- JSON download   GET /api/scans/{id}/report/json
      +-- report page     /dashboard/scans/{id}/report
```

**One canonical representation.** The API, the page and the download all read the same built
report, so they cannot disagree. A later exporter (PDF, SARIF) plugs in at the same point rather
than querying the database again.

**Read-only.** The reporting layer holds no session of its own, makes no network call, and never
invokes a detector. Requesting a report is free of side effects and returns an identical document
each time.

### Deterministic ordering

Findings sort by **severity descending, then category, then rule id, then subject** — defined in
the report layer, never inherited from database row order. Two reports built from the same stored
rows are byte-identical, which is what makes the JSON diffable and safe for a CI check.

### Coverage is part of the verdict

A report never presents "no findings" as "secure". `coverage.is_complete` is true only when every
discovered endpoint was analysed or deliberately skipped, with no analysis failures. The UI wording
follows it:

| Situation | What the report says |
| --------- | -------------------- |
| Findings recorded | "N findings recorded — highest severity …" |
| No findings, full coverage | "No findings from the checks performed" — plus an explicit note that this is not proof of security |
| No findings, partial coverage | "No findings, but coverage was incomplete" — treated as inconclusive |
| Scan failed | "The scan did not complete" — no conclusion can be drawn |
| Scan running | "This scan is still running" — not final |

Endpoints that failed analysis are called out separately: their state is *unknown*, not clean.

### API

| Method | Path | Description |
| ------ | ---- | ----------- |
| GET | `/api/scans/{scan_id}/report` | The canonical report as JSON |
| GET | `/api/scans/{scan_id}/report/json` | The same document with a `Content-Disposition` attachment header |

Both require authentication and resolve ownership through the same user-scoped lookup as every
other scan endpoint — another user's scan returns **404, not 403**, so the endpoint does not
confirm that a scan exists. A test asserts the 404 body does not contain the scan id.

### Report contents

Metadata (target, status, start/end, duration, generated-at), coverage counters, severity
summary, per-category groups, the attack-surface summary, discovered parameter **names**, and for
each finding: rule id, category, severity, confidence, title, description, impact, remediation,
normalised evidence, occurrence count and every affected endpoint.

### What a report never contains

There is **no field** in the report schema for a cookie value, an authorization header, a
credential, a request body, a probe value, an injected payload or a reflected marker — a secret
has nowhere to go. Evidence is the detectors' own normalised wording, which names parameters,
contexts and database families rather than values. Endpoint URLs are the canonical form carrying
parameter names only. Report contents are never logged. Tests assert all of this against a live
report body.

### Frontend

`/dashboard/scans/{id}/report` presents an executive summary, the verdict, severity overview,
coverage and attack surface, and a filterable findings list (by severity, category and
confidence) with expandable detail. "Download JSON" saves the canonical document.

---

## Scan execution lifecycle (Phase 10)

Phase 10 adds no detector. It makes the *running* of a scan a first-class thing: an explicit
state machine, cooperative cancellation, honest progress, and a guarantee that a scan always
reaches a terminal state.

### States

```
QUEUED  -->  RUNNING  -->  COMPLETED
   |            |------->  FAILED
   |            \------->  CANCELLED
   |--------------------->  FAILED
   \--------------------->  CANCELLED
```

`COMPLETED`, `FAILED` and `CANCELLED` are terminal and have no outgoing edges: once a scan stops
it stays stopped. Every status change goes through `services/scan_lifecycle.py::transition`,
which raises `409 invalid_scan_transition` for anything illegal, so a finished scan cannot be
restarted and a completed scan cannot be relabelled as cancelled.

`PENDING` was renamed to `QUEUED` in migration `0008` so the database and the state machine share
one vocabulary. `CANCELLED` was added to the same enum.

### Units of work: no transaction spans network I/O

A scan issues HTTP requests for as long as the target and the budgets allow. Holding a session
open across that would pin a pooled connection and an idle-in-transaction row lock for the entire
run. `create_scan` is therefore split:

| Step | Session | What it does |
| ---- | ------- | ------------ |
| `enqueue_scan` | the request's | INSERT the row as `QUEUED`, commit |
| `_claim` | its own, short | `SELECT ... FOR UPDATE`, `QUEUED -> RUNNING`, commit |
| the scan itself | **none** | crawl, analyse, probe |
| `_finish` | its own | report, attack surface, findings and summary in one transaction |
| `_mark_failed` | its own, fresh | only when something raised |

The claim is conditional: a scan that is not `QUEUED` is not claimed, which is what stops the
same scan being executed twice. `_finish` writes everything in a single transaction, so a scan is
never visible as `COMPLETED` with its findings missing.

Any exception between the `RUNNING` commit and the final commit is caught and settled as
`FAILED`. A rollback could not have fixed this - the `RUNNING` status was already committed - so
the failure path opens a *new* session and closes the scan out. A scan cannot be left `RUNNING`
forever because something raised.

### Cancellation is cooperative

Nothing is killed. No thread is interrupted, no process is terminated, no task is force-cancelled.

`POST /api/scans/{scan_id}/cancel` sets a flag. The running scan reads that flag at safe
boundaries and stops itself:

| Boundary | Why there |
| -------- | --------- |
| between pipeline modules | nothing is in flight and the report is consistent |
| before each crawler fetch | guarantees no new traffic reaches the target |
| before each analysed endpoint | every endpoint is either fully assessed or untouched |
| before each probe target | between detectors, not inside one |
| inside `ProbeEngine.send`, before the budget is spent | no probe escapes mid-detector |

The scanner never learns *how* the flag is stored. `scanner/cancellation.py` holds a pure
`CancellationToken` built from a plain predicate; `services/cancellation.py` supplies a predicate
that reads the database. That keeps the scanner package free of `app.models`, as in every earlier
phase.

The database-backed token opens **its own short-lived session** per check - a running scan must
not read the flag through a session it also holds for writes - and throttles reads to one every
1.5 seconds, so the query count stays proportional to elapsed time rather than to pages crawled.
Once cancellation is seen the token latches. A cancellation check that *fails* returns "not
cancelled": a broken check must never end a scan that nobody asked to stop.

### A cancelled scan is not a failed scan, and not a clean one

Cancellation is a normal outcome. A cancelled scan carries no `error_message` and no
`failure_stage`, and it keeps everything it gathered: the probe result, the pages crawled before
the stop, the endpoints analysed, the findings already aggregated. The crawler records what was
still queued as `CANCELLED` skips, so the gap in coverage is visible rather than silent.

It is also never presented as a pass. `report.metadata.is_conclusive` is true only for a scan
that ran to completion, and `coverage.scan_completed` false forces `coverage.is_complete` false
regardless of what the counters say - a scan cancelled just after analysing everything it had
discovered still did not finish looking. The results page says so in words, too.

### Progress is coarse and honest

The crawler discovers its own workload as it goes, so no true percentage exists. The scan
reports a **stage**, and the percentage attached to it is an explicitly indicative milestone:

| Stage | Indicative | Meaning |
| ----- | ---------: | ------- |
| `QUEUED` | 0 | Created, not started |
| `INITIALIZING` | 5 | Claimed, about to run |
| `PROBING` | 15 | Fetching the target |
| `CRAWLING` | 40 | Discovering pages and inputs |
| `ANALYZING` | 70 | Analysing endpoints and running detectors |
| `AGGREGATING` | 85 | Grouping findings |
| `FINALIZING` | 95 | Saving results |
| `COMPLETED` / `FAILED` / `CANCELLED` | 100 | Terminal |

Stage writes go through their own short transaction and are conditional on the scan still being
`RUNNING`, so a progress update can never resurrect a scan that has already stopped. The stage is
a validated string rather than a native enum: stages are presentation detail and will change more
often than the status set, and `ALTER TYPE` per stage is friction for no gain.

### Failure detail never leaks internals

A scan that fails unexpectedly stores a fixed message and the stage it was in. The exception is
logged with its traceback server-side; nothing derived from it reaches a user-visible field,
where it could carry a connection string, a header, a token or an internal path. `failure_stage`
is safe by construction: it is a name from a fixed vocabulary.

### Frontend

* Plain polling every 3 seconds - no WebSocket, no SSE - and only while something on the page can
  still change. Once every scan shown is terminal the interval stops entirely. Ticks are skipped
  while the tab is hidden.
* The polling refetch is silent, so a live scan updates in place instead of flashing skeletons.
* A stop button on running scans, with a confirmation that says results will be partial.
* The badge reads **Stopping...** between the request and the scan actually stopping. The UI never
  claims a cancellation the backend has not confirmed.
* Live elapsed time, the current stage, and an indicative progress bar labelled as such.
* `CANCELLED` has its own colour, distinct from both success and failure, everywhere it appears.

### API

| Method | Path | Description |
| ------ | ---- | ----------- |
| POST | `/api/scans/{scan_id}/cancel` | Ask a scan to stop |

Owner-only: another user's scan id returns `404`, never `403`. Cancelling a queued scan stops it
outright and returns `CANCELLED`. Cancelling a running scan returns the row **as it is** -
`RUNNING` with `cancel_requested` true - because the stop has not happened yet. Cancelling an
already-cancelled scan succeeds; cancelling a scan that finished returns `409`.

### Single-process execution

Scans still run inline in the request that created them, inside FastAPI's threadpool. This phase
deliberately added no Redis, no Celery, no queue and no worker service. The consequences are:

* `POST /api/scans` blocks for the duration of the scan, bounded by
  `SCANNER_TOTAL_TIMEOUT_SECONDS`.
* Cancellation must come from a *different* request - which works, because the scan holds no
  session or row lock while it runs.
* A process restart mid-scan leaves that scan `RUNNING` in the database with nothing to finish
  it. There is no reaper; it would need one, or a worker, to be corrected automatically.
* Throughput is bounded by the threadpool, not by any scheduler.

The unit-of-work split above is what makes moving execution onto a worker later a change of
caller rather than a change of schema.

---

## Authorized authentication-aware scanning (Phase 11)

A scan can carry credentials the user already holds for an application they are authorized to
test, so the crawler and the existing detectors reach the pages behind its login.

Phase 11 adds no detector. It adds a *request context*.

### Two different things called authentication

| | What it is | Where it lives |
| --- | --- | --- |
| **Scanner-user authentication** | The JWT session cookie that says who is using this application | `app/core/security.py`, unchanged since phase 1 |
| **Target authentication** | A credential the user supplies so a scan can reach their own protected pages | `app/scanner/auth/` |

They never mix. The scanner-user session authorises the *request that creates a scan*; the target
credential is data inside that request.

### What the scanner does not do

It never discovers, guesses, brute-forces, stuffs, cracks, refreshes or renews a credential. It
never submits a login form, never bypasses authentication, never hijacks or fixates a session and
never automates a sign-in workflow. It presents material it was given, and that is all.

Password login automation, OAuth, SAML, MFA and browser-driven flows are deliberately absent:
each is an interaction *with* an authentication system rather than the presentation of material
the user already holds.

### Supported modes

| Mode | What the user supplies | What is sent |
| ---- | ---------------------- | ------------ |
| `NONE` | nothing | nothing — an ordinary anonymous scan |
| `BEARER_TOKEN` | an access token | `Authorization: Bearer <token>` |
| `COOKIE` | one or more name/value pairs | `Cookie: name=value; ...` |

One authentication context per scan. Multi-user, role-comparison and privilege-escalation testing
are **not** implemented — see the limitations below.

### Authentication belongs to the transport

```
AuthenticationContext
        |
   HttpFetcher          <- the one place a credential becomes a header
    /        \
Crawler    ProbeEngine
                |
        XSS / SQLi detectors
```

`HttpFetcher._send` attaches the headers; nothing else in the codebase constructs an
`Authorization` or a `Cookie` header. The crawler and the probe engine each build a fetcher and
therefore inherit the context, and the detectors inherit it from the engine without knowing it
exists. Their interface is untouched:

```python
eligible(target)            # unchanged
probe(target, engine)       # unchanged
```

That is what makes an authenticated XSS or SQLi check free: no detector was modified, and a
future detector is authenticated the day it is written.

Because one fetcher serves the whole active stage, a detector's baseline and its probes always
carry the same context. Comparing an authenticated baseline against an unauthenticated probe
would manufacture a difference and therefore a finding, so the two can never diverge.

### Authentication never widens scope

The context is bound to the origin of the URL the user asked to scan, fixed when it is built:

```python
def applies_to(self, url):
    return is_same_origin(url, self.origin)   # exact scheme, host and port
```

`headers_for` returns nothing for any other URL. A different host, a subdomain, a different
scheme and a different port are all different origins, so the credential is simply not offered.

Every phase 1-10 protection is unchanged: URL validation, the SSRF guard, the http/https-only
rule, the same-origin crawl, the per-hop redirect re-validation, the redirect limit, timeouts and
the response-size cap. Two independent things now protect a credential during a redirect:

* Where a scope lock is set — the crawler, the probe engine, the access check — an off-origin hop
  is **refused outright** and never requested.
* The seed probe still follows redirects anywhere, as it has since phase 2, but the context hands
  out nothing for the new origin, so the hop goes out as an ordinary anonymous request.

A credential cannot follow a redirect off the authorized origin under either path. Both are
covered by tests, and by a live check that reads back what a second origin actually received.

### Secrets are never persisted

There is no column, anywhere, for a token or a cookie value.

A credential arrives in the create request, becomes an in-memory `AuthenticationContext`, is
passed down the call stack into the scanner, and is gone when the call returns. Two facts are
written to the `scans` row and nothing else:

```
auth_mode    NONE | BEARER_TOKEN | COOKIE
auth_status  NOT_CONFIGURED | AVAILABLE | REJECTED | UNKNOWN
```

Passing the context as an argument, rather than keeping it in a registry, is deliberate: its
lifetime is the lifetime of the call, so nothing has to remember to clear it. **This is what ties
authenticated scanning to inline execution.** Moving scans to a worker would put an execution
boundary between the request and the scan, and the credential would have to survive it — which
would mean storing it somewhere. That trade is documented rather than taken.

Practically, Python offers no guaranteed erasure: strings are immutable and their memory is
reclaimed by the garbage collector whenever it runs. The honest claim is that no reference is
retained after the scan, not that the bytes are wiped.

`AuthenticationContext` and `CookieCredential` also refuse to render. `repr`, `str` and any
f-string produce `secret=<redacted>`, so a stray `%s`, a debug print or an exception repr cannot
leak a credential. On the request side, pydantic `SecretStr` gives the same protection in
validation errors and JSON dumps.

### Input validation

The threat is header injection: a CR or LF in a credential would end the header and let the rest
be read as further headers. Rejecting is the only safe answer — sanitising by stripping would
silently alter a credential the user believes they supplied.

| | Rule |
| --- | --- |
| Token | non-empty, at most 8192 characters, printable ASCII only, no CR/LF/NUL/space/tab, not already prefixed with `Bearer` |
| Cookie name | RFC 6265 token characters, at most 256 characters, unique within the set |
| Cookie value | RFC 6265 `cookie-octet`, at most 4096 characters; a quoted value is allowed |
| Cookie set | at least one, at most 20, at most 8192 characters assembled |

Outer whitespace is trimmed from a token — a token pasted from a terminal arrives with a trailing
newline, and that is not part of the credential. Cookie **values** are never normalised: a signed
or encrypted session cookie is one opaque string, and trimming or re-encoding it would break the
signature and turn a working credential into an unexplained 401.

No validation message ever repeats the value it rejected.

### The initial access check

One GET, to the URL the user asked to scan, carrying the material they supplied, before the crawl
starts. It exists to say whether the credential looks usable — not to attack anything. No URL is
guessed, no login endpoint is probed, nothing is retried or refreshed, and no target state is
modified. An unauthenticated scan skips it entirely and issues no request at all.

| Result | Meaning |
| ------ | ------- |
| `NOT_CONFIGURED` | No credential was supplied |
| `AVAILABLE` | The target answered without refusing it |
| `REJECTED` | 401, 403, or a redirect onto a sign-in page |
| `UNKNOWN` | Unreachable, a server error, or an answer that says nothing either way |

The check reads where the target *sent* the scan; it never guesses where a login page might be. A
site whose home page simply is `/login` is not called rejected, because no redirect happened.

`AVAILABLE` is a narrow claim: one request, at one moment, was not refused. It is not a statement
that the credential is valid for every path or for the rest of the scan — a session can expire
mid-scan, and the report never claims otherwise.

### A refusal is not a vulnerability, and not a clean result

A 401 or a 403 is an access decision. It is never turned into a finding.

Nor is it allowed to read as success. When credentials were supplied and refused, the scan
covered only the anonymous surface, so:

* `metadata.is_conclusive` is false,
* `coverage.authentication_usable` is false, which forces `coverage.is_complete` false regardless
  of what the counters say,
* the report leads with "The target refused the credentials supplied", and the results page says
  the same.

Counters alone would happily report "everything discovered was analysed". Everything discovered
by a visitor who never got in.

### Reporting

```json
"authentication": { "mode": "COOKIE", "status": "AVAILABLE",
                    "authenticated": true, "confirmed": true }
```

There is no field for a token, a cookie value, an `Authorization` header or a `Cookie` header —
the report's leakage guarantee is structural, not a matter of remembering to redact. Coverage
wording states which surface was reached: results reflect the endpoints reachable with the
context supplied, and no other user, role or permission level was tested.

### Frontend

The create form offers None / Bearer token / Cookies. Every secret field is `type="password"`
with autocomplete off, switching mode discards the material for the mode being left, and the
draft is cleared in a `finally` — on success, on rejection and on network failure alike.

Nothing is written to `localStorage`, `sessionStorage`, a cookie or a query string; nothing is
logged; and no credential is ever read back, because the API has nothing to return it from. The
scan detail page and the report show the mode and the status, never the material.

### Logging

Log lines carry the scan id, the target origin, the auth mode, the status and the stage. Never a
token, a cookie value, an `Authorization` header, a `Cookie` header or a secret-bearing
exception. A test asserts that an authenticated run emits no credential at any level down to
`DEBUG`.

### API

```json
POST /api/scans
{
  "target_url": "https://app.example.com",
  "authentication": { "mode": "BEARER_TOKEN", "token": "..." }
}
```

or

```json
{ "authentication": { "mode": "COOKIE",
                      "cookies": [{ "name": "session", "value": "..." }] } }
```

Credentials are accepted only on an authenticated scanner-user request, and only in the body.
Malformed material is a `422` on the request, not a failed scan. The response — like every scan
response — carries `auth_mode`, `auth_status` and a grouped `authentication` object, and no
credential.

---

## Authorized authorization and access-control testing (Phase 12)

Phase 11 taught the scanner to sign in as one identity. Phase 12 gives it
several and asks a different question: **can one of them reach what belongs to
another?**

Broken access control is not something a single response reveals. A 403 might be
a working check or a broken route; a 200 might be a private record or an empty
list. Meaning comes only from comparison, so everything below is comparative.

### The rule that governs the whole feature

A finding requires **all three** of:

1. a declared expectation of `DENIED` for this identity and resource,
2. a reference identity that was actually served the resource, and
3. the subject receiving *materially the same content* as that reference.

Drop any one and the result is `UNKNOWN`, and `UNKNOWN` is never a finding.

That is not timidity. Without (1) the scanner would be inventing an
application's business rules; without (2) it does not know what "the resource"
even looks like; without (3) a 200 carrying a shared page template reads as a
data leak. Authorization scanners are notorious for noise, and each of those
three is one of the ways they generate it.

### What the scanner does not do

It does not create accounts, register users, guess usernames, passwords or role
names, brute-force identifiers, or attack authentication in any way. Every
identity is handed to it. Phase 11's prohibitions carry over unchanged, and
Phase 12 adds no way around them.

It also does not enumerate. There is no `1..100000` loop and no path
brute-forcer: the resources tested are the ones the crawler already reached plus
the ones the authorized user named in the policy.

### Identities

An `AuthorizationContext` is a label, an optional role, a privilege rank, and a
phase-11 `AuthenticationContext`. It wraps the existing credential handling
rather than repeating it, so every request still goes through the one transport
that applies credentials, and every secret still lives in the object that
refuses to render itself.

| Field | Meaning |
| ----- | ------- |
| `id` | Stable identifier the policy refers to. Not a secret. |
| `display_name` | What appears in the report. |
| `role_label` | Free text such as USER or ADMIN. **Metadata only** — the scanner attaches no meaning to the word "admin". |
| `privilege_rank` | Higher is more privileged. Used *only* to tell a vertical comparison from a horizontal one, never to decide what should be allowed. |

The anonymous identity is added by the scanner and carries no credential, so
"is this protected at all?" is always answerable.

### The declared policy

The scanner cannot read an application's authorization rules out of its HTTP
traffic, so it does not try. The policy is supplied:

```json
"rules": [
  {"context_id": "alice", "resource": "/admin/*",  "expected": "DENIED"},
  {"context_id": "admin", "resource": "/admin",    "expected": "ALLOWED"}
],
"ownership": [
  {"resource": "/api/orders/101", "owner": "alice"},
  {"resource": "/api/orders/102", "owner": "bob"}
]
```

Matching is on the URL **path**, exact or with one trailing `*`. No regular
expressions: a policy language a user can get subtly wrong is worse than one
that only does the obvious thing. The most specific rule wins, so `/admin/*`
denied can be overridden by `/admin/health` allowed.

**Ownership** is the shortcut that makes object-level testing practical. Naming
an object's owner implies that the owner may read it and that peers may not,
without the user writing a rule per identity per object.

One nuance worth knowing: an ownership-derived denial is **not** applied to an
identity that outranks the owner. Most applications intend an administrator to
be able to read a customer's order, and deciding otherwise would be the scanner
inventing a business rule. A user who does want that boundary tested writes it
as an explicit rule, which always takes precedence.

### What gets compared

| Comparison | Question |
| ---------- | -------- |
| `ANONYMOUS` | Did a request with no credential receive protected content? |
| `HORIZONTAL` | Did one identity receive another's resource at the same privilege level? |
| `VERTICAL` | Did a lower-privilege identity receive a higher-privilege resource? |
| `OBJECT_LEVEL` | Did an identity receive an object whose declared owner is someone else? |

Observation and expectation are recorded separately on every test, so a reader
can always see whether a verdict rests on a declared policy or on nothing:

```
AuthorizationObservation
  context / reference / url
  expected:  ALLOWED | DENIED | UNKNOWN
  observed:  ALLOWED | DENIED | INCONCLUSIVE
  verdict:   MATCHES_POLICY | VIOLATION | CONFLICT | UNKNOWN
```

`CONFLICT` — expected allowed, observed denied — is reported but never becomes a
finding. Failing closed is not a vulnerability; it does mean the declared policy
and the application disagree, and somebody should find out which is wrong.

### Deciding what a response means

Two separate questions, because neither answers the other.

**Did this identity get in?** 401, 403, 404 and 405 are refusals. A redirect
landing on a sign-in page is a refusal expressed as a redirect. 2xx is access.
Anything else — 5xx, an unresolved redirect — is `INCONCLUSIVE`, because only
`ALLOWED` can contribute to a finding and ambiguity must not.

**Did two identities receive the same thing?** All of:

* same status,
* same media type,
* a body long enough for similarity to mean anything (two 20-byte error pages
  are always "similar"; concluding from that flags every site with a consistent
  denial page),
* and a normalised-body match at or above 0.95.

Timestamps, UUIDs and long hex blobs are collapsed before comparison, so a
request id rendered into an otherwise identical page does not hide a match.

**Timing is not used and never will be.** Network variance dwarfs application
variance; treating it as an authorization signal manufactures findings out of
noise.

### Read-only, and bounded

Only `GET` is sent. No `POST`, `PUT`, `PATCH` or `DELETE` is issued to test
authorization, so a scan cannot change the state of the application it is
measuring. Where an authorization boundary exists only on a state-changing
operation, it is simply not tested — the scanner says nothing rather than
causing a side effect to find out.

Cost is identities x endpoints, which is why the budget matters more here than
anywhere else in the scanner. It fails closed: the reservation happens before
the request, so exhaustion means no request rather than one more.

| Limit | Default | Setting |
| ----- | ------: | ------- |
| Identities | 4 | `AUTHZ_MAX_CONTEXTS` |
| Endpoints tested | 100 | `AUTHZ_MAX_ENDPOINTS` |
| Comparisons per endpoint | 8 | `AUTHZ_MAX_COMPARISONS_PER_ENDPOINT` |
| Requests, whole stage | 400 | `AUTHZ_MAX_REQUESTS` |

Each identity gets its own HTTP client. Sharing one would share its cookie jar,
and a `Set-Cookie` from the target could then be replayed as another identity's
request — silently invalidating every comparison drawn afterwards. The jar is
cleared before each request as well.

### Nothing here weakens scope

Every request goes through the same `HttpFetcher` as the rest of the scanner.
There is no authorization transport. URL validation, the SSRF guard, the
http/https-only rule, the exact-origin lock, per-hop redirect re-validation,
redirect limits, timeouts and the response cap all apply unchanged, and each
identity's credentials are bound to the scanned origin exactly as in phase 11.

Cancellation is honoured before each resource, before each identity switch and
before each request, so a cancelled scan starts no further authorization
traffic.

### Nothing private is retained

A response is reduced to a `ResponseFingerprint` — status, media type, byte
length, a truncated digest of the normalised body, and the final path. No
substring of a body survives, so a private record cannot reach a finding, a
report or a log through this path.

Findings therefore carry the resource, the requesting identity, the expected and
observed access, and that fingerprint summary. Never a token, a cookie, a header
or a line of response content.

### Findings

| Rule | Severity | Confidence |
| ---- | -------- | ---------- |
| `AUTHZ_ANONYMOUS_ACCESS` | HIGH | HIGH when the content matches the reference, else MEDIUM |
| `AUTHZ_HORIZONTAL_ACCESS` | HIGH | as above |
| `AUTHZ_VERTICAL_ACCESS` | HIGH | as above |
| `AUTHZ_OBJECT_LEVEL_ACCESS` | HIGH | as above |

All four are category `AUTHORIZATION` and go through the same aggregation,
occurrence tracking and reporting as every other finding — there is no separate
authorization pipeline. The subject is `identity:url`, so two identities
reaching one resource stay separate findings rather than merging into one that
hides which boundary failed.

One deliberate suppression: when an anonymous request already reached a
resource, authenticated identities reaching it too are the same defect seen
again. The anonymous finding is kept — "no credential was needed" is the most
useful way to say it — and the rest remain as observations.

### Coverage

Authorization coverage is reported separately from authentication coverage,
because a scan can authenticate perfectly and test no access control at all:

```json
"authorization": {
  "enabled": true, "contexts": 4,
  "context_labels": ["Anonymous", "alice", "bob", "admin"],
  "endpoints_eligible": 12, "endpoints_tested": 12,
  "comparisons": 48, "unknown": 20, "skipped": 0, "failed": 0,
  "has_policy": true
}
```

`unknown` is the number to read first, and `has_policy` is the one that decides
the wording. Three states are kept strictly apart, because conflating them is
how a scanner misleads:

* **not enabled** — nothing here says anything about access control;
* **enabled, `has_policy` false** — access was compared, but nothing was
  declared, so every comparison is unknown and none of it is a pass;
* **enabled, `has_policy` true** — comparisons were measured against declared
  expectations, and only this can support "no access-control problems found".

Even then the report says what it means: results cover the supplied identities
and resources only, and no other user, role or permission level was tested.

### API

```json
POST /api/scans
{
  "target_url": "https://app.example.com",
  "authorization": {
    "enabled": true,
    "include_anonymous": true,
    "contexts": [
      {"id": "alice", "label": "Alice", "role": "USER", "privilege_rank": 0,
       "authentication": {"mode": "BEARER_TOKEN", "token": "..."}},
      {"id": "admin", "label": "Admin", "role": "ADMIN", "privilege_rank": 10,
       "authentication": {"mode": "COOKIE",
                          "cookies": [{"name": "session", "value": "..."}]}}
    ],
    "rules": [{"context_id": "alice", "resource": "/admin/*", "expected": "DENIED"}],
    "ownership": [{"resource": "/api/orders/101", "owner": "alice"}]
  }
}
```

Credentials are accepted only on an authenticated scanner-user request and only
in the body. A malformed identity or a rule naming an identity that was not
supplied is a `422` on the request, not a failed scan — silently dropping such a
rule would leave a boundary the user believes is under test.

### Database

Two things were added and neither is secret: an `AUTHORIZATION` value on the
`finding_category` enum, and coverage counters plus the user-chosen identity
labels on `scans`. Credentials follow phase 11 exactly — memory for the length
of the scan, never a column, never a row.

---

## API discovery and attack-surface intelligence (Phase 13)

Phase 13 answers a question the earlier phases could not: **which of this
target's endpoints are APIs, and how do we know?**

It is reconnaissance. It adds no vulnerability detector, exploits nothing, and
invokes nothing. An endpoint appearing in the API inventory means the scanner
believes it behaves like an API — not that it is vulnerable, and not that it is
safe. API classification is an input to the existing detectors, never a verdict
of its own.

### Evidence, in order of trust

1. **What the response was.** `application/json`, `application/problem+json`,
   `application/vnd.example.v2+json`, `application/xml` — the endpoint telling
   us what it is. Nothing outranks that, and it is HIGH confidence.
2. **What a specification said.** Corroboration from a document the target
   published. Strong, but it describes intent rather than behaviour: MEDIUM.
3. **What the URL looks like.** `/api/`, `/v1/`, `/rest/`, `/graphql`. A naming
   convention, and naming conventions are wrong all the time: LOW on its own.

**LOW is not an API.** A page at `/api/about` that returns HTML is a web page
with an unfortunate URL, and counting it would make "14 API endpoints" mean
nothing. The rejection is recorded and explained rather than silently dropped.

One rule follows from the ordering and is worth stating plainly: **an
observation beats a document that contradicts it.** If the crawl watched a path
serve HTML, a specification listing that same path does not resurrect it. The
document describes what someone intended; the response describes what happens.

A body that parses as JSON upgrades a missing or wrong `Content-Type`, because
an API that forgets its header is still an API.

### Observed, documented, inferred

Three states, deliberately never added together:

| | Meaning |
| --- | --- |
| **Observed** | The scanner requested it and something answered. |
| **Documented** | A specification says it exists. Nobody checked. |
| **Documented only** | Described and never reached — not shown to exist at all. |

`endpoints_observed` and `endpoints_documented_only` are separate counters, and
the report says which is which on every row. Collapsing them is how an API
inventory ends up describing operations that do not exist.

### Identity

`(method, path)`, with query values excluded. `/api/products?id=1` and
`?id=2` are one endpoint with a parameter called `id` — the only representation
that stays finite on a real site. A second discovery of the same operation
**adds** to the first: sources union, confidence takes the stronger, the
observed URL and the documented parameter list both survive. Overwriting would
discard the very evidence that makes a record trustworthy.

### JSON structure without JSON content

The scanner wants to say "this endpoint returns objects with `id`, `email` and
`role`", because that describes the interface being assessed. It must never say
what was *in* those fields, because that is where the customer's email address,
the session identifier and the API key live.

So a JSON response is reduced to a `JsonShape`: a top-level type, a bounded list
of field **names**, a depth and a count. Values are read while walking the
structure and discarded with the parsed document.

The summary is computed at the one moment the body is still in hand and about to
be dropped — inside the crawler's capture step — so it costs no extra request,
and `CapturedResponse` continues to hold no body. Both breadth and depth are
bounded and say when they stopped, so a truncated field list is never mistaken
for a whole interface. The call is wrapped: one unparseable body must not end a
crawl that has already gathered fifty pages.

### Specification discovery

A small fixed set of conventional paths on the origin already being scanned:

```
/openapi.json   /swagger.json   /api-docs   /api/openapi.json
/api/swagger.json   /v1/openapi.json   /swagger/v1/swagger.json
/.well-known/openapi.json
```

Eight paths published by frameworks — **not a wordlist, and not the start of
one.** There is no directory brute-forcer in this phase and there is not meant
to be. `API_MAX_DOCUMENT_CANDIDATES` caps how many of the list are tried; it
does not supply more, and `API_FETCH_DOCUMENTS=false` turns the traffic off
entirely while leaving classification working.

OpenAPI 3.x and Swagger 2.0 are both read: paths, methods, operation ids,
parameters with their `in` location and requiredness, request and response media
types, and declared security schemes. Parsing is total — a malformed or hostile
document yields a partial result rather than an exception, because a target's
broken JSON is not a reason to fail a scan. Path and parameter counts are
bounded, and a document that hit a bound says so.

**Nothing described by a specification is executed.** A documented `POST` or
`DELETE` is recorded as an operation and never sent. Security schemes are
metadata: learning that an API expects a bearer token does not make the scanner
construct one, prompt for one, or try one.

### GraphQL: presence, not exploitation

Detected from the conventional path, from a GraphQL media type, or from the
error envelope a server returns to a request it cannot serve. A plain `GET` to
`/graphql` is enough — a GraphQL server answers one with an error that
identifies it.

**No introspection query is run. No query is sent. No mutation is sent. No field
is guessed.** `introspection_tested` is reported as `false` explicitly, so a
reader is never left to assume the scanner looked.

### Authentication status, conservatively

| Status | When |
| ------ | ---- |
| `ANONYMOUS_ACCESSIBLE` | 2xx on an unauthenticated scan |
| `AUTHENTICATED_ACCESSIBLE` | 2xx while the scan was authenticated |
| `AUTH_REQUIRED` | 401 |
| `UNKNOWN` | everything else |

A **403 yields UNKNOWN**, deliberately. It is returned for authorization
failures, CSRF checks, IP restrictions and unsupported methods at least as often
as for a missing credential. And a 2xx says which identity got in, never that
another one would have been refused — Phase 12 answers that by actually
comparing identities.

### Integration, not duplication

* **Phase 11.** Documentation discovery and authenticated crawling reuse the
  existing `AuthenticationContext`. An authenticated scan sees the APIs behind
  the login, and the credential is bound to the scan origin exactly as before.
* **Phase 12.** Authorization testing keeps referring to paths, so an API
  operation is represented once. No second identity system, no duplicate rows.
* **Phases 6 and 8.** XSS and SQLi are untouched. An API endpoint stays eligible
  for them under exactly the rules those detectors already had. API
  classification never implies `API == vulnerable` or `API == safe`.
* **Transport.** Every request goes through the same `HttpFetcher`. URL
  validation, the SSRF guard, the exact-origin lock, per-hop redirect
  re-validation, redirect limits, timeouts and the response cap all apply
  unchanged. There is no API transport.

Cancellation is honoured before each documentation candidate, and a cancelled
scan keeps the classification it had already derived.

### Storage

`api_endpoints` links to the crawl row it was observed on, and a documented-only
operation simply has none — that absence *is* the record of nobody having
requested it. Writing documented operations into `endpoints` instead would
inflate the crawl counters, enter the analysis-coverage totals, and make them
eligible for authorization comparison against resources that may not exist.

No column holds a response body, a parameter value, a credential or a header.
`json_field_names` holds names.

| Limit | Default | Setting |
| ----- | ------: | ------- |
| Documentation candidates | 8 | `API_MAX_DOCUMENT_CANDIDATES` |
| Paths read per specification | 500 | `API_MAX_PARSED_PATHS` |
| API endpoints per scan | 500 | `API_MAX_ENDPOINTS` |
| Parameters per endpoint | 50 | `API_MAX_PARAMETERS_PER_ENDPOINT` |
| JSON field names kept | 50 | `API_MAX_JSON_FIELDS` |
| JSON depth walked | 6 | `API_MAX_JSON_DEPTH` |

### API

```
GET /api/scans/{scan_id}/api-endpoints
```

Returns the endpoints, any specifications read, and the coverage summary. The
report carries the same under `coverage.api`, including the endpoint table with
`observed` and `documented_only` on every row.

### What Phase 13 does not do

**It does not test APIs.** It says which endpoints are APIs and how they were
found. There is no API fuzzing, no automatic `POST`/`PUT`/`PATCH`/`DELETE`, no
request body, no GraphQL query or mutation, no identifier enumeration and no
path brute-forcing.

**A specification is not an inventory of what works.** An operation listed in
OpenAPI has not been shown to exist, and the report never implies the scanner
tested every operation a document happens to mention.

**Discovery is not exhaustive.** What is found is what a same-origin crawl
reached plus what the target published at a conventional path. An API with no
links to it and no published specification will not appear.

---

## API security baseline and sensitive data exposure (Phase 14)

Phase 13 built an inventory of a target's APIs. Phase 14 reads those same
responses for weaknesses — and reads is the operative word. **It sends nothing.**

Every input already exists by the time this stage runs: the field names Phase 13
summarised, the headers the crawler kept, error signals computed at capture, and
the per-identity responses Phase 12 gathered while comparing access. A stage that
generated traffic to find these things would be fuzzing, and this phase does not
fuzz, does not provoke errors to read them, and does not send a single request of
its own.

### The rule that governs the phase

**A field being present is not proof of a vulnerability.** Whether an API should
return `phone` depends on what the application is for, and a scanner cannot know
that. So three things are kept apart that are easy to blur:

* **What was observed** — this field name appeared in this response.
* **How sensitive the field is** — a property of the name, not of the context.
* **Whether the context should have received it** — which only a declared
  authorization policy can answer, and usually nobody declared one.

Where no policy exists the verdict is `UNKNOWN_POLICY`: recorded, counted, and
**not a finding**. On a real target that is the common outcome, and the report
says so rather than manufacturing certainty.

### Sensitive field classification

A pure function from a name to a classification. It never sees a value — that is
the point: the scanner can report that a response contained `password_hash`
without ever having kept what was in it.

The hard part is not matching, it is **not over-matching**. A naive search for
"token" flags `token_type` (the literal string "Bearer"), `page_token` (a
pagination cursor) and `requires_token` (a boolean). So the rules run from most
to least precise:

1. **Unambiguous negations** — `has_password`, `token_type`, `page_token`. Facts
   about a credential, never a credential.
2. **Exact matches** — the bulk of the table, and strong enough to outrank a
   suffix: `database_url` ends in `_url` and is still a credential with a
   hostname attached.
3. **Suffix negations** — `_at`, `_count`, `_policy`, `_url`. `password_url` is a
   link to a reset page.
4. **Compound heads, as whole word runs** — `user_password_hash` matches;
   `passwordless` and `tokenizer` do not.

| Sensitivity | Meaning |
| ----------- | ------- |
| `HIGHLY_SENSITIVE` | A secret by construction: password hashes, private keys, access tokens, card numbers, connection strings. |
| `POTENTIALLY_SENSITIVE` | Sensitive in some contexts and ordinary in others: a phone number in a staff directory, an address on an order. |
| `UNKNOWN` | Nothing about the name suggests sensitivity. |

Sensitivity is a property of the *name*. Severity comes from the context.

### When exposure becomes a finding

Two paths, and only two:

**Some fields are never legitimate.** A password hash, a salt, a private key or
a connection string in a JSON body is a defect whoever asked for it — no product
exists in which a client is supposed to receive one. Those produce a finding with
no policy required, because no policy could make them correct.

**Everything else needs evidence.** A token returned to an anonymous request is a
finding; the same token returned to an authenticated one is how a sign-in
endpoint works, and needs the declared policy to say the context should not have
had the resource. Personal data with no policy behind it is an observation.

### Property-level authorization

Phase 12 established who could *reach* a resource. Phase 14 asks what each
identity was handed once inside — OWASP's broken object property level
authorization — using the responses Phase 12 already fetched. **No request is
repeated:** the authorization module records the field names it saw, and this
stage correlates them.

```
USER   -> {id, name, email}
ADMIN  -> {id, name, email, salary, internal_notes}
```

That difference alone is not a defect; an administrator seeing more is the system
working. It becomes one when the extra fields are of a kind no client should hold,
or when the declared policy says this identity should not have had the resource.
The reference for each comparison is the **least**-privileged identity that
received a body, so the question is always "what did this identity get *beyond*
the baseline" rather than "why does the admin see more".

### Verbose errors

Read from failures the scan already ran into while crawling and reading
documentation. Categories only — `STACK_TRACE`, `DATABASE_ERROR`,
`SQL_STATEMENT`, `FRAMEWORK_DEBUG` — and never the text that matched, so a
finding reporting a stack trace does not become one.

Only responses at 400 and above are scanned. Searching every successful page for
exception-shaped text is both wasteful and a reliable false positive: a blog post
about `SELECT` statements is not a database error. One *strong* signal is
conclusive; a lone filesystem path is not, and two weak signals together are.

A generic `{"detail": "Not Found"}` produces nothing, which is the point.

### CORS, read from headers already received

**No `Origin` header is forged to probe CORS** — that is active testing.

| Configuration | Verdict |
| ------------- | ------- |
| No CORS headers | Not a weakness. CORS is not required for every API. |
| `*` without credentials | Ordinary. This is what public APIs look like. |
| `*` **with** credentials | Unsafe — browsers refuse it, so shipping it means the policy was never exercised. |
| `null` with credentials | Unsafe — a sandboxed document can present that origin. |
| A named origin with credentials, no `Vary: Origin` | Low: a shared cache can serve one origin's credentialed response to another. |

### Header disclosure

`Server: nginx` tells an attacker nothing they could not guess and is ignored.
`Server: nginx/1.18.0` names the advisories to read and is reported at LOW.
Diagnostic headers are reported at any value. `Authorization`, `Cookie` and
`Set-Cookie` are structurally excluded: a disclosure finding must not become the
disclosure.

### API inventory

Several versions live at once is what a migration looks like from outside, and
calling it a vulnerability would be guessing at a roadmap. Recorded at **INFO**,
along with documentation that has drifted from the service in either direction.
OWASP treats inventory management as an API concern in its own right, and knowing
which surfaces are live is useful even when nothing is exploitable.

### Findings

| Rule | Severity |
| ---- | -------- |
| `API_SENSITIVE_DATA_EXPOSURE` | HIGH for secrets and anonymous exposure, MEDIUM for personal data |
| `API_PROPERTY_AUTHORIZATION` | HIGH when the extra fields are secrets, else MEDIUM |
| `API_VERBOSE_ERROR` | MEDIUM for a strong signal, LOW otherwise |
| `API_CORS_MISCONFIGURATION` | MEDIUM, or LOW for a missing `Vary` |
| `API_INFORMATION_DISCLOSURE` | LOW |
| `API_LEGACY_VERSION` | INFO |

All under category `API_SECURITY`, through the same aggregation, occurrence
tracking and reporting as every other finding. **Nothing is CRITICAL:** the
scanner observes structure and does not confirm exploitability. The Phase 3
security-header findings are untouched and not duplicated.

### What never reaches a finding

Field names, categories, counts, status codes, header values already vetted as
safe, and signal category names. Not a value, not a body, not an excerpt, not a
credential. The evidence says:

> Field `password_hash` was present in the JSON response for context 'user'.

and never what was in it.

### What Phase 14 does not do

No API fuzzing. No `POST`, `PUT`, `PATCH` or `DELETE`. No request body. No
GraphQL query. No credential attacks, no data extraction, no blind or time-based
SQL injection. It provokes no error and sends no request of its own — every
input was captured by an earlier phase.

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
| POST   | `/api/scans` | yes | Create and run a scan; optionally carries target credentials and authorization identities |
| GET    | `/api/scans` | yes | List the caller's scans (`limit`, `offset`, `status`) |
| GET    | `/api/scans/stats` | yes | Scan counts by status |
| GET    | `/api/scans/{scan_id}` | yes | Read one scan |
| GET    | `/api/scans/{scan_id}/findings` | yes | Deduplicated findings with endpoint context and occurrences |
| GET    | `/api/scans/{scan_id}/endpoints` | yes | URLs the crawler reached, with parameter names |
| GET    | `/api/scans/{scan_id}/forms` | yes | Forms found on crawled pages, with their fields |
| GET    | `/api/scans/{scan_id}/api-endpoints` | yes | API attack surface: endpoints, specifications, GraphQL |
| GET    | `/api/scans/{scan_id}/report` | yes | Canonical security report for one scan |
| GET    | `/api/scans/{scan_id}/report/json` | yes | The same report as a JSON download |
| POST   | `/api/scans/{scan_id}/cancel` | yes | Ask a queued or running scan to stop |
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

* **A limited, specific set of checks.** A scan fetches the target, crawls the same origin,
  assesses security headers and cookies, and runs conservative reflected-XSS and SQL-injection
  checks against discovered GET query parameters. That is the whole of it: no TLS analysis, no
  CORS analysis, no CSRF, SSRF, IDOR or open-redirect testing, and no authorization testing.
* **Authorization testing needs a declared policy, and tests only what it is given.** The
  scanner compares identities you supply and judges the result against expectations you write.
  A resource nobody wrote a rule for is reported as unknown, never as a pass and never as a
  finding — an application's access rules are not visible in its HTTP traffic, and guessing them
  would produce confident nonsense.
* **Authorization testing is read-only.** Only GET is sent. A boundary that exists solely on a
  state-changing operation is not tested, because proving it would mean causing the side effect.
* **No enumeration.** Resources tested are the ones the crawler reached plus the ones you named.
  There is no identifier sweep and no path brute-forcer, so an object you did not name and the
  crawl did not find is not examined.
* **API discovery is reconnaissance, not testing.** It says which endpoints behave like APIs and
  how they were found. It runs no API-specific checks, sends no request body, invokes no
  documented operation, and issues no GraphQL query or mutation. An API appearing in the
  inventory has not been tested beyond the existing XSS and SQL-injection checks.
* **A specification is a claim.** An operation listed in OpenAPI or Swagger has not been shown to
  exist, reachable or working. Documented-only operations are counted and labelled separately
  for exactly that reason.
* **The API inventory is not exhaustive.** It covers what a same-origin crawl reached plus what
  the target published at one of eight conventional documentation paths. An API with no inbound
  link and no published specification will not be found — there is no path brute-forcer.
* **JSON structure is summarised, never stored.** Field names are kept because they describe the
  interface; no value from any response is retained, and both the field list and the depth walked
  are bounded, so a truncated summary is reported as truncated rather than as the whole shape.
* **API security analysis judges names, not data.** It classifies field *names* and reads headers
  and error signals; it never inspects a value. A field called `phone` is treated the same
  whether it holds a phone number or an empty string, and a field holding a secret under an
  innocuous name is not detected at all.
* **Most sensitive-field observations are unjudgeable without a policy.** Whether an API should
  return a given field depends on the application, so unless the field is a secret by
  construction — a password hash, a private key, a connection string — the scanner needs a
  declared authorization policy to call it wrong. Without one the result is `UNKNOWN_POLICY`:
  recorded and counted, and neither a finding nor a clean result.
* **Verbose-error detection is passive and partial.** Only responses the scan already provoked
  naturally are examined, and only above status 400. An endpoint that returns a debug page under
  conditions the scan never met is not seen, because reaching it would mean sending payloads.
* **CORS is judged from headers alone.** No `Origin` header is forged, so a policy that reflects
  arbitrary origins back is only detected when the response the scan already received happens to
  show it.
* **Vendor `+json` media types are classified but not summarised.** The transport downloads
  bodies for `application/json` and `text/*` but not for suffixed vendor types, so an endpoint
  serving `application/vnd.example+json` is correctly identified as an API from its header while
  its response structure is unavailable. Widening that would change what the XSS and SQLi
  detectors read, which is out of scope here.
* **Target authentication is presented, never obtained.** Credentials are supplied by the
  authorized user. There is no login automation, no OAuth, no SAML, no MFA handling, no browser
  engine, and nothing that discovers, guesses or brute-forces a credential.
* **Authentication can lapse mid-scan.** `AVAILABLE` reflects one request at the start. If a
  session expires while the scan runs, later pages are fetched anonymously and simply appear as
  redirects to a login page; the scanner does not re-authenticate, and cannot.
* **Credentials are not persisted, which ties scanning to inline execution.** A target credential
  lives in memory for the length of the request and is never written to PostgreSQL. Moving scans
  onto a worker would require it to cross that boundary, which would mean storing it — so that
  change is not a drop-in one. Python also offers no guaranteed memory erasure: no reference is
  kept after a scan, but the bytes are reclaimed whenever the garbage collector runs.
* **Scans run in the API process.** There is no queue and no worker: `POST /api/scans` blocks
  until the scan stops, and a process restart mid-scan leaves that scan `RUNNING` with nothing to
  finish it. Nothing reaps such a row automatically.
* **Cancellation is cooperative, so it is not instant.** A stop takes effect at the next safe
  boundary - up to the 1.5 s cancellation-poll interval, plus however long the request already in
  flight takes to return. Nothing is killed mid-request.
* **Progress is a stage, not a measurement.** The crawler discovers its own workload, so the
  percentage attached to each stage is an indicative milestone and nothing more.
* **Findings are configuration observations.** Their absence does not mean a site is secure — it
  means these particular checks found nothing on one response.
* **Cookie classification is name-based.** A session cookie with an unusual name will not be
  recognised as one; a non-session cookie named `auth_pref` would be. Findings that depend on this
  carry MEDIUM confidence.
* **Only cookies set on the scanned response are seen.** Cookies set after login, or by
  JavaScript, are invisible to this scanner.
* **Two vulnerability classes are actively tested:** reflected XSS and SQL injection, both on
  GET query parameters only. There is no CSRF, SSRF, IDOR or open-redirect testing.
* **SQLi detection is conservative and signal-based.** It never extracts data, enumerates a
  schema, runs stacked queries, uses UNION, or uses time-based blind techniques. It reports
  error-based and reproduced boolean-differential signals; a vulnerability reachable only by
  those excluded techniques will not be found, and a clean result is not proof of safety.
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
* **A report summarises what this scanner observed.** It does not prove a target is secure:
  authenticated areas, form submissions, JavaScript-rendered content and every vulnerability
  class the scanner does not test are outside its scope. Reports are read-only views of stored
  scan data and never re-run a scan.
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
* Findings are not verified by exploitation. A reported issue is a signal the scanner observed and reproduced, not a demonstrated exploit.

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
| 7 | Reusable active-probe framework; XSS migrated onto it | done |
| 8 | Conservative SQL-injection detection (error-based + boolean) | done |
| 9 | Reporting layer: canonical report, API, results page, JSON export | done |
| 10 | Scan execution lifecycle: state machine, cancellation, progress | done |
| 11 | Authorized authentication-aware scanning (bearer token, cookies) | done |
| 12 | Authorization testing: anonymous, horizontal, vertical, object-level | done |
| 13 | API discovery: classification, OpenAPI/Swagger, GraphQL presence | done |
| 14 | API security baseline: sensitive data, verbose errors, CORS, inventory | **done - current release** |
| 15 | TLS inspection and risk scoring | planned |
| 16 | Further active testing: open redirect, CSRF | planned |
| 17 | Additional export formats (PDF, SARIF), background execution | planned |

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
