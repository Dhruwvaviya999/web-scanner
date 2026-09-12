"""Turning configuration observations into findings.

Three rules govern every builder below.

**No content, ever.** Not a line of a `.env`, not a byte of a repository
object, not a source line from a map, not a stack frame from a debug page, not
a credential, a cookie or a token. The observations reaching these builders
never carried any of it, so a finding cannot leak it even by accident. Evidence
names a path, a status code, a media type and a size — the fact of exposure,
never the substance of it.

**Nothing is CRITICAL.** A misconfiguration is a door left open, not a
demonstrated break-in. `.env` exposure is HIGH because the consequence is
immediate and well understood; nothing here goes above it.

**The absence of a best practice is not a finding.** No `Permissions-Policy` is
not a weakness. A path containing "admin" is not an exposure. A `Server` header
is not a vulnerability — it is how web servers work, and the technology rule is
INFO precisely so it can be read as inventory rather than as an accusation.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from app.scanner.config_security.methods import surprising_methods
from app.scanner.config_security.types import (
    AccessVisibility,
    CandidateKind,
    CandidateObservation,
    CspObservation,
    DebugObservation,
    HeaderDefect,
    HeaderDefectObservation,
    HstsQuality,
    ListingObservation,
    MethodObservation,
    NormalizationObservation,
    RedirectBehaviour,
    SourceMapObservation,
    TechnologyObservation,
    TlsObservation,
    TransportObservation,
)
from app.scanner.security.types import (
    FindingCategory,
    FindingConfidence,
    FindingData,
    FindingRule,
    FindingSeverity,
)

_CATEGORY = FindingCategory.CONFIGURATION


def _path_of(url: str) -> str:
    try:
        return urlsplit(url).path or url
    except ValueError:  # pragma: no cover - urlsplit is lenient
        return url


# --------------------------------------------------------------------------- #
# Transport
# --------------------------------------------------------------------------- #


def insecure_http_finding(
    observation: TransportObservation, *, require_https: bool
) -> FindingData | None:
    """The application is served over plaintext and offers no upgrade.

    Two gates before this fires, both there to keep the finding meaningful.
    `require_https` is off by default, and a loopback or private-network target
    is exempt whatever it is set to — a developer scanning their own machine
    over HTTP has not misconfigured anything.
    """
    if not require_https or observation.local_target:
        return None
    if observation.secure_transport:
        return None
    if observation.redirect is RedirectBehaviour.REDIRECTS_TO_HTTPS:  # pragma: no cover
        return None

    return FindingData(
        rule=FindingRule.CONFIG_INSECURE_HTTP,
        title="Application is served over plain HTTP",
        category=_CATEGORY,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.HIGH,
        description=(
            "The target answered over plain HTTP and did not redirect to HTTPS. "
            "Everything sent to or from it — form input, session cookies, the pages "
            "themselves — crosses the network in a form anyone on the path can read "
            "and modify."
        ),
        evidence=(
            f"The scan reached {observation.final_url or 'the target'} over HTTP; "
            f"redirect behaviour: {observation.redirect.value}."
        ),
        impact=(
            "An attacker positioned on the network can read session cookies and "
            "credentials in transit, and can alter responses to inject content. No "
            "application-level control compensates for this."
        ),
        remediation=(
            "Serve the application over HTTPS and redirect every plain-HTTP request to "
            "it before any cookie is issued. Once HTTPS is stable, add "
            "Strict-Transport-Security so the first request never goes out in the clear."
        ),
        subject="transport",
    )



def weak_hsts_finding(observation: TransportObservation) -> FindingData | None:
    """An HSTS policy that does not cover what it should.

    Deliberately narrow, because Phase 3 already reports HSTS missing, disabled
    and short. Only two cases survive that boundary, and neither has a Phase 3
    rule:

    * the policy covers the bare host but not its subdomains;
    * the header was sent over plain HTTP, where browsers discard it.
    """
    if observation.hsts_quality is HstsQuality.HOST_ONLY:
        return FindingData(
            rule=FindingRule.CONFIG_WEAK_HSTS,
            title="HSTS does not cover subdomains",
            category=_CATEGORY,
            severity=FindingSeverity.LOW,
            confidence=FindingConfidence.HIGH,
            description=(
                "Strict-Transport-Security is set with a long max-age but without "
                "includeSubDomains, so the policy protects this host and nothing "
                "beneath it. A subdomain reached over HTTP is not covered, and a cookie "
                "scoped to the parent domain can still be sent to it in the clear."
            ),
            evidence=(
                f"Strict-Transport-Security max-age={observation.hsts_max_age}; "
                "includeSubDomains absent."
            ),
            impact=(
                "An attacker who can answer for any subdomain over HTTP can set or read "
                "domain-scoped cookies. Whether that matters depends on whether "
                "subdomains exist and what cookies are scoped to the parent."
            ),
            remediation=(
                "Add includeSubDomains once every subdomain is confirmed to serve "
                "HTTPS. Adding it before that will make any HTTP-only subdomain "
                "unreachable, so verify first."
            ),
            subject="hsts:subdomains",
        )

    if observation.hsts_quality is HstsQuality.INEFFECTIVE_OVER_HTTP:
        return FindingData(
            rule=FindingRule.CONFIG_WEAK_HSTS,
            title="HSTS header sent over plain HTTP",
            category=_CATEGORY,
            severity=FindingSeverity.INFO,
            confidence=FindingConfidence.HIGH,
            description=(
                "A Strict-Transport-Security header was sent on a plain-HTTP response. "
                "Browsers ignore HSTS delivered over HTTP by design, since an attacker "
                "who can modify the response could otherwise set or clear the policy. "
                "The header is doing nothing here."
            ),
            evidence=(
                "Strict-Transport-Security was present on an HTTP response, where it "
                "has no effect."
            ),
            impact=(
                "None directly — but the header's presence can give the impression that "
                "HSTS is deployed when no browser is acting on it."
            ),
            remediation=(
                "Send Strict-Transport-Security only on HTTPS responses, and redirect "
                "HTTP to HTTPS so browsers reach the version that carries it."
            ),
            subject="hsts:over-http",
        )

    return None


def tls_failure_finding(observation: TransportObservation) -> FindingData | None:
    """The client refused the certificate.

    Reported as what it is and no more. Which defect the certificate had —
    expired, self-signed, wrong hostname, untrusted issuer — is not determined
    by this scan, and naming one on no evidence would be a specific claim the
    scanner cannot support.
    """
    if observation.tls is not TlsObservation.CERTIFICATE_REJECTED:
        return None

    return FindingData(
        rule=FindingRule.CONFIG_TLS_CONNECTION_FAILURE,
        title="TLS certificate could not be verified",
        category=_CATEGORY,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.HIGH,
        description=(
            "The HTTPS connection failed certificate verification. This scan does not "
            "determine which specific problem the certificate had — it may be expired, "
            "self-signed, issued for another hostname, or signed by an issuer this "
            "client does not trust."
        ),
        evidence="The HTTP client rejected the target's certificate during the handshake.",
        impact=(
            "Visitors see a browser warning, and any who click through lose the "
            "authentication half of TLS: the connection is encrypted, but not "
            "demonstrably to the right server."
        ),
        remediation=(
            "Inspect the certificate directly to establish the cause, then reissue or "
            "reconfigure the chain. Confirm intermediate certificates are served, since "
            "a missing intermediate fails in some clients and not others."
        ),
        subject="tls",
    )


# --------------------------------------------------------------------------- #
# Methods
# --------------------------------------------------------------------------- #


def unsafe_methods_finding(observation: MethodObservation) -> FindingData | None:
    """A method advertised where it does not belong.

    Nothing here was invoked. `DELETE` on a REST resource is the design and is
    filtered out upstream by `surprising_methods`; what reaches this builder is
    a diagnostic method, or a state-changing method somewhere that is not an API.
    """
    surprising = surprising_methods(observation)
    if not surprising:
        return None

    diagnostic = [m for m in surprising if m in ("TRACE", "TRACK", "CONNECT")]
    severity = FindingSeverity.MEDIUM if diagnostic else FindingSeverity.LOW

    if diagnostic and observation.trace_confirmed:
        confidence = FindingConfidence.HIGH
        confirmation = "The method was confirmed enabled against a local fixture."
    else:
        confidence = FindingConfidence.MEDIUM
        confirmation = (
            "This is what the server advertised; no request using these methods was "
            "sent, so whether they are actually enabled is not established."
        )

    return FindingData(
        rule=FindingRule.CONFIG_UNSAFE_HTTP_METHODS,
        title="Unexpected HTTP methods advertised",
        category=_CATEGORY,
        severity=severity,
        confidence=confidence,
        description=(
            f"{_path_of(observation.url)} advertises {', '.join(surprising)}. "
            + (
                "TRACE and TRACK echo the request back, including headers the browser "
                "attached, and have no use in a deployed application. "
                if diagnostic
                else "These methods change server state and this endpoint does not look "
                "like an API, where they would be expected. "
            )
            + confirmation
        ),
        evidence=(
            f"OPTIONS {_path_of(observation.url)} → "
            f"Allow: {observation.allow_header or 'not sent'}; "
            f"advertised: {', '.join(observation.advertised) or 'none'}."
        ),
        impact=(
            "A method enabled but not intended widens what the endpoint can be asked "
            "to do. Whether any of these can be used depends on authorization, which "
            "this check did not test."
        ),
        remediation=(
            "Restrict each route to the methods it implements and have the server "
            "reject the rest with 405. Disable TRACE and TRACK at the web-server layer; "
            "no application needs either."
        ),
        subject=f"methods:{_path_of(observation.url)}",
    )


# --------------------------------------------------------------------------- #
# Debug
# --------------------------------------------------------------------------- #


def debug_finding(observation: DebugObservation) -> FindingData | None:
    """Development configuration reachable in a deployed application.

    Requires `conclusive`: two independent markers, or one plus a diagnostic
    leak Phase 14 already found. One marker on its own is a coincidence waiting
    to be reported — the word "debug" is common in ordinary pages.
    """
    if not observation.conclusive:
        return None

    names = [signal.value for signal in observation.signals]
    interactive = "INTERACTIVE_CONSOLE" in names
    severity = FindingSeverity.HIGH if interactive else FindingSeverity.MEDIUM

    return FindingData(
        rule=FindingRule.CONFIG_DEBUG_EXPOSURE,
        title=(
            "Interactive debugger reachable"
            if interactive
            else "Application is running in development configuration"
        ),
        category=_CATEGORY,
        severity=severity,
        confidence=FindingConfidence.MEDIUM,
        description=(
            f"{_path_of(observation.url)} returned a response carrying development-mode "
            f"markers: {', '.join(names)}. "
            + (
                "An interactive debug console allows code to be evaluated on the server "
                "through the browser, which is a direct route to full compromise if it "
                "is reachable without a PIN. "
                if interactive
                else "Debug output typically includes stack traces, configuration values "
                "and internal paths. "
            )
            + "The matched text is not recorded — reproducing it here would republish "
            "the very material this finding reports as exposed."
        ),
        evidence=(
            f"{_path_of(observation.url)} → status {observation.status_code}; "
            f"signals: {', '.join(names)}"
            + (
                "; corroborated by a diagnostic leak found during API error analysis."
                if observation.corroborated_by_error_analysis
                else "."
            )
        ),
        impact=(
            "Debug output hands an attacker the internal structure of the application "
            "— file paths, framework versions, configuration keys, sometimes "
            "credentials. Where an interactive console is exposed, the impact is "
            "arbitrary code execution."
        ),
        remediation=(
            "Turn debug mode off in every deployed environment and drive it from an "
            "environment variable that defaults to off. Return generic error pages to "
            "clients and keep diagnostics in server-side logs."
        ),
        subject=f"debug:{_path_of(observation.url)}",
    )


# --------------------------------------------------------------------------- #
# Sensitive files and repository metadata
# --------------------------------------------------------------------------- #

#: Files whose exposure is severe on its own, because of what they always hold.
_HIGH_VALUE = (".env", ".env.local", ".env.production", ".npmrc")


def sensitive_file_finding(observation: CandidateObservation) -> FindingData | None:
    """A deployment file served from the web root.

    The contents were never read into anything that survives this call. The
    finding says a path answered, what media type it claimed and how large it
    was — enough for somebody to go and look, and nothing that reproduces the
    exposure in a report or a database row.
    """
    if not observation.exposed or observation.kind is not CandidateKind.SENSITIVE_FILE:
        return None

    path = observation.path
    lowered = path.lower()

    # robots.txt is meant to be public. It is fetched because it maps the site,
    # not because serving it is a defect.
    if lowered.endswith("robots.txt"):
        return None

    high_value = any(lowered.endswith(name) for name in _HIGH_VALUE)
    severity = FindingSeverity.HIGH if high_value else FindingSeverity.MEDIUM

    return FindingData(
        rule=FindingRule.CONFIG_SENSITIVE_FILE_EXPOSURE,
        title=(
            "Environment file is publicly reachable"
            if high_value
            else "Deployment file is publicly reachable"
        ),
        category=_CATEGORY,
        severity=severity,
        confidence=FindingConfidence.HIGH,
        description=(
            f"A request for {path} returned a successful response whose body had the "
            "shape of the file requested, rather than an application page. "
            + (
                "Environment files hold database credentials, API keys and signing "
                "secrets by convention. Assume anything in this one is known."
                if high_value
                else "Deployment and configuration files describe how the application is "
                "built and where its dependencies come from, and often carry more."
            )
            + " The file's contents were not read, stored or reported."
        ),
        evidence=(
            f"GET {path} → status {observation.status_code}, "
            f"content type {observation.media_type or 'not stated'}, "
            f"{observation.size if observation.size is not None else 'unknown'} bytes. "
            "No part of the response body was retained."
        ),
        impact=(
            "Anyone who can reach the site can read this file. Where it holds "
            "credentials, they are compromised from the moment it became reachable — "
            "not from the moment somebody was seen using them."
            if high_value
            else "The file reveals how the deployment is put together, which narrows the "
            "search for a way in."
        ),
        remediation=(
            "Move the file out of the web root and deny the path at the web-server "
            "layer as a second line. "
            + (
                "Rotate every credential the file contains, and treat the rotation as "
                "urgent rather than scheduled."
                if high_value
                else "Ship only what the application needs at runtime."
            )
        ),
        subject=f"file:{path}",
    )


def repository_metadata_finding(observation: CandidateObservation) -> FindingData | None:
    """Version-control metadata reachable from the web root.

    Established from exactly one file. The scanner does not fetch `.git/config`,
    walk refs, or pull objects: reconstructing the repository is the attack this
    finding warns about, and performing it to prove the point would be doing the
    thing rather than reporting it.
    """
    if not observation.exposed or observation.kind is not CandidateKind.REPOSITORY:
        return None

    return FindingData(
        rule=FindingRule.CONFIG_REPOSITORY_METADATA_EXPOSURE,
        title="Version-control metadata is publicly reachable",
        category=_CATEGORY,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.HIGH,
        description=(
            f"A request for {observation.path} returned a response with the shape of a "
            "Git HEAD file, which means the repository directory is being served. Where "
            "directory contents are reachable, the full source history can usually be "
            "reconstructed offline — including files deleted in later commits, and any "
            "credential ever committed to the branch. "
            "This scan fetched one metadata file and stopped: no repository object, "
            "reference or configuration was requested, and nothing was reconstructed."
        ),
        evidence=(
            f"GET {observation.path} → status {observation.status_code}, "
            f"{observation.size if observation.size is not None else 'unknown'} bytes, "
            "with the structure of a Git HEAD reference. "
            "No repository content was fetched or recorded."
        ),
        impact=(
            "The application's source becomes readable, along with its history. Secrets "
            "removed in a later commit are still present in an earlier one, so a "
            "credential someone believes was deleted is recoverable."
        ),
        remediation=(
            "Stop deploying the repository directory: build an artefact and ship that. "
            "Block requests for dot-directories at the web server as a second line. If "
            "the directory has been reachable, treat every credential ever committed to "
            "the repository as compromised and rotate it."
        ),
        subject=f"repository:{observation.path}",
    )


# --------------------------------------------------------------------------- #
# Admin and management
# --------------------------------------------------------------------------- #


def admin_interface_finding(
    observation: CandidateObservation, *, policy_denies: bool = False
) -> FindingData | None:
    """An administrative interface that answered an anonymous request.

    Never fires because a path contains "admin". It fires when an anonymous
    request was *served*, which is a different statement. Even then the default
    is INFO, because plenty of applications correctly serve a login page at
    `/admin` — the severity rises only when the Phase 12 policy says this
    identity should have been refused.
    """
    if not observation.exposed or observation.kind is not CandidateKind.ADMIN:
        return None
    if observation.visibility is not AccessVisibility.PUBLICLY_REACHABLE:
        return None

    if policy_denies:
        severity = FindingSeverity.HIGH
        confidence = FindingConfidence.HIGH
        judgement = (
            "The authorization policy supplied for this scan says an anonymous request "
            "should have been denied here, and it was not."
        )
    else:
        severity = FindingSeverity.INFO
        confidence = FindingConfidence.LOW
        judgement = (
            "No authorization policy was supplied, so whether this should be reachable "
            "is unknown. Many applications serve a login form at this path, which is "
            "correct behaviour and looks identical from outside."
        )

    return FindingData(
        rule=FindingRule.CONFIG_ADMIN_INTERFACE_EXPOSURE,
        title=(
            "Administrative interface reachable without authentication"
            if policy_denies
            else "Administrative path answered an anonymous request"
        ),
        category=_CATEGORY,
        severity=severity,
        confidence=confidence,
        description=(
            f"An anonymous request for {observation.path} was served "
            f"(status {observation.status_code}). {judgement}"
        ),
        evidence=(
            f"GET {observation.path} with no credentials → status "
            f"{observation.status_code}, content type "
            f"{observation.media_type or 'not stated'}."
        ),
        impact=(
            "If the interface exposes administrative function rather than a login "
            "prompt, anyone who finds the path holds it."
            if policy_denies
            else "None established. This is recorded so the intended access policy can "
            "be confirmed by someone who knows it."
        ),
        remediation=(
            "Require authentication and authorization before any administrative "
            "function renders, and confirm the check runs server-side rather than "
            "hiding the interface in the client. Restricting the path by network where "
            "the deployment allows it is a useful second layer."
        ),
        subject=f"admin:{observation.path}",
    )


def management_interface_finding(
    observation: CandidateObservation, *, sensitive: bool = False
) -> FindingData | None:
    """A management endpoint exposing more than its own liveness.

    A health check answering `{"status":"UP"}` is a correctly built health
    check, and produces nothing. `sensitive` is set by the caller when Phase 14's
    field analysis found configuration or environment material in the response,
    which is what turns an inventory entry into a finding.
    """
    if not observation.exposed or observation.kind is not CandidateKind.MANAGEMENT:
        return None
    if observation.visibility is not AccessVisibility.PUBLICLY_REACHABLE:
        return None
    if not sensitive:
        return None

    return FindingData(
        rule=FindingRule.CONFIG_MANAGEMENT_INTERFACE_EXPOSURE,
        title="Management endpoint exposes internal detail",
        category=_CATEGORY,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.MEDIUM,
        description=(
            f"An anonymous request for {observation.path} returned a response carrying "
            "configuration or environment detail rather than a simple status. "
            "Management surfaces of this kind are built for operators on an internal "
            "network and routinely expose settings, dependency versions and internal "
            "hostnames."
        ),
        evidence=(
            f"GET {observation.path} with no credentials → status "
            f"{observation.status_code}, content type "
            f"{observation.media_type or 'not stated'}, "
            f"{observation.size if observation.size is not None else 'unknown'} bytes. "
            "No value from the response was recorded."
        ),
        impact=(
            "Internal configuration narrows an attacker's search considerably: known "
            "dependency versions, internal service names and infrastructure detail all "
            "become available without any further probing."
        ),
        remediation=(
            "Require authentication on management endpoints, or bind them to an "
            "interface the public internet cannot reach. Where the framework supports "
            "it, expose only the specific endpoints operations needs rather than the "
            "whole surface."
        ),
        subject=f"management:{observation.path}",
    )


# --------------------------------------------------------------------------- #
# Directory listing, defaults, source maps
# --------------------------------------------------------------------------- #


def directory_listing_finding(observation: ListingObservation) -> FindingData:
    return FindingData(
        rule=FindingRule.CONFIG_DIRECTORY_LISTING,
        title="Directory listing is enabled",
        category=_CATEGORY,
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.HIGH,
        description=(
            f"{_path_of(observation.url)} returned a server-generated directory index "
            "rather than a page. Anyone visiting can enumerate the files in that "
            "directory without guessing names — including files that are present but "
            "not linked from anywhere."
        ),
        evidence=(
            f"GET {_path_of(observation.url)} returned a "
            f"{observation.server_style or 'server'}-style directory index"
            + (
                f" containing roughly {observation.entry_count} entries."
                if observation.entry_count
                else "."
            )
        ),
        impact=(
            "Unreferenced files become discoverable: backups, editor swap files, "
            "deployment artefacts and old versions that were never meant to be found."
        ),
        remediation=(
            "Disable automatic indexing (Apache `Options -Indexes`, nginx `autoindex "
            "off`) and serve an index document or a 403 instead. Remove artefacts that "
            "do not belong in the served directory in the first place."
        ),
        subject=f"listing:{_path_of(observation.url)}",
    )


def default_content_finding(observation: CandidateObservation) -> FindingData | None:
    if not observation.exposed or observation.kind is not CandidateKind.SAMPLE:
        return None

    return FindingData(
        rule=FindingRule.CONFIG_DEFAULT_SAMPLE_EXPOSURE,
        title="Default or sample content is served",
        category=_CATEGORY,
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.MEDIUM,
        description=(
            f"{observation.path} returned default or sample content shipped with the "
            "server or framework. It suggests the deployment was not fully cleaned "
            "down, and it identifies the platform precisely."
        ),
        evidence=(
            f"GET {observation.path} → status {observation.status_code}, "
            f"content type {observation.media_type or 'not stated'}."
        ),
        impact=(
            "Sample content pins the platform and version, which narrows the set of "
            "known issues worth trying. Some sample applications are themselves "
            "vulnerable."
        ),
        remediation=(
            "Remove default and sample content from deployed environments, and make "
            "removal part of the build rather than a manual step."
        ),
        subject=f"sample:{observation.path}",
    )


def source_map_finding(observation: SourceMapObservation) -> FindingData | None:
    """A published source map.

    Not automatically serious, and graded to say so. Plenty of teams publish
    maps deliberately so production stack traces are readable. What the finding
    records is that the original sources are reachable, so somebody can decide
    whether that was the intent.
    """
    if not observation.reachable:
        return None

    return FindingData(
        rule=FindingRule.CONFIG_SOURCE_MAP_EXPOSURE,
        title="JavaScript source map is publicly reachable",
        category=_CATEGORY,
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.HIGH,
        description=(
            f"{_path_of(observation.asset_url)} publishes a source map at "
            f"{_path_of(observation.map_url)}, and the map answered. A source map "
            "republishes the original, unminified sources, typically including comments "
            "and the project's directory structure. "
            "This is often deliberate — maps make production errors debuggable — so it "
            "is reported as something to confirm rather than as a defect. No source "
            "from the map was read or stored."
        ),
        evidence=(
            f"GET {_path_of(observation.map_url)} returned a source map"
            + (
                f" listing {observation.source_count} original files."
                if observation.source_count
                else "."
            )
            + " Only the count was recorded."
        ),
        impact=(
            "Client-side logic becomes readable as written rather than as minified. "
            "That matters where comments, internal endpoint names or client-side keys "
            "are present in the sources; it matters little otherwise."
        ),
        remediation=(
            "If maps are not needed in production, stop emitting them or keep them out "
            "of the deployed bundle. If they are needed, upload them to the error "
            "tracker instead of serving them, or restrict access to the map files."
        ),
        subject=f"sourcemap:{_path_of(observation.map_url)}",
    )


# --------------------------------------------------------------------------- #
# Headers, CSP, technology, normalization
# --------------------------------------------------------------------------- #


def technology_finding(observation: TechnologyObservation) -> FindingData:
    """Inventory, at INFO, and deliberately never more.

    Most web servers send one of these headers, and grading every default
    configuration as a weakness is how a findings list becomes noise people
    filter out. The value is that a reader can see what is running.
    """
    return FindingData(
        rule=FindingRule.CONFIG_TECHNOLOGY_DISCLOSURE,
        title="Response headers name the software serving the site",
        category=_CATEGORY,
        severity=FindingSeverity.INFO,
        confidence=FindingConfidence.HIGH,
        description=(
            f"The {observation.header} header identifies the software behind the "
            + ("target, including its version. " if observation.versioned else "target. ")
            + "This is the default behaviour of most web servers and is not a "
            "vulnerability. It is recorded because a pinned version tells an attacker "
            "which known issues are worth trying first."
        ),
        evidence=f"{observation.header}: {observation.value}",
        impact=(
            "Reconnaissance only. It shortens the list of things worth attempting; it "
            "does not enable any of them."
        ),
        remediation=(
            "Suppress or generalise the header if you would rather not advertise the "
            "version (`server_tokens off` in nginx, `ServerTokens Prod` in Apache, "
            "removing `X-Powered-By` in application middleware). Treat this as tidiness "
            "rather than a fix — keeping the software patched is what matters."
        ),
        subject=f"technology:{observation.header}",
    )


def weak_csp_finding(observation: CspObservation) -> FindingData | None:
    """A policy that does not restrict where script comes from.

    Scoped off Phase 3, which already reports a missing policy and flags
    `'unsafe-inline'`/`'unsafe-eval'` at INFO. Only `UNRESTRICTED` reaches here,
    and that is a different defect: not "inline script is allowed" but "script
    may be loaded from anywhere at all".
    """
    if not observation.reportable:
        return None

    sources = ", ".join(observation.wildcard_sources) or "no script-governing directive"

    return FindingData(
        rule=FindingRule.CONFIG_WEAK_CSP,
        title="Content-Security-Policy does not restrict script sources",
        category=_CATEGORY,
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.MEDIUM,
        description=(
            "A Content-Security-Policy is set, but the directive governing script "
            f"execution permits {sources}. A wildcard or scheme source allows script "
            "from any host, which leaves the policy providing essentially no protection "
            "against injected script — the main thing CSP exists to do. "
            "This is a separate observation from the permissive-directive check, which "
            "looks at inline and evaluated script rather than source breadth."
        ),
        evidence=(
            f"Effective script sources on {_path_of(observation.url)} include: {sources}."
            + (" More than one policy header was sent." if observation.duplicated else "")
        ),
        impact=(
            "If a cross-site scripting flaw exists, the policy does not constrain where "
            "the injected script may load code from. This finding does not itself mean "
            "such a flaw is present."
        ),
        remediation=(
            "Name the specific origins script may come from, or move to per-request "
            "nonces. Remove `*` and bare scheme sources such as `https:` from "
            "`script-src`, and set an explicit `script-src` rather than relying on a "
            "wildcarded `default-src`."
        ),
        subject=f"csp:{_path_of(observation.url)}",
    )


def header_defect_finding(observation: HeaderDefectObservation) -> FindingData | None:
    """A security header that is present but does not work.

    Distinct from Phase 3 by construction: Phase 3 reports headers that are
    *absent*, and every case here is a header that is there.
    """
    if observation.defect is HeaderDefect.DUPLICATE_CONFLICTING:
        severity = FindingSeverity.MEDIUM
        title = f"Conflicting {observation.header} headers"
        detail = (
            "The response carries this header more than once with different values. "
            "How a browser resolves that varies by header — some take the first, some "
            "the most restrictive, and CSP intersects them — so the effective policy is "
            "unlikely to be the one intended."
        )
    elif observation.defect is HeaderDefect.EMPTY_VALUE:
        severity = FindingSeverity.LOW
        title = f"{observation.header} is present with no value"
        detail = (
            "The header is sent empty, so it protects nothing while appearing in an "
            "audit as configured. This is usually a template or middleware that ran "
            "without the value it expected."
        )
    elif observation.defect is HeaderDefect.INVALID_VALUE:
        severity = FindingSeverity.LOW
        title = f"{observation.header} has an invalid value"
        detail = (
            "The value is not one this header accepts, so browsers discard the header "
            "entirely and the protection it was meant to provide is absent."
        )
    else:
        severity = FindingSeverity.INFO
        title = f"{observation.header} is deprecated"
        detail = f"This header no longer does what it once did: {observation.detail}."

    return FindingData(
        rule=FindingRule.CONFIG_HEADER_MISCONFIGURATION,
        title=title,
        category=_CATEGORY,
        severity=severity,
        confidence=FindingConfidence.HIGH,
        description=detail,
        evidence=(
            f"{observation.header}"
            + (f": {observation.value}" if observation.value else " was sent empty")
            + f" on {_path_of(observation.url)}."
        ),
        impact=(
            "The control this header configures is not in force, and its presence "
            "makes that hard to notice."
        ),
        remediation=(
            "Set the header exactly once, with a valid value, from one place in the "
            "stack. Where a proxy and the application both add security headers, decide "
            "which owns them and remove the other."
        ),
        subject=f"header:{observation.header}:{observation.defect.value}",
    )


def path_normalization_finding(
    observation: NormalizationObservation,
) -> FindingData:
    return FindingData(
        rule=FindingRule.CONFIG_PATH_NORMALIZATION,
        title="Inconsistent path handling",
        category=_CATEGORY,
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.LOW,
        description=(
            f"{observation.detail.capitalize()}. Where a proxy and an application "
            "resolve a URL differently, an access rule written against one spelling can "
            "be sidestepped using another. "
            "This was observed from responses the scan had already collected: no "
            "traversal payload or encoded path was sent to test it, so this is a "
            "configuration observation rather than a demonstrated bypass."
        ),
        evidence=(
            f"Signal {observation.signal.value} across: {', '.join(observation.paths)}."
        ),
        impact=(
            "Potentially an authorization bypass, if any rule is written against a "
            "specific path spelling. Whether one is has not been established."
        ),
        remediation=(
            "Normalise paths in one place — ideally the edge — before any access rule "
            "is evaluated, and make the application reject or redirect spellings that "
            "do not match the canonical form. Avoid writing authorization rules against "
            "literal path strings."
        ),
        subject=f"normalization:{observation.signal.value}:{observation.paths[0] if observation.paths else ''}",
    )
