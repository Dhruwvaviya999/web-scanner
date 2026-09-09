"""Deciding what a response means, and whether two responses match.

Two questions, kept separate on purpose:

1. **Did this context get in?** — `classify_access`.
2. **Did two contexts receive the same thing?** — `equivalent`.

Neither is sufficient alone, and the detector needs both. A 200 does not mean
access was granted: applications routinely answer 200 with a sign-in page. Two
200s do not mean the same resource was served: they may be the same empty-state
template. Only "the subject was let in *and* received materially what the owner
receives" supports a conclusion.

Timing is deliberately absent. It is not an authorization signal — network
variance dwarfs application variance, and treating it as evidence manufactures
findings out of noise.

Nothing here retains a response body. Comparison happens on values already in
memory and yields a `ResponseFingerprint`, which is a length and a digest.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

from app.scanner.active.comparison import body_similarity, media_type, response_text
from app.scanner.authorization.types import (
    AuthorizationConfig,
    ObservedAccess,
    ResponseFingerprint,
)
from app.scanner.types import RawHttpResponse

#: Landing on one of these after asking for a resource is a refusal expressed
#: as a redirect. Same list the phase-11 access check uses, for one vocabulary.
_SIGN_IN_MARKERS = ("login", "signin", "sign-in", "sign_in", "sso", "session/new")

#: Explicit refusals. 404 is included: whatever the reason, the context did not
#: receive the resource, and treating "hidden" as "allowed" would be worse.
_DENIED_STATUSES = frozenset({401, 403, 404, 405, 407})

#: Collapsed before hashing so that a timestamp, a CSRF token or a request id
#: rendered into an otherwise identical page does not make two responses look
#: different. Deliberately conservative — over-normalising would make different
#: pages look alike, which is the dangerous direction.
_VOLATILE_PATTERNS = (
    re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?(\.\d+)?"),  # timestamps
    re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    re.compile(r"\b[0-9a-fA-F]{32,}\b"),  # long hex blobs: tokens, digests
)

_WHITESPACE = re.compile(r"\s+")

#: How much of a digest is kept. Enough to compare two responses this process
#: is holding; short enough that it is plainly not a store of the content.
_DIGEST_LENGTH = 16


def normalized_body(response: RawHttpResponse) -> str:
    """The body with volatile fragments collapsed, for comparison only.

    Never stored, never logged, never returned to a caller that persists.
    """
    text = response_text(response)
    for pattern in _VOLATILE_PATTERNS:
        text = pattern.sub("~", text)
    return _WHITESPACE.sub(" ", text).strip()


def fingerprint(response: RawHttpResponse) -> ResponseFingerprint:
    """Reduce a response to something safe to keep."""
    body = normalized_body(response)
    digest = hashlib.sha256(body.encode("utf-8", "replace")).hexdigest()[:_DIGEST_LENGTH]
    try:
        final_path = urlsplit(response.final_url).path or "/"
    except ValueError:  # pragma: no cover - urlsplit is lenient
        final_path = None

    return ResponseFingerprint(
        status_code=response.status_code,
        content_type=media_type(response),
        body_length=len(response.body),
        body_digest=digest,
        final_path=final_path,
        redirected=response.redirect_count > 0,
    )


def looks_like_sign_in(url: str | None) -> bool:
    if not url:
        return False
    try:
        path = urlsplit(url).path.lower()
    except ValueError:  # pragma: no cover
        return False
    return any(marker in path for marker in _SIGN_IN_MARKERS)


def classify_access(response: RawHttpResponse, *, requested_url: str) -> ObservedAccess:
    """Whether this context appears to have received the resource.

    Conservative in the direction that matters: anything ambiguous is
    `INCONCLUSIVE` rather than `ALLOWED`, because only `ALLOWED` can contribute
    to a finding.
    """
    if response.status_code in _DENIED_STATUSES:
        return ObservedAccess.DENIED

    # Bounced to a sign-in page: a refusal, however it is dressed up. Not
    # counted when the resource asked for *is* the sign-in page.
    if (
        response.redirect_count > 0
        and looks_like_sign_in(response.final_url)
        and not looks_like_sign_in(requested_url)
    ):
        return ObservedAccess.DENIED

    if 200 <= response.status_code < 300:
        return ObservedAccess.ALLOWED

    if 300 <= response.status_code < 400:
        # A redirect the transport did not resolve. Where it leads is unknown,
        # so what the context received is unknown too.
        return ObservedAccess.INCONCLUSIVE

    # 5xx and anything else: the target's problem, not an access decision.
    return ObservedAccess.INCONCLUSIVE


def equivalent(
    reference: RawHttpResponse,
    subject: RawHttpResponse,
    config: AuthorizationConfig,
) -> bool:
    """Whether two contexts received materially the same thing.

    Every one of these conditions has to hold, because each rules out a
    different way of being wrong:

    * **Same status** — a 200 and a 302 are not the same answer.
    * **Same media type** — a JSON record and an HTML page are not the same
      answer, however similar their text.
    * **A body big enough to mean something** — two 20-byte error pages are
      always "similar", and concluding from that would flag every application
      with a consistent denial page.
    * **A high similarity ratio** — identical digests are the clean case;
      near-identical bodies still count, because a private page usually renders
      the viewer's own name somewhere in it.
    """
    if reference.status_code != subject.status_code:
        return False
    if media_type(reference) != media_type(subject):
        return False

    left = normalized_body(reference)
    right = normalized_body(subject)

    if len(left) < config.min_comparable_body_bytes:
        # Too little content for similarity to carry information. Only an exact
        # match counts, and even that is weak evidence the detector downgrades.
        return bool(left) and left == right

    if left == right:
        return True

    return body_similarity(reference, subject) >= config.equivalence_threshold


def similarity(reference: RawHttpResponse, subject: RawHttpResponse) -> float:
    """The raw ratio, for evidence text. Rounded by the caller."""
    return body_similarity(reference, subject)
