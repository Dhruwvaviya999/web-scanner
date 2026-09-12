"""Passive JWT recognition.

**Recognition, and nothing else.** This module does not verify a signature,
crack one, forge a token, strip an algorithm, replay a token anywhere, or send a
token to any destination. It reads the two unencrypted segments a JWT publishes
by design, records the algorithm label and the *names* of the claims, and
discards the token.

That restraint is what makes the output safe to store. Saying an endpoint issues
a token declaring `alg: HS256` with an `exp` claim is useful to a reviewer.
Saying what the token *is* would put a live credential in a database row, a
report and a log — which is the exposure this phase exists to detect.

Everything is bounded and total: a hostile or merely broken token yields
`decoded=False` rather than an exception.
"""

from __future__ import annotations

import base64
import binascii
import json
import re

from app.scanner.session_security.types import JwtMetadata

#: Three base64url segments separated by dots. The signature may be empty —
#: `alg: none` tokens end with a trailing dot — which is exactly the case most
#: worth recognising.
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")

#: A token longer than this is not something a scan needs to reason about, and
#: decoding it would only spend memory.
_MAX_TOKEN_LENGTH = 8192

#: Claim names kept per token. A bounded list; the names describe the shape.
_MAX_CLAIMS = 40

#: How much of a body is searched. A token issued by a response is at the top of
#: it, and scanning megabytes of HTML for base64 buys nothing.
_MAX_SCAN_BYTES = 65_536


def _decode_segment(segment: str) -> dict | None:
    """Decode one base64url JWT segment as JSON. Never raises."""
    if not segment:
        return None
    padded = segment + "=" * (-len(segment) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return None
    try:
        decoded = json.loads(raw.decode("utf-8", "replace"))
    except (ValueError, RecursionError):
        return None
    return decoded if isinstance(decoded, dict) else None


def _text(value: object, limit: int = 40) -> str | None:
    """A short label from an untrusted document, or None."""
    if not isinstance(value, str):
        return None
    cleaned = value.strip().replace("\r", " ").replace("\n", " ")
    return cleaned[:limit] or None


def describe(token: str) -> JwtMetadata:
    """Reduce a JWT to its safe metadata.

    The payload's *values* are read while walking the document — they have to be,
    to find the claim names — and are dropped when this returns. Only names, two
    header labels and a few booleans survive.
    """
    if not token or len(token) > _MAX_TOKEN_LENGTH:
        return JwtMetadata()

    parts = token.split(".")
    if len(parts) != 3:
        return JwtMetadata()

    header = _decode_segment(parts[0])
    if header is None:
        # Token-shaped, but the header is not JSON. Not a JWT.
        return JwtMetadata()

    payload = _decode_segment(parts[1]) or {}
    names = tuple(str(name)[:60] for name in list(payload)[:_MAX_CLAIMS])

    return JwtMetadata(
        algorithm=_text(header.get("alg")),
        token_type=_text(header.get("typ")),
        claim_names=names,
        has_expiry="exp" in payload,
        has_issuer="iss" in payload,
        has_audience="aud" in payload,
        has_issued_at="iat" in payload,
        decoded=True,
    )


def find_tokens(text: str | bytes, limit: int = 10) -> tuple[JwtMetadata, ...]:
    """Recognise JWTs in a body and describe each. Values never leave.

    Deduplicated by metadata, so a token repeated across a page counts once.
    """
    if not text:
        return ()

    if isinstance(text, bytes):
        content = text[:_MAX_SCAN_BYTES].decode("utf-8", "replace")
    else:
        content = text[:_MAX_SCAN_BYTES]

    described: list[JwtMetadata] = []
    seen: set[tuple] = set()
    for match in JWT_PATTERN.finditer(content):
        metadata = describe(match.group(0))
        if not metadata.decoded:
            continue
        key = (metadata.algorithm, metadata.token_type, metadata.claim_names)
        if key in seen:
            continue
        seen.add(key)
        described.append(metadata)
        if len(described) >= limit:
            break

    return tuple(described)


def safe_find_tokens(text: str | bytes, limit: int = 10) -> tuple[JwtMetadata, ...]:
    """`find_tokens`, guaranteed not to raise.

    Called from the crawler's capture step, which has no guard of its own: an
    exception here would unwind a crawl that already gathered fifty pages.
    """
    try:
        return find_tokens(text, limit=limit)
    except Exception:  # noqa: BLE001 - a token summary is never worth a scan
        return ()


#: Claim names that carry more than an identifier. Their *presence* is worth
#: noting to a reviewer; their contents are never read out.
SENSITIVE_CLAIM_NAMES = frozenset(
    {
        "password",
        "password_hash",
        "secret",
        "api_key",
        "apikey",
        "ssn",
        "credit_card",
        "card_number",
        "private_key",
        "refresh_token",
    }
)

#: Algorithms that are unambiguously a problem. `none` asserts the token needs
#: no signature at all. Common algorithms are deliberately absent: HS256 is not
#: a weakness, and saying so would be wrong on most of the internet.
WEAK_ALGORITHMS = frozenset({"none"})


def sensitive_claims(metadata: JwtMetadata) -> tuple[str, ...]:
    """Claim names that suggest the token carries more than an identity."""
    return tuple(
        name
        for name in metadata.claim_names
        if name.strip().lower().replace("-", "_") in SENSITIVE_CLAIM_NAMES
    )


def weaknesses(metadata: JwtMetadata) -> tuple[str, ...]:
    """Safe, specific observations about a token's metadata.

    Deliberately short. A JWT is not insecure for using a mainstream algorithm,
    and this refuses to say so — only `alg: none`, a missing expiry, and
    sensitive claim names are reported, because each is defensible on its own.
    """
    if not metadata.decoded:
        # A three-segment string whose header is not JSON is not a JWT, and it
        # has no claims to be missing. Reporting "no exp claim" about one would
        # be a finding about a string that was never a token.
        return ()

    observations: list[str] = []
    if metadata.unsigned:
        observations.append("declares alg none, asserting it needs no signature")
    if not metadata.has_expiry:
        observations.append("carries no exp claim, so it declares no expiry of its own")
    found = sensitive_claims(metadata)
    if found:
        observations.append(
            f"carries claim names that suggest sensitive content: {', '.join(sorted(found))}"
        )
    return tuple(observations)
