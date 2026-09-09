"""Summarising a JSON response without keeping any of it.

The scanner wants to say "this endpoint returns objects with `id`, `email` and
`role`" because that describes the interface a reviewer is assessing. It must
never say what was in those fields, because that is where the customer's email
address, the session identifier and the API key live.

So this module produces a `JsonShape`: a top-level type, a bounded list of field
*names*, a depth and a count. Values are read during parsing — they have to be,
to walk the structure — and then discarded with the parsed document when the
function returns. Nothing here returns, stores or logs one.

Everything is bounded. A hostile or merely enormous document must not be able to
turn a summary into an out-of-memory or a stack overflow, so both breadth and
depth stop at a configured limit and say that they did.
"""

from __future__ import annotations

import json
from typing import Any

from app.scanner.api.types import ApiDiscoveryLimits, JsonShape

#: Names whose *values* are sensitive. The name itself is safe to record — that
#: an endpoint returns a field called `access_token` is exactly the sort of thing
#: a reviewer needs to know — but it is listed here so that any future code
#: tempted to keep a sample value has a ready answer for which ones never can be.
SENSITIVE_FIELD_NAMES = frozenset(
    {
        "access_token",
        "accesstoken",
        "api_key",
        "apikey",
        "authorization",
        "client_secret",
        "cookie",
        "credentials",
        "id_token",
        "jwt",
        "password",
        "passwd",
        "private_key",
        "refresh_token",
        "secret",
        "session",
        "session_id",
        "sessionid",
        "token",
    }
)


def looks_sensitive(field_name: str) -> bool:
    """Whether a field name suggests its value is a credential.

    Used to flag an interface for a reviewer, never to decide whether to store a
    value — no value is stored either way.
    """
    normalised = field_name.strip().lower().replace("-", "_")
    if normalised in SENSITIVE_FIELD_NAMES:
        return True
    return any(marker in normalised for marker in ("password", "secret", "token", "apikey"))


def parse_json_body(body: bytes | str) -> Any | None:
    """Parse a body as JSON, or return None. Never raises.

    A body that does not parse is simply not JSON, which is an ordinary answer
    and not an error worth failing a scan over.
    """
    if not body:
        return None
    try:
        text = body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    except Exception:  # noqa: BLE001 - a decode failure means "not JSON"
        return None

    stripped = text.strip()
    if not stripped or stripped[0] not in "[{\"-0123456789tfn":
        # Cheap rejection before handing a large HTML page to the JSON parser.
        return None

    try:
        return json.loads(stripped)
    except (ValueError, RecursionError):
        return None


def summarize_json(
    document: Any, limits: ApiDiscoveryLimits | None = None
) -> JsonShape:
    """Reduce a parsed JSON document to structure.

    Field names are collected breadth-first from the top level down, so the
    names a reviewer most wants — the shape of the resource itself — survive the
    budget, and deeply nested detail is what gets dropped.
    """
    bounds = limits or ApiDiscoveryLimits()

    if isinstance(document, dict):
        top_level = "object"
    elif isinstance(document, list):
        top_level = "array"
    else:
        return JsonShape(top_level="scalar", field_names=(), depth=0, field_count=0)

    names: list[str] = []
    seen: set[str] = set()
    field_count = 0
    max_depth = 0
    truncated = False

    # Breadth-first, with an explicit queue rather than recursion: a document
    # nested a thousand levels deep must bound the work, not the stack.
    queue: list[tuple[Any, int]] = [(document, 0)]
    while queue:
        node, depth = queue.pop(0)
        max_depth = max(max_depth, depth)

        if depth >= bounds.max_json_depth:
            truncated = True
            continue

        if isinstance(node, dict):
            for key, value in node.items():
                field_count += 1
                name = str(key)
                if name not in seen:
                    if len(names) >= bounds.max_json_fields:
                        truncated = True
                    else:
                        seen.add(name)
                        names.append(name)
                if isinstance(value, (dict, list)):
                    queue.append((value, depth + 1))
        elif isinstance(node, list):
            # Only the first few elements: a thousand-item collection has the
            # same shape as its first element, and walking all of it buys
            # nothing but time.
            for value in node[:3]:
                if isinstance(value, (dict, list)):
                    queue.append((value, depth + 1))

    return JsonShape(
        top_level=top_level,
        field_names=tuple(names),
        depth=max_depth,
        field_count=field_count,
        truncated=truncated,
    )


def summarize_body(
    body: bytes | str, limits: ApiDiscoveryLimits | None = None
) -> JsonShape | None:
    """Parse and summarise in one step, or return None when it is not JSON."""
    document = parse_json_body(body)
    if document is None:
        return None
    return summarize_json(document, limits)
