"""Marker generation for reflected-XSS probing.

The scanner never sends a working exploit. It sends an **inert marker**: a
random token followed by the four metacharacters that decide whether a
reflection is exploitable.

    ws4f1a9c3e0b7da"'><ws4f1a9c3e0b7db

There is no `<script>`, no event handler, no `javascript:` — nothing that does
anything if the target renders it. The metacharacters sit *between* two unique
markers, so whatever the application rendered for them is exactly the text
between those markers — never adjacent page markup. What it does is reveal, character by
character, which of `"`, `'`, `>` and `<` survive the application's output
encoding. That is the evidence the analyser reasons about, and it is enough to
classify a reflection without ever attempting execution.
"""

from __future__ import annotations

import secrets

from app.scanner.vulnerabilities.xss.types import XssProbe

#: Prefix that makes a marker recognisable in logs and unlikely to collide with
#: anything the application produces on its own.
TOKEN_PREFIX = "ws"

#: Length of the random part. 12 hex characters is ~48 bits — far beyond
#: accidental collision, and short enough to survive length-limited fields.
TOKEN_RANDOM_LENGTH = 12

#: The metacharacters whose fate decides exploitability, in a fixed order so
#: evidence is reproducible. Inert on its own: this is not a payload.
CANARY = "\"'><"

#: Characters the analyser reports on individually.
CANARY_CHARACTERS = frozenset(CANARY)


def new_token() -> str:
    """A fresh, unique, purely alphanumeric token.

    Alphanumeric on purpose: it passes through validation, escaping and
    URL-encoding unchanged, so if it fails to appear in a response the reason is
    that the value was not reflected — not that it was mangled.
    """
    return f"{TOKEN_PREFIX}{secrets.token_hex(TOKEN_RANDOM_LENGTH // 2)}"


def new_probe() -> XssProbe:
    """A marker for the encoding-sensitive request."""
    return XssProbe(token=new_token(), canary=CANARY)


def new_baseline_token() -> str:
    """A marker for the baseline request.

    Carries no metacharacters, so it establishes that the parameter is reflected
    at all before any conclusion is drawn from the probe.
    """
    return new_token()
