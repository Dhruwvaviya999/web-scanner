"""Recognising a verbose error response without keeping any of it.

**Nothing here provokes an error.** Phase 14 sends no malformed payload and no
unexpected type; it reads the failures the scan already ran into while crawling,
checking authentication and reading documentation. A scanner that manufactures
errors to look at them is fuzzing, and this phase does not fuzz.

The output is a set of *category names* — `STACK_TRACE`, `DATABASE_ERROR` — and
nothing else. No matched text, no line, no excerpt. That is what lets a finding
say "the response exposed a stack trace" without the finding becoming the very
disclosure it is reporting.

Signals are computed at capture time, next to the JSON summary, and only for
responses that actually failed. Scanning every HTML page on a site for SQL
keywords would be both wasteful and a reliable source of false positives — a
blog post about `SELECT` statements is not a database error.
"""

from __future__ import annotations

import re

from app.scanner.api_security.types import (
    STRONG_ERROR_SIGNALS,
    ErrorObservation,
    ErrorSignal,
)

#: How much of a body is examined. A debug page puts its diagnostics at the top,
#: and an unbounded scan of a large response buys nothing.
MAX_SCAN_BYTES = 16_384

#: Below this status nothing is scanned. Phase 14 reads *error* responses; a
#: 200 is the application working, and searching every successful page for
#: exception-shaped text is how a scanner invents findings.
ERROR_STATUS_FLOOR = 400


# --------------------------------------------------------------------------- #
# Patterns. Each is deliberately specific: a phrase a framework emits, not a
# word a human might write.
# --------------------------------------------------------------------------- #

_PATTERNS: list[tuple[ErrorSignal, re.Pattern[str]]] = [
    (
        ErrorSignal.STACK_TRACE,
        re.compile(
            r"traceback \(most recent call last\)"
            r"|\n\s+at [\w.$<>]+\("
            r"|\n\s*at [\w.]+\.[\w$]+\("
            r"|exception in thread"
            r"|\bstack trace:"
            r'|file "[^"]+", line \d+',
            re.IGNORECASE,
        ),
    ),
    (
        ErrorSignal.FILESYSTEM_PATH,
        re.compile(
            r"/(?:var/www|usr/local|usr/share|home/\w|opt/\w|srv/\w|app/\w)/"
            r"|[a-z]:\\\\?(?:users|program files|inetpub|windows)\\"
            r"|site-packages/"
            r"|node_modules/",
            re.IGNORECASE,
        ),
    ),
    (
        ErrorSignal.DATABASE_ERROR,
        re.compile(
            r"sqlstate\["
            r"|\bora-\d{4,5}\b"
            r"|psycopg2?\.\w+"
            r"|sqlite3\.\w+error"
            r"|mysql server"
            r"|\bpg::\w+"
            r"|sqlalchemy\.exc"
            r"|duplicate key value violates"
            r"|column .* does not exist"
            r"|you have an error in your sql syntax",
            re.IGNORECASE,
        ),
    ),
    (
        ErrorSignal.SQL_STATEMENT,
        re.compile(
            r"\bselect\b[\s\S]{1,200}?\bfrom\b\s+[\w.\"`\[]"
            r"|\binsert\s+into\b\s+[\w.\"`\[]"
            r"|\bupdate\b\s+[\w.\"`\[][\s\S]{1,120}?\bset\b"
            r"|\bdelete\s+from\b\s+[\w.\"`\[]",
            re.IGNORECASE,
        ),
    ),
    (
        ErrorSignal.FRAMEWORK_DEBUG,
        re.compile(
            r"werkzeug debugger"
            r"|django\.core\.exceptions"
            r"|whoops, looks like something went wrong"
            r"|\brails\.root\b"
            r"|asp\.net.{0,40}(?:version|error)"
            r"|<title>\s*server error"
            r"|symfony\\component"
            r"|\bdebug\s*[=:]\s*true"
            r"|laravel\\",
            re.IGNORECASE,
        ),
    ),
    (
        ErrorSignal.EXCEPTION_CLASS,
        # A qualified exception type: `com.example.FooException`,
        # `django.db.utils.IntegrityError`. A bare `ValueError` is far too
        # common in ordinary prose to count.
        re.compile(r"\b[a-z][\w]*(?:\.[\w]+){2,}(?:Error|Exception)\b"),
    ),
    (
        ErrorSignal.INTERNAL_HOST,
        re.compile(
            r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b"
            r"|\b[\w-]+\.(?:internal|local|lan|corp)\b",
            re.IGNORECASE,
        ),
    ),
    (
        ErrorSignal.ENVIRONMENT_DUMP,
        re.compile(
            r"\bDATABASE_URL\b"
            r"|\bSECRET_KEY\b"
            r"|\bAWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY)\b"
            r"|\bDJANGO_SETTINGS_MODULE\b"
            r"|\bos\.environ\b"
        ),
    ),
]


def detect_error_signals(
    body: bytes | str, *, status_code: int, content_type: str | None = None
) -> tuple[ErrorSignal, ...]:
    """Which diagnostic categories a failed response exposed.

    Returns category names only — never the text that matched. Nothing is
    scanned below `ERROR_STATUS_FLOOR`, and only a bounded prefix is read.
    """
    if status_code < ERROR_STATUS_FLOOR or not body:
        return ()

    if isinstance(body, bytes):
        text = body[:MAX_SCAN_BYTES].decode("utf-8", "replace")
    else:
        text = body[:MAX_SCAN_BYTES]

    if not text.strip():
        return ()

    signals: list[ErrorSignal] = []
    for signal, pattern in _PATTERNS:
        try:
            if pattern.search(text):
                signals.append(signal)
        except Exception:  # noqa: BLE001 - a regex must never end a crawl
            continue
    return tuple(signals)


def safe_detect(
    body: bytes | str, *, status_code: int, content_type: str | None = None
) -> tuple[ErrorSignal, ...]:
    """`detect_error_signals`, guaranteed not to raise.

    Called from the crawler's capture step, which has no guard of its own: an
    exception here would unwind a crawl that has already gathered fifty pages.
    """
    try:
        return detect_error_signals(
            body, status_code=status_code, content_type=content_type
        )
    except Exception:  # noqa: BLE001
        return ()


def analyze(
    *,
    url: str,
    method: str,
    status_code: int,
    content_type: str | None,
    signals: tuple[ErrorSignal, ...],
    body_length: int = 0,
) -> ErrorObservation | None:
    """Turn detected signals into an observation, or nothing.

    A single weak signal is not enough. A filesystem path alone might be a
    legitimate resource name in an error message, and an exception class alone
    might be an API's own documented error code. One *strong* signal — a stack
    trace, a database error, a framework debug page — is conclusive on its own,
    and two weak ones together are enough to be worth a reader's attention.
    """
    if not signals:
        return None

    strong = set(signals) & STRONG_ERROR_SIGNALS
    if not strong and len(set(signals)) < 2:
        return None

    return ErrorObservation(
        url=url,
        method=method,
        status_code=status_code,
        content_type=content_type,
        signals=tuple(dict.fromkeys(signals)),
        body_length=body_length,
    )
