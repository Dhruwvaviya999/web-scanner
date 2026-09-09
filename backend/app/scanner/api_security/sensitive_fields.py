"""Classifying a field name by how sensitive it is.

A pure function from a name to a classification. It never sees a value, which is
the point: the scanner can say "this response contained a field called
`password_hash`" without ever having kept what was in it.

**The hard part is not matching, it is not over-matching.** A naive substring
search for "token" flags `token_type` (which is the literal string "Bearer"),
`page_token` (a pagination cursor), and `csrf_token_required` (a boolean). A
naive search for "password" flags `has_password`, `password_changed_at` and
`password_policy`. Each of those would be a false positive in a report a human
has to triage, so the rules below run from most to least precise:

1. **Unambiguous negations** — `has_password`, `token_type`, `page_token`. These
   are facts about a credential and never a credential, whatever else matches.
2. **Exact matches** — the highest-precision rule and the bulk of the table.
3. **Suffix negations** — `_at`, `_count`, `_policy`, `_url`. Weaker than the
   table on purpose: `password_url` is a link to a reset page and is negated,
   while `database_url` is in the table and is a credential with a hostname
   attached.
4. **Compound matches** — a sensitive head as a whole word run, so
   `user_password_hash` matches while `passwordless` does not.

Sensitivity is a property of the *name*, never of the context. Whether a field's
presence is a problem is a separate question, answered by the caller from the
authorization policy — see `types.ExposureVerdict`.
"""

from __future__ import annotations

import re

from app.scanner.api_security.types import (
    FieldCategory,
    FieldClassification,
    FieldSensitivity,
)

# --------------------------------------------------------------------------- #
# Negative patterns: names that mention a secret without being one
# --------------------------------------------------------------------------- #

#: Booleans and metadata *about* a credential. `has_password` says whether one
#: is set; it is not one. Checked before every positive rule.
_NEGATIVE_PREFIXES = ("has_", "is_", "can_", "should_", "requires_", "needs_", "use_")

#: Suffixes that turn a secret's name into a fact about it: a timestamp, a
#: count, a length, a policy, a type. `token_type` is the string "Bearer".
_NEGATIVE_SUFFIXES = (
    "_at",
    "_on",
    "_count",
    "_length",
    "_type",
    "_types",
    "_policy",
    "_policies",
    "_required",
    "_enabled",
    "_expires_in",
    "_expiry",
    "_expires",
    "_ttl",
    "_algorithm",
    "_alg",
    "_format",
    "_hint",
    "_label",
    "_name",
    "_id_type",
    "_strength",
    "_score",
    "_url",
    "_uri",
    "_endpoint",
    "_field",
    "_fields",
    "_placeholder",
)

#: Whole names that mention a credential concept but carry nothing secret.
_NEGATIVE_EXACT = frozenset(
    {
        "token_type",
        "page_token",
        "next_token",
        "next_page_token",
        "continuation_token",
        "pagination_token",
        "cursor",
        "password_policy",
        "passwordless",
        "authentication",
        "authenticated",
        "auth_method",
        "auth_methods",
        "auth_provider",
        "key",  # far too generic: a map key, a sort key, a translation key
        "keys",
        "secret_questions",
        "address_type",
        "phone_type",
    }
)


# --------------------------------------------------------------------------- #
# The rule table
# --------------------------------------------------------------------------- #

# Each entry: exact names, then category and sensitivity.
#
# HIGHLY_SENSITIVE is reserved for material that is a secret by construction —
# there is no ordinary product reason for a client to be handed someone's
# password hash, private key or access token. Everything whose sensitivity
# depends on what the application is for sits at POTENTIALLY_SENSITIVE, and the
# *context* decides whether its presence matters.

_AUTHENTICATION_HIGH = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "password_hash",
        "passwordhash",
        "pass_hash",
        "hashed_password",
        "password_digest",
        "password_salt",
        "salt",
        "secret",
        "client_secret",
        "app_secret",
        "shared_secret",
        "otp_secret",
        "totp_secret",
        "mfa_secret",
        "recovery_codes",
        "backup_codes",
    }
)

_TOKEN_HIGH = frozenset(
    {
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "bearer_token",
        "auth_token",
        "authorization",
        "api_key",
        "apikey",
        "api_secret",
        "jwt",
        "csrf_token",
        "xsrf_token",
        "reset_token",
        "activation_token",
        "verification_token",
        "invite_token",
    }
)

_SESSION_HIGH = frozenset(
    {
        "session",
        "session_id",
        "sessionid",
        "session_token",
        "session_key",
        "sid",
        "cookie",
        "cookies",
        "set_cookie",
    }
)

_CRYPTO_HIGH = frozenset(
    {
        "private_key",
        "privatekey",
        "secret_key",
        "secretkey",
        "signing_key",
        "encryption_key",
        "master_key",
        "certificate_key",
        "ssh_key",
        "pem",
    }
)

_FINANCIAL_HIGH = frozenset(
    {
        # Payment card data is a secret by construction, like a password hash:
        # there is no ordinary reason to hand a client someone else's PAN.
        "card_number",
        "cardnumber",
        "pan",
        "cvv",
        "cvc",
        "card_security_code",
        "full_card_number",
    }
)

_INFRASTRUCTURE_HIGH = frozenset(
    {
        # These embed credentials by construction — a connection string is a
        # password with a hostname attached.
        "database_url",
        "db_url",
        "connection_string",
        "dsn",
        "database_password",
        "smtp_password",
    }
)

_PERSONAL_POTENTIAL = frozenset(
    {
        "ssn",
        "social_security_number",
        "national_id",
        "nino",
        "passport",
        "passport_number",
        "date_of_birth",
        "dob",
        "birth_date",
        "birthdate",
        "phone",
        "phone_number",
        "mobile",
        "mobile_number",
        "address",
        "street_address",
        "home_address",
        "postal_code",
        "zip_code",
        "tax_id",
        "drivers_license",
        "license_number",
    }
)

_FINANCIAL_POTENTIAL = frozenset(
    {
        "bank_account",
        "account_number",
        "iban",
        "bic",
        "swift",
        "routing_number",
        "sort_code",
        "salary",
        "compensation",
    }
)

_INFRASTRUCTURE_POTENTIAL = frozenset(
    {
        "internal_ip",
        "private_ip",
        "internal_host",
        "internal_hostname",
        "internal_url",
        "server_path",
        "file_path",
        "stack_trace",
        "stacktrace",
        "traceback",
        "debug",
        "debug_info",
        "environment",
        "env",
        "config",
        "configuration",
        "internal_id",
        "internal_notes",
    }
)

_EXACT_RULES: list[tuple[frozenset[str], FieldCategory, FieldSensitivity]] = [
    (_AUTHENTICATION_HIGH, FieldCategory.AUTHENTICATION, FieldSensitivity.HIGHLY_SENSITIVE),
    (_TOKEN_HIGH, FieldCategory.TOKEN, FieldSensitivity.HIGHLY_SENSITIVE),
    (_SESSION_HIGH, FieldCategory.SESSION, FieldSensitivity.HIGHLY_SENSITIVE),
    (_CRYPTO_HIGH, FieldCategory.CRYPTOGRAPHIC, FieldSensitivity.HIGHLY_SENSITIVE),
    (_FINANCIAL_HIGH, FieldCategory.FINANCIAL, FieldSensitivity.HIGHLY_SENSITIVE),
    (
        _INFRASTRUCTURE_HIGH,
        FieldCategory.INFRASTRUCTURE,
        FieldSensitivity.HIGHLY_SENSITIVE,
    ),
    (_PERSONAL_POTENTIAL, FieldCategory.PERSONAL, FieldSensitivity.POTENTIALLY_SENSITIVE),
    (
        _FINANCIAL_POTENTIAL,
        FieldCategory.FINANCIAL,
        FieldSensitivity.POTENTIALLY_SENSITIVE,
    ),
    (
        _INFRASTRUCTURE_POTENTIAL,
        FieldCategory.INFRASTRUCTURE,
        FieldSensitivity.POTENTIALLY_SENSITIVE,
    ),
]

#: Heads that keep their meaning under a qualifier, so `user_password_hash` and
#: `admin_api_key` match. Only applied after the negative rules, and only as a
#: whole underscore-delimited run — `keyboard` never matches `key`.
_COMPOUND_HEADS: list[tuple[str, FieldCategory, FieldSensitivity]] = [
    ("password_hash", FieldCategory.AUTHENTICATION, FieldSensitivity.HIGHLY_SENSITIVE),
    ("password", FieldCategory.AUTHENTICATION, FieldSensitivity.HIGHLY_SENSITIVE),
    ("client_secret", FieldCategory.AUTHENTICATION, FieldSensitivity.HIGHLY_SENSITIVE),
    ("access_token", FieldCategory.TOKEN, FieldSensitivity.HIGHLY_SENSITIVE),
    ("refresh_token", FieldCategory.TOKEN, FieldSensitivity.HIGHLY_SENSITIVE),
    ("id_token", FieldCategory.TOKEN, FieldSensitivity.HIGHLY_SENSITIVE),
    ("api_key", FieldCategory.TOKEN, FieldSensitivity.HIGHLY_SENSITIVE),
    ("private_key", FieldCategory.CRYPTOGRAPHIC, FieldSensitivity.HIGHLY_SENSITIVE),
    ("secret_key", FieldCategory.CRYPTOGRAPHIC, FieldSensitivity.HIGHLY_SENSITIVE),
    ("signing_key", FieldCategory.CRYPTOGRAPHIC, FieldSensitivity.HIGHLY_SENSITIVE),
    ("session_token", FieldCategory.SESSION, FieldSensitivity.HIGHLY_SENSITIVE),
    ("card_number", FieldCategory.FINANCIAL, FieldSensitivity.HIGHLY_SENSITIVE),
    ("connection_string", FieldCategory.INFRASTRUCTURE, FieldSensitivity.HIGHLY_SENSITIVE),
]

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NON_WORD = re.compile(r"[^a-z0-9]+")


def normalize(name: str) -> str:
    """Reduce a field name to a comparable snake_case form.

    `apiKey`, `API-KEY` and `api key` all become `api_key`, so one rule covers
    every casing convention an API might use.
    """
    if not name:
        return ""
    spaced = _CAMEL_BOUNDARY.sub("_", name.strip())
    lowered = spaced.lower()
    return _NON_WORD.sub("_", lowered).strip("_")


def _is_strongly_negated(normalized: str) -> bool:
    """Names that are unambiguously *about* a secret, whatever else matches.

    `has_password` and `token_type` are facts, never credentials, so they are
    ruled out before any positive rule is consulted.
    """
    return normalized in _NEGATIVE_EXACT or normalized.startswith(_NEGATIVE_PREFIXES)


def _is_suffix_negated(normalized: str) -> bool:
    """Names whose *suffix* turns a secret into metadata about one.

    Checked only after the exact table, because a suffix is weaker evidence than
    a name the table already knows. `password_url` is a link to a reset page and
    is negated; `database_url` is in the table and is a credential with a
    hostname attached.
    """
    return normalized.endswith(_NEGATIVE_SUFFIXES)


def _contains_run(normalized: str, head: str) -> bool:
    """Whether `head` appears as whole underscore-delimited words.

    `user_api_key` contains the run `api_key`; `apikeyboard` does not contain
    anything. Matching on word runs rather than substrings is what keeps
    `keyboard`, `tokenizer` and `passwordless` out of the results.
    """
    parts = normalized.split("_")
    target = head.split("_")
    if len(target) > len(parts):
        return False
    for index in range(len(parts) - len(target) + 1):
        if parts[index : index + len(target)] == target:
            return True
    return False


def classify_field(name: str) -> FieldClassification:
    """Classify one field name. Pure, and never sees a value."""
    normalized = normalize(name)
    if not normalized:
        return FieldClassification(name=name)

    # 1. Unambiguous negations first, so `has_password` and `token_type` never
    #    reach a positive rule.
    if _is_strongly_negated(normalized):
        return FieldClassification(name=name, rule="negated")

    # 2. Exact matches: the highest-precision rule, and strong enough to
    #    outrank a suffix. `database_url` ends in `_url` and is still a
    #    credential.
    for names, category, sensitivity in _EXACT_RULES:
        if normalized in names:
            return FieldClassification(
                name=name, category=category, sensitivity=sensitivity, rule="exact"
            )

    # 3. Suffix negations, now that the table has had its say.
    if _is_suffix_negated(normalized):
        return FieldClassification(name=name, rule="negated")

    # 4. Compound heads, as whole word runs.
    for head, category, sensitivity in _COMPOUND_HEADS:
        if _contains_run(normalized, head):
            return FieldClassification(
                name=name, category=category, sensitivity=sensitivity, rule=f"compound:{head}"
            )

    return FieldClassification(name=name)


def classify_fields(names) -> tuple[FieldClassification, ...]:
    """Classify a sequence of names, keeping only the sensitive ones.

    Deduplicated by name: one field is one observation however many times it
    appears in a nested structure.
    """
    seen: dict[str, FieldClassification] = {}
    for name in names:
        classification = classify_field(name)
        if classification.sensitive:
            seen.setdefault(classification.name, classification)
    return tuple(seen.values())
