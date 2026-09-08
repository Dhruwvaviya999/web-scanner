"""SQL-injection analyzer: error signatures and differential logic.

Pure — text in, classification out. No network, no database.
"""

from __future__ import annotations

from app.scanner.vulnerabilities.sqli.analyzer import (
    analyze_error_signals,
    assess_differential,
    is_material_difference,
)
from app.scanner.vulnerabilities.sqli.types import (
    DatabaseFamily,
    DifferentialSignal,
    ErrorSignalStrength,
)


def family(text: str) -> DatabaseFamily | None:
    analysis = analyze_error_signals(text)
    return analysis.primary.family if analysis.primary else None


# =========================================================================== #
# Error signatures — one per engine
# =========================================================================== #


def test_postgresql_error():
    text = 'ERROR: unterminated quoted string at or near "\'" at character 42'
    assert family(text) is DatabaseFamily.POSTGRESQL
    assert analyze_error_signals(text).strength is ErrorSignalStrength.STRONG


def test_mysql_error():
    text = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
    assert family(text) is DatabaseFamily.MYSQL


def test_mariadb_error():
    text = "check the manual that corresponds to your MariaDB server version for the right syntax"
    assert family(text) is DatabaseFamily.MYSQL  # same family enum


def test_sql_server_error():
    text = "Unclosed quotation mark after the character string ''. Incorrect syntax near 'x'."
    assert family(text) is DatabaseFamily.MSSQL


def test_oracle_error():
    text = "ORA-00933: SQL command not properly ended"
    assert family(text) is DatabaseFamily.ORACLE


def test_sqlite_error():
    text = 'sqlite3.OperationalError: near "\'": syntax error'
    assert family(text) is DatabaseFamily.SQLITE


def test_generic_driver_error():
    text = "SQLSTATE[42000]: Syntax error or access violation: 1064"
    assert family(text) is DatabaseFamily.GENERIC
    assert analyze_error_signals(text).strength is ErrorSignalStrength.STRONG


# =========================================================================== #
# False-positive control on the signatures themselves
# =========================================================================== #


def test_page_mentioning_sql_is_not_a_database_error():
    for text in (
        "<h1>Learn SQL in 21 days</h1><p>Our SQL tutorial covers SELECT and JOIN.</p>",
        "Structured Query Language (SQL) is a database language.",
        "Download our MySQL cheat sheet and PostgreSQL reference guide.",
        "Contact the SQL team at sql@example.com about database training.",
    ):
        assert analyze_error_signals(text).strength is ErrorSignalStrength.NONE, text


def test_ordinary_error_page_without_database_indicators_is_ignored():
    for text in (
        "<h1>500 Internal Server Error</h1><p>Something went wrong.</p>",
        "<h1>404 Not Found</h1>",
        "An error occurred while processing your request. Please try again.",
        "Validation error: the email field is required.",
    ):
        assert analyze_error_signals(text).strength is ErrorSignalStrength.NONE, text


def test_case_variation_is_handled():
    lower = "you have an error in your sql syntax"
    upper = "YOU HAVE AN ERROR IN YOUR SQL SYNTAX"
    mixed = "You Have An Error In Your SQL Syntax"
    for text in (lower, upper, mixed):
        assert family(text) is DatabaseFamily.MYSQL, text


def test_whitespace_and_surrounding_markup_do_not_prevent_recognition():
    text = "<div class='err'>\n  ORA-01756: quoted string not properly terminated\n</div>"
    assert family(text) is DatabaseFamily.ORACLE


def test_multiple_signatures_prefer_the_strong_one():
    text = "PDOException: SQLSTATE[42000] You have an error in your SQL syntax near '\"'"
    analysis = analyze_error_signals(text)
    assert analysis.strength is ErrorSignalStrength.STRONG
    assert len(analysis.signals) >= 2


def test_dynamic_noise_does_not_hide_the_signal():
    text = (
        '{"request_id":"a1b2c3d4","timestamp":"2026-09-08T10:00:00Z",'
        '"error":"sqlite3.OperationalError: near \\"\'\\": syntax error"}'
    )
    assert family(text) is DatabaseFamily.SQLITE


def test_empty_response_has_no_signal():
    assert analyze_error_signals("").strength is ErrorSignalStrength.NONE


def test_signature_label_never_leaks_matched_text():
    """The stored signature is a fixed label, not the matched string."""
    text = "ORA-00933: SQL command near 'secret_table_name'"
    signal = analyze_error_signals(text).primary
    assert signal is not None
    assert "secret_table_name" not in signal.signature
    assert signal.signature == "oracle_ora"


# =========================================================================== #
# Differential logic
# =========================================================================== #


def sig(true_sim: float, false_sim: float) -> DifferentialSignal:
    return DifferentialSignal(true_similarity=true_sim, false_similarity=false_sim,
                              reproduced=False)


def test_true_resembles_baseline_false_differs_is_material():
    assert is_material_difference(0.99, 0.55) is True


def test_true_that_already_differs_is_not_material():
    # If the "true" probe doesn't track the baseline, the pattern is not boolean.
    assert is_material_difference(0.80, 0.40) is False


def test_two_near_identical_responses_are_not_material():
    assert is_material_difference(0.99, 0.985) is False


def test_small_difference_is_not_material():
    assert is_material_difference(0.99, 0.93) is False  # below the margin


def test_single_material_observation_is_insufficient():
    """One clean differential is noise; a finding needs reproduction."""
    strong = sig(0.99, 0.5)
    assert assess_differential(strong, None) is False


def test_reproduced_material_difference_is_sufficient():
    strong = sig(0.99, 0.5)
    assert assess_differential(strong, sig(0.98, 0.52)) is True


def test_first_material_but_second_not_is_insufficient():
    assert assess_differential(sig(0.99, 0.5), sig(0.99, 0.99)) is False


def test_status_only_change_does_not_satisfy_the_body_rule():
    """status_differs is recorded but is not what the differential turns on."""
    signal = DifferentialSignal(true_similarity=0.99, false_similarity=0.985,
                                reproduced=False, status_differs=True)
    assert is_material_difference(signal.true_similarity, signal.false_similarity) is False
