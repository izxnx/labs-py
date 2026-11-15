"""Модульні тести перевірки даних і правила варіанта 8.

Варіант 8: score >= 9.0 і cvssData.scope == "CHANGED".
"""

import copy
import json
from pathlib import Path

import pytest

from labs.lab04 import analysis
from labs.lab04.tests.factories import (
    CVE_ID,
    MISSING,
    make_empty_payload,
    make_metric,
    make_payload,
)

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"
VARIANT = 8
RULE_8 = {"threshold": 9.0, "field": "scope", "expected": "CHANGED"}
REPORT_KEYS = {
    "cve_id",
    "variant",
    "description",
    "vuln_status",
    "cvss_version",
    "score",
    "score_source",
    "vector",
    "rule",
    "observed",
    "decision",
}


def run(payload, variant=VARIANT):
    record = analysis.extract_record(payload, CVE_ID)
    return analysis.build_report(record, CVE_ID, variant)


def single_metric(**kwargs):
    return {"cvssMetricV31": [make_metric(**kwargs)]}


# --- Правило варіанта: межа порога та ознака --------------------------


@pytest.mark.parametrize(
    ("score", "scope", "expected"),
    [
        (8.9, "CHANGED", "other"),  # нижче порога
        (9.0, "CHANGED", "review"),  # рівно на порозі
        (9.1, "CHANGED", "review"),  # вище порога
        (10.0, "UNCHANGED", "other"),  # висока оцінка, інша ознака
        (0, "CHANGED", "other"),  # нижня межа діапазону
        (10, "CHANGED", "review"),  # ціле число як оцінка
    ],
)
def test_decision_by_score_and_scope(score, scope, expected):
    payload = make_payload(single_metric(score=score, scope=scope))
    report = run(payload)
    assert report["decision"] == expected
    assert report["observed"] == scope
    assert report["score"] == score


def test_full_report_for_review():
    report = run(make_payload())
    assert report == {
        "cve_id": CVE_ID,
        "variant": 8,
        "description": "Synthetic vulnerability for tests.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 9.8,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "rule": RULE_8,
        "observed": "CHANGED",
        "decision": "review",
    }


# --- Синтетичний файл: очікування для всіх варіантів ------------------


@pytest.mark.parametrize(
    ("variant", "expected"),
    [(n, "review") for n in range(1, 8)]
    + [(n, "other") for n in range(8, 16)],
)
def test_sample_file_decision_per_variant(variant, expected):
    payload = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    assert run(payload, variant)["decision"] == expected


# --- Стани not_found, rejected, insufficient_data ---------------------


def test_not_found_keeps_only_id_variant_and_rule():
    record = analysis.extract_record(make_empty_payload(), CVE_ID)
    assert record is None
    report = analysis.build_report(record, CVE_ID, VARIANT)
    assert set(report) == REPORT_KEYS
    assert report == {
        "cve_id": CVE_ID,
        "variant": 8,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": RULE_8,
        "observed": None,
        "decision": "not_found",
    }


def test_rejected_ignores_high_score():
    report = run(make_payload(status="Rejected"))
    assert report["decision"] == "rejected"
    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Synthetic vulnerability for tests."
    for key in ("score", "score_source", "cvss_version", "vector"):
        assert report[key] is None
    assert report["observed"] is None


def test_rejected_does_not_validate_scores():
    payload = make_payload(metrics=None, status="Rejected")
    payload["vulnerabilities"][0]["cve"]["metrics"] = "broken"
    assert run(payload)["decision"] == "rejected"


def test_missing_status_gives_insufficient_data_without_scores():
    report = run(make_payload(status=MISSING))
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] is None
    assert report["description"] == "Synthetic vulnerability for tests."
    assert report["score"] is None
    assert report["observed"] is None


@pytest.mark.parametrize(
    "metrics",
    [MISSING, {}, {"cvssMetricV31": []}, {"cvssMetricV30": [{}]}],
    ids=["no-metrics", "no-v31", "empty-v31", "only-other-version"],
)
def test_missing_v31_score_gives_insufficient_data(metrics):
    report = run(make_payload(metrics=metrics))
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] == "Analyzed"
    assert report["score"] is None
    assert report["observed"] is None


def test_missing_scope_field_gives_insufficient_data():
    report = run(make_payload(single_metric(scope=MISSING)))
    assert report["decision"] == "insufficient_data"
    assert report["score"] == 9.8
    assert report["observed"] is None


# --- Помилки поля варіанта --------------------------------------------


@pytest.mark.parametrize("scope", [None, "changed", "PARTIAL", 1, True, ""])
def test_invalid_scope_raises(scope):
    payload = make_payload(single_metric(scope=scope))
    with pytest.raises(ValueError):
        run(payload)


# --- Вибір оцінки -----------------------------------------------------


def test_primary_has_priority_over_earlier_secondary():
    metrics = {
        "cvssMetricV31": [
            make_metric(
                source="vendor@example.invalid",
                metric_type="Secondary",
                score=5.0,
                scope="UNCHANGED",
            ),
            make_metric(score=9.5, scope="CHANGED"),
        ]
    }
    report = run(make_payload(metrics))
    assert report["score"] == 9.5
    assert report["score_source"] == "nvd@nist.gov"
    assert report["decision"] == "review"


def test_first_primary_is_selected_among_several():
    metrics = {
        "cvssMetricV31": [
            make_metric(source="first@example.invalid", score=9.2),
            make_metric(source="second@example.invalid", score=3.0),
        ]
    }
    report = run(make_payload(metrics))
    assert report["score_source"] == "first@example.invalid"
    assert report["score"] == 9.2


def test_without_primary_first_metric_is_selected():
    metrics = {
        "cvssMetricV31": [
            make_metric(
                source="a@example.invalid",
                metric_type="Secondary",
                score=9.9,
                scope="CHANGED",
            ),
            make_metric(
                source="b@example.invalid",
                metric_type="Secondary",
                score=2.0,
                scope="UNCHANGED",
            ),
        ]
    }
    report = run(make_payload(metrics))
    assert report["score_source"] == "a@example.invalid"
    assert report["decision"] == "review"


def test_score_and_field_come_from_same_metric():
    # Висока оцінка Secondary і CHANGED не поєднуються з Primary.
    metrics = {
        "cvssMetricV31": [
            make_metric(metric_type="Secondary", score=10.0, scope="CHANGED"),
            make_metric(metric_type="Primary", score=8.0, scope="CHANGED"),
        ]
    }
    assert run(make_payload(metrics))["decision"] == "other"


def test_optional_report_fields_absent_are_none():
    metric = make_metric(source=MISSING, version=MISSING, vectorString=MISSING)
    report = run(make_payload({"cvssMetricV31": [metric]}))
    assert report["score_source"] is None
    assert report["cvss_version"] is None
    assert report["vector"] is None
    assert report["decision"] == "review"


# --- Помилки структури ------------------------------------------------


@pytest.mark.parametrize(
    "score",
    [True, False, "9.8", None, float("nan"), float("inf"), -0.1, 10.1],
    ids=["true", "false", "str", "null", "nan", "inf", "below", "above"],
)
def test_invalid_base_score_raises(score):
    payload = make_payload(single_metric(score=score))
    with pytest.raises(ValueError):
        run(payload)


def test_missing_base_score_raises():
    payload = make_payload(single_metric(score=MISSING))
    with pytest.raises(ValueError):
        run(payload)


@pytest.mark.parametrize(
    "metrics",
    [
        None,
        [],
        {"cvssMetricV31": None},
        {"cvssMetricV31": {}},
        {"cvssMetricV31": ["oops"]},
        {"cvssMetricV31": [make_metric(), 42]},
        {"cvssMetricV31": [{"type": "Primary", "cvssData": None}]},
        {"cvssMetricV31": [{"type": "Primary"}]},
    ],
    ids=[
        "metrics-null",
        "metrics-list",
        "v31-null",
        "v31-dict",
        "item-str",
        "second-item-int",
        "cvssdata-null",
        "cvssdata-missing",
    ],
)
def test_malformed_metrics_raise(metrics):
    payload = make_payload()
    payload["vulnerabilities"][0]["cve"]["metrics"] = metrics
    with pytest.raises(ValueError):
        run(payload)


@pytest.mark.parametrize(
    "overrides",
    [
        {"version": "3.0"},
        {"version": ""},
        {"vectorString": ""},
        {"vectorString": None},
    ],
)
def test_invalid_present_optional_cvss_fields_raise(overrides):
    payload = make_payload(single_metric(**overrides))
    with pytest.raises(ValueError):
        run(payload)


@pytest.mark.parametrize("source", [None, "", "   ", 5])
def test_invalid_source_raises(source):
    payload = make_payload(single_metric(source=source))
    with pytest.raises(ValueError):
        run(payload)


@pytest.mark.parametrize("status", [None, "", "  ", 3])
def test_invalid_status_raises(status):
    with pytest.raises(ValueError):
        run(make_payload(status=status))


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        "text",
        {},
        {"vulnerabilities": None},
        {"vulnerabilities": {}},
        {"vulnerabilities": ["x"]},
        {"vulnerabilities": [{}]},
        {"vulnerabilities": [{"cve": None}]},
    ],
    ids=[
        "null",
        "list",
        "str",
        "no-vulnerabilities",
        "vuln-null",
        "vuln-dict",
        "item-str",
        "item-no-cve",
        "cve-null",
    ],
)
def test_malformed_payload_raises(payload):
    with pytest.raises(ValueError):
        analysis.extract_record(payload, CVE_ID)


def test_more_than_one_vulnerability_raises():
    payload = make_payload()
    payload["vulnerabilities"].append(
        copy.deepcopy(payload["vulnerabilities"][0])
    )
    with pytest.raises(ValueError):
        analysis.extract_record(payload, CVE_ID)


def test_mismatched_cve_id_raises():
    payload = make_payload(cve_id="CVE-2099-99999")
    with pytest.raises(ValueError):
        analysis.extract_record(payload, CVE_ID)


# --- Описи ------------------------------------------------------------


def test_first_non_empty_english_description_is_selected():
    descriptions = [
        {"lang": "es", "value": "Descripción"},
        {"lang": "en", "value": "   "},
        {"lang": "en", "value": "Second English text."},
        {"lang": "en", "value": "Third English text."},
    ]
    report = run(make_payload(descriptions=descriptions))
    assert report["description"] == "Second English text."


@pytest.mark.parametrize(
    "descriptions",
    [MISSING, [], [{"lang": "es", "value": "Solo español"}]],
)
def test_no_english_description_gives_none(descriptions):
    report = run(make_payload(descriptions=descriptions))
    assert report["description"] is None
    assert report["decision"] == "review"


@pytest.mark.parametrize(
    "descriptions",
    [
        {"lang": "en"},
        ["text"],
        [{"lang": "en"}],
        [{"lang": None, "value": "x"}],
    ],
)
def test_malformed_descriptions_raise(descriptions):
    with pytest.raises(ValueError):
        run(make_payload(descriptions=descriptions))


# --- Контракт функцій -------------------------------------------------


def test_extract_and_build_do_not_modify_payload():
    payload = make_payload()
    original = copy.deepcopy(payload)
    run(payload)
    assert payload == original


@pytest.mark.parametrize("variant", [0, 16, -1, True, "8", 8.0, None])
def test_invalid_variant_raises(variant):
    with pytest.raises(ValueError):
        analysis.build_report(None, CVE_ID, variant)


def test_report_always_has_all_keys():
    for payload in (make_empty_payload(), make_payload()):
        assert set(run(payload)) == REPORT_KEYS
