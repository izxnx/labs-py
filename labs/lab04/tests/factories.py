"""Фабрики синтетичних відповідей NVD для тестів.

Кожен виклик створює новий словник, тому тести не впливають один на одного.
"""

from typing import Any

CVE_ID = "CVE-2099-10001"

# Позначка «поле відсутнє» для параметрів фабрик.
MISSING = object()


def make_cvss_data(
    score: Any = 9.8, scope: Any = "CHANGED", **overrides: Any
) -> dict[str, Any]:
    """Повертає новий cvssData; значення MISSING видаляє поле."""
    data: dict[str, Any] = {
        "version": "3.1",
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "attackVector": "NETWORK",
        "attackComplexity": "LOW",
        "privilegesRequired": "NONE",
        "userInteraction": "NONE",
        "scope": scope,
        "confidentialityImpact": "HIGH",
        "integrityImpact": "HIGH",
        "availabilityImpact": "HIGH",
        "baseScore": score,
        "baseSeverity": "CRITICAL",
    }
    data.update(overrides)
    return {key: value for key, value in data.items() if value is not MISSING}


def make_metric(
    source: Any = "nvd@nist.gov",
    metric_type: Any = "Primary",
    **cvss_kwargs: Any,
) -> dict[str, Any]:
    """Повертає новий елемент cvssMetricV31."""
    metric: dict[str, Any] = {
        "source": source,
        "type": metric_type,
        "cvssData": make_cvss_data(**cvss_kwargs),
    }
    return {
        key: value for key, value in metric.items() if value is not MISSING
    }


def make_payload(
    metrics: Any = None,
    status: Any = "Analyzed",
    cve_id: str = CVE_ID,
    descriptions: Any = None,
) -> dict[str, Any]:
    """Повертає нову відповідь NVD з одним записом.

    ``metrics=None`` означає одну Primary-оцінку 9.8 зі scope=CHANGED;
    MISSING для ``metrics``/``status``/``descriptions`` видаляє поле.
    """
    if metrics is None:
        metrics = {"cvssMetricV31": [make_metric()]}
    if descriptions is None:
        descriptions = [
            {"lang": "en", "value": "Synthetic vulnerability for tests."}
        ]
    cve: dict[str, Any] = {
        "id": cve_id,
        "vulnStatus": status,
        "descriptions": descriptions,
        "metrics": metrics,
        "references": [],
    }
    cve = {key: value for key, value in cve.items() if value is not MISSING}
    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_CVE",
        "version": "2.0",
        "vulnerabilities": [{"cve": cve}],
    }


def make_empty_payload() -> dict[str, Any]:
    """Повертає порожній результат пошуку."""
    return {
        "resultsPerPage": 0,
        "startIndex": 0,
        "totalResults": 0,
        "format": "NVD_CVE",
        "version": "2.0",
        "vulnerabilities": [],
    }
