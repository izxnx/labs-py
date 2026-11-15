"""Перевірка відповіді NVD і застосування правила варіанта.

Функції модуля працюють лише з переданими аргументами: не читають файлів
і змінних середовища, не виконують HTTP-запитів, нічого не друкують і не
змінюють отриманий ``payload``. Порушення контракту даних позначається
винятком ``ValueError``.
"""

import copy
import math
from typing import Any

# Номер варіанта -> (поріг T, поле cvssData, очікуване значення).
VARIANT_RULES: dict[int, tuple[float, str, str]] = {
    1: (7.0, "attackVector", "NETWORK"),
    2: (8.0, "attackComplexity", "LOW"),
    3: (7.0, "privilegesRequired", "NONE"),
    4: (8.0, "userInteraction", "NONE"),
    5: (7.0, "confidentialityImpact", "HIGH"),
    6: (7.0, "integrityImpact", "HIGH"),
    7: (7.0, "availabilityImpact", "HIGH"),
    8: (9.0, "scope", "CHANGED"),
    9: (5.0, "attackVector", "LOCAL"),
    10: (6.0, "privilegesRequired", "LOW"),
    11: (6.0, "userInteraction", "REQUIRED"),
    12: (6.0, "confidentialityImpact", "LOW"),
    13: (6.0, "integrityImpact", "LOW"),
    14: (6.0, "availabilityImpact", "LOW"),
    15: (8.0, "attackComplexity", "HIGH"),
}

_IMPACT = frozenset({"NONE", "LOW", "HIGH"})
ALLOWED_VALUES: dict[str, frozenset[str]] = {
    "attackVector": frozenset(
        {"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"}
    ),
    "attackComplexity": frozenset({"LOW", "HIGH"}),
    "privilegesRequired": frozenset({"NONE", "LOW", "HIGH"}),
    "userInteraction": frozenset({"NONE", "REQUIRED"}),
    "scope": frozenset({"UNCHANGED", "CHANGED"}),
    "confidentialityImpact": _IMPACT,
    "integrityImpact": _IMPACT,
    "availabilityImpact": _IMPACT,
}

REJECTED_STATUS = "Rejected"


def _optional_text(
    container: dict[str, Any], key: str, where: str
) -> str | None:
    """Повертає None для відсутнього поля або непорожній рядок."""
    if key not in container:
        return None
    value = container[key]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{where}.{key} має бути непорожнім рядком")
    return value


def _english_description(cve: dict[str, Any]) -> str | None:
    """Повертає перший непорожній англійський опис або None."""
    if "descriptions" not in cve:
        return None
    descriptions = cve["descriptions"]
    if not isinstance(descriptions, list):
        raise ValueError("cve.descriptions має бути списком")
    for index, item in enumerate(descriptions):
        if not isinstance(item, dict):
            raise ValueError(f"cve.descriptions[{index}] має бути об'єктом")
        lang = item.get("lang")
        value = item.get("value")
        if not isinstance(lang, str) or not isinstance(value, str):
            raise ValueError(
                f"cve.descriptions[{index}] має містити рядки lang і value"
            )
    for item in descriptions:
        if item["lang"] == "en" and item["value"].strip():
            return item["value"]
    return None


def _select_metric(cve: dict[str, Any]) -> dict[str, Any] | None:
    """Вибирає першу оцінку Primary, інакше першу оцінку v3.1."""
    if "metrics" not in cve:
        return None
    metrics = cve["metrics"]
    if not isinstance(metrics, dict):
        raise ValueError("cve.metrics має бути об'єктом")
    if "cvssMetricV31" not in metrics:
        return None
    items = metrics["cvssMetricV31"]
    if not isinstance(items, list):
        raise ValueError("metrics.cvssMetricV31 має бути списком")
    if not items:
        return None
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f"cvssMetricV31[{index}] має бути об'єктом")
    for item in items:
        if item.get("type") == "Primary":
            return item
    return items[0]


def _validate_score(value: Any) -> int | float:
    """Перевіряє, що baseScore — скінченне число 0–10, не bool."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("cvssData.baseScore має бути числом")
    if not math.isfinite(value) or not 0 <= value <= 10:
        raise ValueError("cvssData.baseScore має бути в межах від 0 до 10")
    return value


def extract_record(payload: Any, cve_id: str) -> dict[str, Any] | None:
    """Перевіряє відповідь NVD і повертає внутрішній запис або None.

    None означає, що пошук повернув порожній ``vulnerabilities``.
    Внутрішній запис — словник із ключами:

    - ``vuln_status``: ``str | None`` — статус NVD;
    - ``description``: ``str | None`` — перший непорожній опис ``en``;
    - ``score``: ``int | float | None`` — ``baseScore`` вибраної оцінки;
    - ``score_source``: ``str | None`` — ``source`` вибраної оцінки;
    - ``cvss_version``: ``str | None`` — ``"3.1"`` або None;
    - ``vector``: ``str | None`` — ``vectorString``;
    - ``cvss_data``: ``dict | None`` — глибока копія ``cvssData``
      вибраної оцінки (поле варіанта перевіряє ``build_report``).

    Для статусу ``Rejected`` або відсутнього статусу оцінки не
    аналізуються: ``score``, ``score_source``, ``cvss_version``,
    ``vector`` і ``cvss_data`` дорівнюють None. Так само вони None, якщо
    оцінки CVSS v3.1 немає.
    """
    if not isinstance(cve_id, str):
        raise ValueError("Ідентифікатор CVE має бути рядком")
    if not isinstance(payload, dict):
        raise ValueError("Відповідь має бути JSON-об'єктом")
    if "vulnerabilities" not in payload:
        raise ValueError("Відповідь не містить vulnerabilities")
    vulnerabilities = payload["vulnerabilities"]
    if not isinstance(vulnerabilities, list):
        raise ValueError("vulnerabilities має бути списком")
    if not vulnerabilities:
        return None
    if len(vulnerabilities) > 1:
        raise ValueError(
            "Для точного ідентифікатора очікується не більше одного запису"
        )

    item = vulnerabilities[0]
    if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
        raise ValueError("vulnerabilities[0] має містити об'єкт cve")
    cve = item["cve"]
    if cve.get("id") != cve_id:
        raise ValueError(
            "Ідентифікатор у відповіді не збігається із запитаним"
        )

    record: dict[str, Any] = {
        "vuln_status": _optional_text(cve, "vulnStatus", "cve"),
        "description": _english_description(cve),
        "score": None,
        "score_source": None,
        "cvss_version": None,
        "vector": None,
        "cvss_data": None,
    }
    status = record["vuln_status"]
    if status is None or status == REJECTED_STATUS:
        return record

    metric = _select_metric(cve)
    if metric is None:
        return record

    cvss_data = metric.get("cvssData")
    if not isinstance(cvss_data, dict):
        raise ValueError("Вибрана оцінка має містити об'єкт cvssData")
    if "baseScore" not in cvss_data:
        raise ValueError("cvssData не містить baseScore")

    version = _optional_text(cvss_data, "version", "cvssData")
    if version is not None and version != "3.1":
        raise ValueError('cvssData.version має дорівнювати "3.1"')

    record["score"] = _validate_score(cvss_data["baseScore"])
    record["score_source"] = _optional_text(metric, "source", "cvssMetricV31")
    record["cvss_version"] = version
    record["vector"] = _optional_text(cvss_data, "vectorString", "cvssData")
    record["cvss_data"] = copy.deepcopy(cvss_data)
    return record


def get_rule(variant: int) -> tuple[float, str, str]:
    """Повертає (поріг, поле, очікуване значення) для варіанта 1–15."""
    if (
        isinstance(variant, bool)
        or not isinstance(variant, int)
        or variant not in VARIANT_RULES
    ):
        raise ValueError("Номер варіанта має бути цілим числом від 1 до 15")
    return VARIANT_RULES[variant]


def build_report(
    record: dict[str, Any] | None, cve_id: str, variant: int
) -> dict[str, Any]:
    """Застосовує правило варіанта до запису та повертає словник звіту.

    Рішення: ``not_found`` → ``rejected`` → ``insufficient_data`` →
    ``review`` (``score >= T`` і поле дорівнює ``expected``) → ``other``.
    Наявне поле варіанта з ``null`` чи недопустимим значенням — помилка
    даних (``ValueError``); відсутнє поле — брак даних.
    """
    threshold, field, expected = get_rule(variant)
    report: dict[str, Any] = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {
            "threshold": threshold,
            "field": field,
            "expected": expected,
        },
        "observed": None,
        "decision": "not_found",
    }
    if record is None:
        return report
    if not isinstance(record, dict):
        raise ValueError("Внутрішній запис має бути словником або None")

    report["description"] = record.get("description")
    report["vuln_status"] = record.get("vuln_status")
    status = report["vuln_status"]
    if status == REJECTED_STATUS:
        report["decision"] = "rejected"
        return report
    if status is None or record.get("score") is None:
        report["decision"] = "insufficient_data"
        return report

    report["cvss_version"] = record.get("cvss_version")
    report["score"] = record["score"]
    report["score_source"] = record.get("score_source")
    report["vector"] = record.get("vector")

    cvss_data = record.get("cvss_data")
    if not isinstance(cvss_data, dict):
        raise ValueError("Запис з оцінкою має містити cvss_data")
    if field not in cvss_data:
        report["decision"] = "insufficient_data"
        return report
    observed = cvss_data[field]
    if not isinstance(observed, str) or observed not in ALLOWED_VALUES[field]:
        raise ValueError(f"cvssData.{field} має недопустиме значення")

    report["observed"] = observed
    matches = report["score"] >= threshold and observed == expected
    report["decision"] = "review" if matches else "other"
    return report
