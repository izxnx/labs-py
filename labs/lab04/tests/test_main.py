"""Тести командного інтерфейсу та інтеграційні тести локального режиму."""

import json
from pathlib import Path
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client, main
from labs.lab04.tests.factories import (
    CVE_ID,
    make_empty_payload,
    make_metric,
    make_payload,
)

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"
FAKE_KEY = "fake-key-0000"

EXPECTED_SAMPLE_REPORT = {
    "cve_id": "CVE-2099-10001",
    "variant": 8,
    "description": "Synthetic vulnerability for offline API testing.",
    "vuln_status": "Analyzed",
    "cvss_version": "3.1",
    "score": 9.8,
    "score_source": "nvd@nist.gov",
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "rule": {"threshold": 9.0, "field": "scope", "expected": "CHANGED"},
    "observed": "UNCHANGED",
    "decision": "other",
}


@pytest.fixture
def forbid_fetch(monkeypatch):
    """Падає, якщо CLI спробує звернутися до клієнта NVD."""
    fake = Mock(side_effect=AssertionError("мережа не повинна викликатися"))
    monkeypatch.setattr(main.api_client, "fetch_response", fake)
    return fake


def write_json(tmp_path, payload, name="response.json"):
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# --- Локальний режим --------------------------------------------------


def test_local_sample_produces_report(capsys, forbid_fetch):
    code = main.main(["--cve", CVE_ID, "--input", str(SAMPLE_PATH)])
    out, err = capsys.readouterr()

    assert code == 0
    assert err == ""
    assert json.loads(out) == EXPECTED_SAMPLE_REPORT
    forbid_fetch.assert_not_called()


def test_local_review_case(tmp_path, capsys, forbid_fetch):
    path = write_json(tmp_path, make_payload())
    code = main.main(["--cve", CVE_ID, "--input", str(path)])
    out, _ = capsys.readouterr()
    assert code == 0
    assert json.loads(out)["decision"] == "review"


def test_local_not_found_is_success(tmp_path, capsys, forbid_fetch):
    path = write_json(tmp_path, make_empty_payload())
    code = main.main(["--cve", CVE_ID, "--input", str(path)])
    out, err = capsys.readouterr()
    assert code == 0
    assert err == ""
    assert json.loads(out)["decision"] == "not_found"


def test_local_insufficient_data_is_success(tmp_path, capsys, forbid_fetch):
    path = write_json(tmp_path, make_payload(metrics={}))
    code = main.main(["--cve", CVE_ID, "--input", str(path)])
    out, _ = capsys.readouterr()
    assert code == 0
    assert json.loads(out)["decision"] == "insufficient_data"


def test_output_keeps_non_ascii(tmp_path, capsys, forbid_fetch):
    payload = make_payload(
        descriptions=[{"lang": "en", "value": "Тест — опис"}]
    )
    path = write_json(tmp_path, payload)
    main.main(["--cve", CVE_ID, "--input", str(path)])
    out, _ = capsys.readouterr()
    assert "Тест — опис" in out


def test_missing_file(tmp_path, capsys, forbid_fetch):
    missing = tmp_path / "absent.json"
    code = main.main(["--cve", CVE_ID, "--input", str(missing)])
    out, err = capsys.readouterr()
    assert code == 1
    assert out == ""
    assert "не знайдено" in err
    assert "Traceback" not in err


def test_invalid_json_file(tmp_path, capsys, forbid_fetch):
    path = tmp_path / "broken.json"
    path.write_text('{"vulnerabilities": [', encoding="utf-8")
    code = main.main(["--cve", CVE_ID, "--input", str(path)])
    out, err = capsys.readouterr()
    assert code == 1
    assert out == ""
    assert "некоректний JSON" in err
    assert "Traceback" not in err


def test_non_utf8_file(tmp_path, capsys, forbid_fetch):
    path = tmp_path / "cp1251.json"
    path.write_bytes('{"a": "Привіт"}'.encode("cp1251"))
    code = main.main(["--cve", CVE_ID, "--input", str(path)])
    _, err = capsys.readouterr()
    assert code == 1
    assert "UTF-8" in err


def test_directory_instead_of_file(tmp_path, capsys, forbid_fetch):
    code = main.main(["--cve", CVE_ID, "--input", str(tmp_path)])
    _, err = capsys.readouterr()
    assert code == 1
    assert err.startswith("Помилка:")


def test_invalid_data_returns_1(tmp_path, capsys, forbid_fetch):
    payload = make_payload({"cvssMetricV31": [make_metric(scope=None)]})
    path = write_json(tmp_path, payload)
    code = main.main(["--cve", CVE_ID, "--input", str(path)])
    out, err = capsys.readouterr()
    assert code == 1
    assert out == ""
    assert "scope" in err


def test_cve_mismatch_returns_1(tmp_path, capsys, forbid_fetch):
    path = write_json(tmp_path, make_payload(cve_id="CVE-2099-20002"))
    code = main.main(["--cve", CVE_ID, "--input", str(path)])
    _, err = capsys.readouterr()
    assert code == 1
    assert "не збігається" in err


def test_load_response_reads_utf8_json(tmp_path):
    path = write_json(tmp_path, {"vulnerabilities": []})
    assert main.load_response(path) == {"vulnerabilities": []}


# --- Аргументи та варіант ---------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--cve", "cve-2099-10001"],
        ["--cve", "CVE-2099-100"],
        ["--cve", "CVE-99-10001"],
        ["--cve", " CVE-2099-10001"],
        ["--cve", "CVE-2099-10001x"],
        ["--cve", "CVE-2099-10001\n"],
        ["--cve", "CVE-٢٠٩٩-10001"],
    ],
    ids=[
        "missing",
        "lowercase",
        "short-number",
        "short-year",
        "leading-space",
        "suffix",
        "newline",
        "non-ascii-digits",
    ],
)
def test_invalid_arguments_exit_2(argv, capsys, forbid_fetch):
    with pytest.raises(SystemExit) as caught:
        main.main(argv)
    assert caught.value.code == 2
    out, err = capsys.readouterr()
    assert out == ""
    assert err != ""


@pytest.mark.parametrize("cve_id", ["CVE-2021-44228", "CVE-1999-0001"])
def test_cve_pattern_accepts_valid_ids(cve_id):
    assert main.cve_id_type(cve_id) == cve_id


@pytest.mark.parametrize("variant", [0, 16, -8, True, "8", 8.0, None])
def test_invalid_variant_returns_2(monkeypatch, capsys, variant, forbid_fetch):
    monkeypatch.setattr(main, "VARIANT_NUMBER", variant)
    code = main.main(["--cve", CVE_ID, "--input", str(SAMPLE_PATH)])
    out, err = capsys.readouterr()
    assert code == 2
    assert out == ""
    assert "VARIANT_NUMBER" in err


def test_other_variant_changes_rule(monkeypatch, capsys, forbid_fetch):
    monkeypatch.setattr(main, "VARIANT_NUMBER", 1)
    code = main.main(["--cve", CVE_ID, "--input", str(SAMPLE_PATH)])
    report = json.loads(capsys.readouterr().out)
    assert code == 0
    assert report["variant"] == 1
    assert report["decision"] == "review"


# --- Мережевий режим (підміна функції клієнта) ------------------------


def test_network_mode_uses_client(monkeypatch, capsys):
    fake = Mock(return_value=make_payload())
    monkeypatch.setattr(main.api_client, "fetch_response", fake)
    code = main.main(["--cve", CVE_ID])
    out, _ = capsys.readouterr()
    assert code == 0
    assert json.loads(out)["decision"] == "review"
    fake.assert_called_once_with(CVE_ID)


@pytest.mark.parametrize(
    ("error", "fragment"),
    [
        (requests.exceptions.ConnectTimeout("secret details"), "час"),
        (requests.exceptions.ReadTimeout("secret details"), "час"),
        (requests.exceptions.ConnectionError("secret details"), "з'єднатися"),
        (requests.exceptions.TooManyRedirects("secret details"), "HTTP"),
        (
            requests.exceptions.JSONDecodeError("secret details", "{", 1),
            "JSON",
        ),
        (api_client.UnexpectedStatusError(301), "301"),
    ],
)
def test_network_errors_return_1(monkeypatch, capsys, error, fragment):
    monkeypatch.setattr(
        main.api_client, "fetch_response", Mock(side_effect=error)
    )
    code = main.main(["--cve", CVE_ID])
    out, err = capsys.readouterr()
    assert code == 1
    assert out == ""
    assert fragment in err
    assert "secret details" not in err
    assert "Traceback" not in err


@pytest.mark.parametrize("status", [404, 429, 500])
def test_http_error_reports_status(monkeypatch, capsys, status):
    response = Mock(spec=requests.Response)
    response.status_code = status
    error = requests.exceptions.HTTPError("body secret", response=response)
    monkeypatch.setattr(
        main.api_client, "fetch_response", Mock(side_effect=error)
    )
    code = main.main(["--cve", CVE_ID])
    out, err = capsys.readouterr()
    assert code == 1
    assert out == ""
    assert str(status) in err
    assert "body secret" not in err
    assert "not_found" not in err


# --- Інтеграція CLI + справжній клієнт (підміна requests.get) ---------


def test_cli_with_real_client_does_not_leak_key(monkeypatch, capsys):
    monkeypatch.setenv("NVD_API_KEY", FAKE_KEY)
    response = Mock(spec=requests.Response)
    response.status_code = 500
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "500 Server Error", response=response
    )
    fake_get = Mock(return_value=response)
    monkeypatch.setattr(api_client.requests, "get", fake_get)

    code = main.main(["--cve", CVE_ID])
    out, err = capsys.readouterr()

    assert code == 1
    assert "500" in err
    assert FAKE_KEY not in out + err
    assert fake_get.call_args.kwargs["headers"]["apiKey"] == FAKE_KEY
    assert fake_get.call_args.kwargs["timeout"] == (3.05, 10)


def test_cli_with_real_client_success(monkeypatch, capsys):
    response = Mock(spec=requests.Response)
    response.status_code = 200
    response.json.return_value = make_payload()
    monkeypatch.setattr(
        api_client.requests, "get", Mock(return_value=response)
    )
    code = main.main(["--cve", CVE_ID])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["decision"] == "review"
