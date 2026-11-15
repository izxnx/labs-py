"""Тести HTTP-клієнта: підміняється requests.get, а не fetch_response."""

from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
FAKE_KEY = "fake-key-0000"


def make_response(status_code=200, payload=None):
    response = Mock(spec=requests.Response)
    response.status_code = status_code
    response.headers = {"Content-Type": "application/json; charset=utf-8"}
    response.json.return_value = payload
    return response


def install_get(monkeypatch, response=None, side_effect=None):
    fake_get = Mock(return_value=response, side_effect=side_effect)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    return fake_get


# --- build_headers ----------------------------------------------------


def test_headers_without_key():
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_headers_with_fake_key(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", FAKE_KEY)
    assert api_client.build_headers() == {
        "Accept": "application/json",
        "apiKey": FAKE_KEY,
    }


def test_headers_strip_key(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", f"  {FAKE_KEY}\n")
    assert api_client.build_headers()["apiKey"] == FAKE_KEY


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_empty_or_blank_key_means_no_key(monkeypatch, value):
    monkeypatch.setenv("NVD_API_KEY", value)
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_key_is_read_on_each_call(monkeypatch):
    assert "apiKey" not in api_client.build_headers()
    monkeypatch.setenv("NVD_API_KEY", FAKE_KEY)
    assert api_client.build_headers()["apiKey"] == FAKE_KEY


# --- fetch_response: успіх --------------------------------------------


def test_fetch_uses_expected_request(monkeypatch):
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    response = make_response(payload=payload)
    fake_get = install_get(monkeypatch, response)

    assert api_client.fetch_response("CVE-2099-10001") == payload
    fake_get.assert_called_once_with(
        NVD_URL,
        params={"cveId": "CVE-2099-10001"},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_sends_key_in_header_not_in_url(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", FAKE_KEY)
    fake_get = install_get(monkeypatch, make_response(payload={}))

    api_client.fetch_response("CVE-2021-44228")

    args, kwargs = fake_get.call_args
    assert args == (NVD_URL,)
    assert kwargs["headers"]["apiKey"] == FAKE_KEY
    assert kwargs["params"] == {"cveId": "CVE-2021-44228"}
    assert FAKE_KEY not in str(args) and FAKE_KEY not in str(kwargs["params"])


# --- fetch_response: помилки ------------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.ConnectTimeout("connect timeout"),
        requests.exceptions.ReadTimeout("read timeout"),
        requests.exceptions.ConnectionError("no route"),
    ],
    ids=["connect-timeout", "read-timeout", "connection"],
)
def test_network_errors_propagate(monkeypatch, error):
    install_get(monkeypatch, side_effect=error)
    with pytest.raises(type(error)):
        api_client.fetch_response("CVE-2099-10001")


@pytest.mark.parametrize("status", [404, 429, 500, 503])
def test_http_error_propagates_with_status(monkeypatch, status):
    response = make_response(status_code=status)
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        f"{status} error", response=response
    )
    install_get(monkeypatch, response)

    with pytest.raises(requests.exceptions.HTTPError) as caught:
        api_client.fetch_response("CVE-2099-10001")
    assert caught.value.response.status_code == status
    response.json.assert_not_called()


@pytest.mark.parametrize("status", [204, 301, 302])
def test_unexpected_status_without_http_error(monkeypatch, status):
    response = make_response(status_code=status)
    install_get(monkeypatch, response)

    with pytest.raises(api_client.UnexpectedStatusError) as caught:
        api_client.fetch_response("CVE-2099-10001")
    assert caught.value.status_code == status
    response.json.assert_not_called()


def test_invalid_json_propagates(monkeypatch):
    response = make_response()
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )
    install_get(monkeypatch, response)

    with pytest.raises(requests.exceptions.JSONDecodeError):
        api_client.fetch_response("CVE-2099-10001")


def test_real_network_is_blocked_in_tests():
    # Автоматична фікстура прибирає Session.request: справжній виклик
    # requests.get має завершитися помилкою, а не дійти до мережі.
    with pytest.raises(AttributeError):
        requests.get(NVD_URL, timeout=(3.05, 10))
