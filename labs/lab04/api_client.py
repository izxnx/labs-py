"""HTTP-клієнт NVD CVE API 2.0.

Модуль лише формує заголовки та виконує один GET-запит. Перевірка змісту
відповіді виконується в ``analysis.py``, обробка винятків — у ``main.py``.
"""

import os
from typing import Any

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY_ENV = "NVD_API_KEY"
# (час встановлення з'єднання, час очікування між порціями даних)
REQUEST_TIMEOUT = (3.05, 10)


class UnexpectedStatusError(Exception):
    """Сервіс повернув статус без HTTP-помилки, але відмінний від 200.

    Наприклад, 204 або перенаправлення 3xx, яке клієнт не виконує.
    """

    def __init__(self, status_code: int) -> None:
        super().__init__(f"Неочікуваний HTTP-статус {status_code}")
        self.status_code = status_code


def build_headers() -> dict[str, str]:
    """Повертає заголовки запиту до NVD.

    Ключ читається зі змінної ``NVD_API_KEY`` під час кожного виклику.
    Відсутнє, порожнє чи пробільне значення означає запит без ключа.
    """
    headers = {"Accept": "application/json"}
    api_key = (os.getenv(API_KEY_ENV) or "").strip()
    if api_key:
        headers["apiKey"] = api_key
    return headers


def fetch_response(cve_id: str) -> Any:
    """Виконує один GET-запит до NVD і повертає декодований JSON.

    Винятки Requests (таймаут, з'єднання, ``HTTPError``,
    ``requests.exceptions.JSONDecodeError``) не перехоплюються: їх
    обробляє викликальний код. Для статусу, відмінного від 200, без
    HTTP-помилки піднімається ``UnexpectedStatusError``.
    """
    response = requests.get(
        NVD_API_URL,
        params={"cveId": cve_id},
        headers=build_headers(),
        timeout=REQUEST_TIMEOUT,
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code != 200:
        raise UnexpectedStatusError(response.status_code)
    return response.json()
