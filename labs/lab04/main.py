"""Консольна утиліта ЛР №4: перегляд запису NVD за ідентифікатором CVE.

Запуск з кореня репозиторію::

    python -m labs.lab04.main --cve CVE-2099-10001 \\
        --input labs/lab04/data/nvd_sample.json
    python -m labs.lab04.main --cve CVE-2021-44228

Коди завершення: 0 — звіт сформовано; 1 — помилка отримання, читання чи
перевірки даних; 2 — неправильні аргументи або номер варіанта.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import requests

from labs.lab04 import analysis, api_client
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")

EXIT_OK = 0
EXIT_DATA_ERROR = 1
EXIT_USAGE_ERROR = 2


def cve_id_type(value: str) -> str:
    """Тип аргументу argparse: повний збіг із CVE-YYYY-NNNN(...)."""
    if not CVE_PATTERN.fullmatch(value):
        raise argparse.ArgumentTypeError(
            "очікується ідентифікатор у форматі CVE-РРРР-NNNN "
            "(великі літери, щонайменше 4 цифри в номері)"
        )
    return value


def build_parser() -> argparse.ArgumentParser:
    """Створює парсер аргументів командного рядка."""
    parser = argparse.ArgumentParser(
        prog="python -m labs.lab04.main",
        description="Звіт про вразливість із NVD за правилом варіанта.",
    )
    parser.add_argument(
        "--cve",
        required=True,
        type=cve_id_type,
        help="ідентифікатор CVE, наприклад CVE-2021-44228",
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="шлях до локальної відповіді NVD (UTF-8 JSON); без мережі",
    )
    return parser


def is_valid_variant(value: Any) -> bool:
    """Перевіряє, що номер варіанта — int від 1 до 15, не bool."""
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 1 <= value <= 15
    )


def load_response(path: Path) -> Any:
    """Читає локальну відповідь NVD із UTF-8 JSON-файла."""
    with Path(path).open(encoding="utf-8") as file:
        return json.load(file)


def _error(message: str) -> None:
    print(f"Помилка: {message}", file=sys.stderr)


def _read_local(path: Path) -> tuple[bool, Any]:
    """Читає файл; повертає (успіх, дані) і друкує причину помилки."""
    try:
        return True, load_response(path)
    except UnicodeDecodeError:
        _error(f"файл {path} не є текстом у кодуванні UTF-8.")
    except json.JSONDecodeError as exc:
        _error(
            f"файл {path} містить некоректний JSON "
            f"(рядок {exc.lineno}, стовпець {exc.colno})."
        )
    except FileNotFoundError:
        _error(f"файл {path} не знайдено.")
    except IsADirectoryError:
        _error(f"{path} є директорією, а не файлом.")
    except PermissionError:
        _error(f"немає дозволу на читання файла {path}.")
    except OSError as exc:
        _error(f"не вдалося прочитати файл {path} ({exc.strerror}).")
    return False, None


def _fetch_remote(cve_id: str) -> tuple[bool, Any]:
    """Виконує запит до NVD; друкує зрозуміле повідомлення про помилку.

    Ключ, заголовки, текст винятку та тіло відповіді не виводяться.
    """
    try:
        return True, api_client.fetch_response(cve_id)
    except requests.exceptions.JSONDecodeError:
        _error("відповідь NVD не є коректним JSON.")
    except requests.exceptions.Timeout:
        _error("перевищено час очікування відповіді NVD.")
    except requests.exceptions.ConnectionError:
        _error("не вдалося з'єднатися з NVD (мережа або TLS).")
    except requests.exceptions.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "?"
        message = f"NVD повернув HTTP-помилку {status}."
        if status in (403, 429):
            message += " Можливе обмеження частоти запитів або хибний ключ."
        elif status == 404:
            message += " Це помилка запиту, а не порожній результат пошуку."
        _error(message)
    except api_client.UnexpectedStatusError as exc:
        _error(
            f"NVD повернув неочікуваний HTTP-статус {exc.status_code} "
            "(очікується 200, перенаправлення не виконуються)."
        )
    except requests.exceptions.RequestException as exc:
        _error(f"помилка HTTP-запиту до NVD ({type(exc).__name__}).")
    return False, None


def main(argv: list[str] | None = None) -> int:
    """Розбирає аргументи, отримує дані, друкує JSON-звіт у stdout."""
    if not is_valid_variant(VARIANT_NUMBER):
        _error(
            "VARIANT_NUMBER у shared/student.py має бути цілим числом "
            "від 1 до 15."
        )
        return EXIT_USAGE_ERROR

    args = build_parser().parse_args(argv)

    if args.input is not None:
        ok, payload = _read_local(args.input)
    else:
        ok, payload = _fetch_remote(args.cve)
    if not ok:
        return EXIT_DATA_ERROR

    try:
        record = analysis.extract_record(payload, args.cve)
        report = analysis.build_report(record, args.cve, VARIANT_NUMBER)
    except ValueError as exc:
        _error(f"некоректні дані NVD: {exc}.")
        return EXIT_DATA_ERROR

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
