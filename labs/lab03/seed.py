"""Перевірка JSON та атомарне заповнення порожньої бази."""

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .config import (
    CATEGORY_NAMES,
    RECORD_TITLE_PREFIX,
    SEED_STATUSES,
    SEED_VALUES,
    VARIANT_NUMBER,
)
from .database import DATABASE_PATH, get_connection, initialize_database
from .schemas import SeedData

SEED_PATH = Path(__file__).resolve().parent / "data" / "seed.json"


def _load_seed() -> SeedData:
    """Зчитати JSON і перевірити повний навчальний набір варіанта 8."""
    payload: Any = json.loads(SEED_PATH.read_text(encoding="utf-8"))
    data = SeedData.model_validate(payload)

    category_names = [category.name for category in data.categories]
    if category_names != list(CATEGORY_NAMES):
        raise ValueError(
            "Назви або порядок категорій не відповідають варіанту 8"
        )
    if [category.id for category in data.categories] != [1, 2, 3]:
        raise ValueError("Початкові id категорій мають дорівнювати 1, 2 і 3")

    expected_records = []
    for index, (value, status) in enumerate(
        zip(SEED_VALUES, SEED_STATUSES, strict=True),
        start=1,
    ):
        expected_records.append(
            {
                "code": f"V{VARIANT_NUMBER:02d}-{index:02d}",
                "title": f"{RECORD_TITLE_PREFIX} {index:02d}",
                "category_id": ((index - 1) % len(CATEGORY_NAMES)) + 1,
                "value": value,
                "status": status,
            }
        )
    actual_records = [record.model_dump() for record in data.records]
    if actual_records != expected_records:
        raise ValueError("Записи seed.json не відповідають даним варіанта 8")
    return data


def seed_database() -> bool:
    """Додати три категорії й вісім записів однією транзакцією."""
    initialize_database()
    data = _load_seed()
    with closing(get_connection()) as connection, connection:
        categories_count = connection.execute(
            "SELECT COUNT(*) FROM categories"
        ).fetchone()[0]
        records_count = connection.execute(
            "SELECT COUNT(*) FROM records"
        ).fetchone()[0]
        if categories_count or records_count:
            print("База вже містить дані; повторне заповнення пропущено.")
            return False

        connection.executemany(
            "INSERT INTO categories (id, name) VALUES (?, ?)",
            [(item.id, item.name) for item in data.categories],
        )
        connection.executemany(
            """
                INSERT INTO records
                    (code, title, category_id, value, status)
                VALUES (?, ?, ?, ?, ?)
                """,
            [
                (
                    item.code,
                    item.title,
                    item.category_id,
                    item.value,
                    item.status,
                )
                for item in data.records
            ],
        )
    print(
        f"Початкові дані додано: 3 категорії, 8 записів. "
        f"База: {DATABASE_PATH.name}"
    )
    return True


def main() -> int:
    """Запустити початкове заповнення з командного рядка."""
    try:
        seed_database()
    except (
        OSError,
        sqlite3.Error,
        json.JSONDecodeError,
        ValidationError,
        ValueError,
    ) as exc:
        print(f"Не вдалося заповнити базу: {exc}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
