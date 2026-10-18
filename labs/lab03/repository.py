"""Параметризовані SQL-операції над категоріями та записами."""

import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from typing import Any

from .database import get_connection


class NotFoundError(Exception):
    """Запитаний запис або категорія відсутні."""


class ConflictError(Exception):
    """Операція порушує унікальність або зв'язок між таблицями."""


@contextmanager
def _write_connection() -> Iterator[sqlite3.Connection]:
    """Виконати зміни атомарно та закрити з'єднання після операції."""
    with closing(get_connection()) as connection:
        try:
            with connection:
                yield connection
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "Операція порушує обмеження бази даних"
            ) from exc


def _category_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {"id": row["id"], "name": row["name"]}


def _record_from_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "code": row["code"],
        "title": row["title"],
        "category_id": row["category_id"],
        "category_name": row["category_name"],
        "value": row["value"],
        "status": row["status"],
    }


def _record_select() -> str:
    """Повернути спільну вибірку з назвою пов'язаної категорії."""
    return """
        SELECT r.id, r.code, r.title, r.category_id, c.name AS category_name,
               r.value, r.status
        FROM records AS r
        JOIN categories AS c ON c.id = r.category_id
    """


def _ensure_category(connection: sqlite3.Connection, category_id: int) -> None:
    row = connection.execute(
        "SELECT 1 FROM categories WHERE id = ?", (category_id,)
    ).fetchone()
    if row is None:
        raise NotFoundError("Категорію не знайдено")


def get_categories() -> list[dict[str, Any]]:
    """Повернути категорії за зростанням id."""
    with closing(get_connection()) as connection:
        rows = connection.execute(
            "SELECT id, name FROM categories ORDER BY id ASC"
        ).fetchall()
    return [_category_from_row(row) for row in rows]


def create_category(name: str) -> dict[str, Any]:
    """Створити категорію або повідомити про конфлікт її назви."""
    with _write_connection() as connection:
        try:
            cursor = connection.execute(
                "INSERT INTO categories (name) VALUES (?)", (name,)
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError(
                "Назва категорії вже використовується"
            ) from exc
        row = connection.execute(
            "SELECT id, name FROM categories WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
        assert row is not None
        return _category_from_row(row)


def delete_category(category_id: int) -> None:
    """Видалити наявну категорію, якщо вона ще не містить записів."""
    with _write_connection() as connection:
        row = connection.execute(
            "SELECT id FROM categories WHERE id = ?", (category_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("Категорію не знайдено")
        count = connection.execute(
            "SELECT COUNT(*) FROM records WHERE category_id = ?",
            (category_id,),
        ).fetchone()[0]
        if count:
            raise ConflictError("Категорія містить записи")
        connection.execute(
            "DELETE FROM categories WHERE id = ?", (category_id,)
        )


def get_record(record_id: int) -> dict[str, Any]:
    """Отримати один запис разом із назвою категорії."""
    with closing(get_connection()) as connection:
        row = connection.execute(
            _record_select() + " WHERE r.id = ?", (record_id,)
        ).fetchone()
    if row is None:
        raise NotFoundError("Запис не знайдено")
    return _record_from_row(row)


def list_records(
    *,
    category_id: int | None,
    status: str | None,
    min_value: float | None,
    q: str | None,
    limit: int,
    offset: int,
) -> list[dict[str, Any]]:
    """Повернути сторінку записів із переданими фільтрами AND."""
    conditions: list[str] = []
    parameters: list[Any] = []
    filters = (
        ("r.category_id = ?", category_id),
        ("r.status = ?", status),
        ("r.value >= ?", min_value),
        ("instr(r.title, ?) > 0", q),
    )
    for clause, value in filters:
        if value is not None:
            conditions.append(clause)
            parameters.append(value)

    query = _record_select()
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY r.id ASC LIMIT ? OFFSET ?"
    parameters.extend((limit, offset))

    with closing(get_connection()) as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [_record_from_row(row) for row in rows]


def create_record(record: dict[str, Any]) -> dict[str, Any]:
    """Додати запис із категорією та повернути його повне подання."""
    with _write_connection() as connection:
        _ensure_category(connection, record["category_id"])
        try:
            cursor = connection.execute(
                """
                INSERT INTO records (code, title, category_id, value, status)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    record["code"],
                    record["title"],
                    record["category_id"],
                    record["value"],
                    record["status"],
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("Код запису вже використовується") from exc
        row = connection.execute(
            _record_select() + " WHERE r.id = ?", (cursor.lastrowid,)
        ).fetchone()
        assert row is not None
        return _record_from_row(row)


def replace_record(record_id: int, record: dict[str, Any]) -> dict[str, Any]:
    """Повністю замінити змінювані поля запису без зміни його id."""
    with _write_connection() as connection:
        current = connection.execute(
            "SELECT id FROM records WHERE id = ?", (record_id,)
        ).fetchone()
        if current is None:
            raise NotFoundError("Запис не знайдено")
        _ensure_category(connection, record["category_id"])
        try:
            connection.execute(
                """
                UPDATE records
                SET code = ?, title = ?, category_id = ?, value = ?, status = ?
                WHERE id = ?
                """,
                (
                    record["code"],
                    record["title"],
                    record["category_id"],
                    record["value"],
                    record["status"],
                    record_id,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ConflictError("Код запису вже використовується") from exc
        row = connection.execute(
            _record_select() + " WHERE r.id = ?", (record_id,)
        ).fetchone()
        assert row is not None
        return _record_from_row(row)


def delete_record(record_id: int) -> None:
    """Видалити запис або повідомити, що такого id немає."""
    with _write_connection() as connection:
        cursor = connection.execute(
            "DELETE FROM records WHERE id = ?", (record_id,)
        )
        if cursor.rowcount == 0:
            raise NotFoundError("Запис не знайдено")


def create_records_bulk(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Додати весь пакет однією транзакцією або скасувати його повністю."""
    created: list[dict[str, Any]] = []
    with _write_connection() as connection:
        for record in records:
            _ensure_category(connection, record["category_id"])
        for record in records:
            try:
                cursor = connection.execute(
                    """
                    INSERT INTO records
                        (code, title, category_id, value, status)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        record["code"],
                        record["title"],
                        record["category_id"],
                        record["value"],
                        record["status"],
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError(
                    "Пакет містить дублікат коду або порушує обмеження"
                ) from exc
            row = connection.execute(
                _record_select() + " WHERE r.id = ?", (cursor.lastrowid,)
            ).fetchone()
            assert row is not None
            created.append(_record_from_row(row))
    return created
