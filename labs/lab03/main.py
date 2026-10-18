"""FastAPI-застосунок для обліку часу відновлення сервісів."""

import logging
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

from .config import DOMAIN_TITLE, VALUE_THRESHOLD, VALUE_UNIT
from .database import initialize_database
from .routers import categories, records

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Створити таблиці перед обробкою запитів, не заповнюючи їх."""
    initialize_database()
    yield


app = FastAPI(
    title=f"Лабораторна робота № 3 — {DOMAIN_TITLE}",
    description=(
        f"Навчальний реєстр часу відновлення сервісів у {VALUE_UNIT}. "
        f"Індивідуальний варіант: {VARIANT_NUMBER}; поріг: "
        f"{VALUE_THRESHOLD:g} {VALUE_UNIT}."
    ),
    version="1.0.0",
    lifespan=lifespan,
)
app.include_router(categories.router)
app.include_router(records.router)


@app.get("/ping", tags=["Сервіс"], summary="Перевірити доступність API")
def ping() -> dict[str, str]:
    """Повернути короткий стан API."""
    return {"status": "ok"}


@app.get(
    "/student",
    tags=["Сервіс"],
    summary="Дані студента та індивідуальний варіант",
)
def student_info() -> dict[str, str | int]:
    """Повернути значення з єдиного спільного student.py."""
    return {
        "student_name": STUDENT_NAME,
        "group_name": GROUP_NAME,
        "variant_number": VARIANT_NUMBER,
    }


@app.exception_handler(RequestValidationError)
def handle_validation_error(
    _: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Повернути 422 без несеріалізовних значень із некоректного JSON."""
    details = [
        {
            key: value
            for key, value in error.items()
            if key not in {"input", "ctx"}
        }
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": details})


@app.exception_handler(sqlite3.Error)
def handle_database_error(_: Request, exc: sqlite3.Error) -> JSONResponse:
    """Записати технічну помилку БД у лог і повернути безпечну відповідь."""
    logger.error(
        "SQLite request failed: %s",
        exc,
        exc_info=(type(exc), exc, exc.__traceback__),
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Не вдалося виконати операцію з базою даних"},
    )
