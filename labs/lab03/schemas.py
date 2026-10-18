"""Pydantic-моделі HTTP-запитів і відповідей."""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

Status = Literal["new", "in_progress", "done"]


class InputModel(BaseModel):
    """Спільні правила для вхідних JSON-об'єктів."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")


class CategoryCreate(InputModel):
    """Дані для створення категорії."""

    name: Annotated[str, Field(min_length=2, max_length=40)]


class CategoryRead(CategoryCreate):
    """Категорія у відповіді API."""

    id: int = Field(gt=0, strict=True)


class RecordCreate(InputModel):
    """Змінювані поля вимірювання відновлення."""

    code: Annotated[str, Field(min_length=3, max_length=40)]
    title: Annotated[str, Field(min_length=3, max_length=120)]
    category_id: int = Field(gt=0, strict=True)
    value: float = Field(ge=0, allow_inf_nan=False, strict=True)
    status: Status


class RecordReplace(RecordCreate):
    """Повний набір полів для заміни запису через PUT."""


class RecordRead(RecordCreate):
    """Запис у відповіді API з категорією та ідентифікатором."""

    id: int = Field(gt=0, strict=True)
    category_name: str


class SeedCategory(CategoryCreate):
    """Категорія початкових даних з наперед заданим id."""

    id: int = Field(gt=0)


class SeedData(InputModel):
    """Структура JSON для відтворюваного початкового заповнення."""

    categories: Annotated[
        list[SeedCategory], Field(min_length=3, max_length=3)
    ]
    records: Annotated[list[RecordCreate], Field(min_length=8, max_length=8)]
