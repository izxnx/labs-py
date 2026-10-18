"""HTTP-маршрути для навчальних вимірювань відновлення."""

from typing import Annotated

from fastapi import (
    APIRouter,
    Body,
    HTTPException,
    Path,
    Query,
    Response,
    status,
)

from .. import repository
from ..config import VALUE_THRESHOLD, VALUE_UNIT
from ..schemas import RecordCreate, RecordRead, RecordReplace, Status

router = APIRouter(prefix="/records", tags=["Вимірювання"])


def _as_dict(payload: RecordCreate | RecordReplace) -> dict[str, object]:
    return payload.model_dump()


@router.get(
    "",
    response_model=list[RecordRead],
    summary="Список вимірювань",
    description=(
        "Фільтри поєднуються через AND; порядок за id. "
        f"Час вимірюється в {VALUE_UNIT}; навчальний поріг — "
        f"{VALUE_THRESHOLD:g}."
    ),
)
def read_records(
    category_id: Annotated[int | None, Query(gt=0)] = None,
    status_filter: Annotated[
        Status | None,
        Query(alias="status", description="new, in_progress або done"),
    ] = None,
    min_value: Annotated[
        float | None,
        Query(
            ge=0, allow_inf_nan=False, description=f"Мінімум у {VALUE_UNIT}"
        ),
    ] = None,
    q: Annotated[str | None, Query(min_length=1, max_length=120)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[dict[str, object]]:
    """Повернути сторінку вимірювань із необов'язковими фільтрами."""
    return repository.list_records(
        category_id=category_id,
        status=status_filter,
        min_value=min_value,
        q=q,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=status.HTTP_201_CREATED,
    summary="Додати пакет вимірювань атомарно",
    description="Приймає від 1 до 100 записів; помилка скасовує весь пакет.",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Дублікат або порушення обмеження"},
    },
)
def add_records_bulk(
    payload: Annotated[
        list[RecordCreate],
        Body(min_length=1, max_length=100, description="Від 1 до 100 записів"),
    ],
) -> list[dict[str, object]]:
    """Додати весь список однією транзакцією."""
    try:
        return repository.create_records_bulk(
            [_as_dict(item) for item in payload]
        )
    except repository.NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except repository.ConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.post(
    "",
    response_model=RecordRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створити вимірювання",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Код уже використовується"},
    },
)
def add_record(payload: RecordCreate) -> dict[str, object]:
    """Зберегти одне вимірювання відновлення."""
    try:
        return repository.create_record(_as_dict(payload))
    except repository.NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except repository.ConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get(
    "/{record_id}",
    response_model=RecordRead,
    summary="Отримати вимірювання",
    responses={404: {"description": "Запис не знайдено"}},
)
def read_record(
    record_id: Annotated[int, Path(gt=0, description="Додатний id запису")],
) -> dict[str, object]:
    """Знайти вимірювання за його id."""
    try:
        return repository.get_record(record_id)
    except repository.NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    summary="Повністю замінити вимірювання",
    responses={
        404: {"description": "Запис або категорію не знайдено"},
        409: {"description": "Код уже використовується"},
    },
)
def replace_record(
    record_id: Annotated[int, Path(gt=0, description="Додатний id запису")],
    payload: RecordReplace,
) -> dict[str, object]:
    """Замінити всі змінювані поля, зберігши id запису."""
    try:
        return repository.replace_record(record_id, _as_dict(payload))
    except repository.NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except repository.ConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.delete(
    "/{record_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалити вимірювання",
    responses={404: {"description": "Запис не знайдено"}},
)
def remove_record(
    record_id: Annotated[int, Path(gt=0, description="Додатний id запису")],
) -> Response:
    """Видалити наявний запис."""
    try:
        repository.delete_record(record_id)
    except repository.NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
