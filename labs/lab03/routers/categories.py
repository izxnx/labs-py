"""HTTP-маршрути для керування категоріями."""

from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Response, status

from .. import repository
from ..schemas import CategoryCreate, CategoryRead

router = APIRouter(prefix="/categories", tags=["Категорії"])


@router.get(
    "",
    response_model=list[CategoryRead],
    summary="Список категорій",
    description="Повертає категорії за зростанням ідентифікатора.",
)
def read_categories() -> list[dict[str, object]]:
    """Повернути всі категорії."""
    return repository.get_categories()


@router.post(
    "",
    response_model=CategoryRead,
    status_code=status.HTTP_201_CREATED,
    summary="Створити категорію",
    responses={409: {"description": "Назва вже використовується"}},
)
def add_category(payload: CategoryCreate) -> dict[str, object]:
    """Створити категорію з унікальною назвою."""
    try:
        return repository.create_category(payload.name)
    except repository.ConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.delete(
    "/{category_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Видалити порожню категорію",
    responses={
        404: {"description": "Категорію не знайдено"},
        409: {"description": "Категорія містить записи"},
    },
)
def remove_category(
    category_id: Annotated[
        int, Path(gt=0, description="Додатний id категорії")
    ],
) -> Response:
    """Видалити категорію лише тоді, коли на неї нічого не посилається."""
    try:
        repository.delete_category(category_id)
    except repository.NotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except repository.ConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return Response(status_code=status.HTTP_204_NO_CONTENT)
