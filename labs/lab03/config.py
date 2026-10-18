"""Предметні налаштування індивідуального варіанта 8."""

VARIANT_NUMBER = 8
DOMAIN_TITLE = "Облік часу відновлення сервісів"
VALUE_UNIT = "хв"
VALUE_THRESHOLD = 60.0
VALUE_MIN = 0.0
VALUE_MAX: float | None = None

CATEGORY_NAMES = ("database", "web_service", "file_storage")
RECORD_TITLE_PREFIX = "Вимірювання відновлення"
SEED_VALUES = (75.0, 20.0, 40.0, 90.0, 35.0, 65.0, 55.0, 60.0)
SEED_STATUSES = (
    "new",
    "in_progress",
    "done",
    "new",
    "done",
    "in_progress",
    "done",
    "new",
)
