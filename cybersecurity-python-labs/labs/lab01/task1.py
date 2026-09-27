"""Завдання 1: Комплексний аналізатор надійності паролів.

Варіант 8.
"""

import os
import random
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

from shared.student import STUDENT_NAME, VARIANT_NUMBER  # noqa: E402

PASSWORDS = [
    "ThreatH@nt3r",
    "weak123",
    "P3n3trat10n@Test",
    "visitor",
    "Cyber@Defense2023",
    "normal",
    "Incident@R3sp0nse",
    "standard",
    "Risk@Analys1s",
    "typical",
]

CRITERIA = {
    "min_length": 10,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

FORBIDDEN_PASSWORDS = {
    "weak123",
    "visitor",
    "normal",
    "standard",
    "typical",
    "admin",
}

SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?/~`"


def has_digit(password):
    """Перевірити, чи містить пароль хоча б одну цифру."""
    return any(ch.isdigit() for ch in password)


def has_upper(password):
    """Перевірити, чи містить пароль хоча б одну велику літеру."""
    return any(ch.isupper() for ch in password)


def has_lower(password):
    """Перевірити, чи містить пароль хоча б одну малу літеру."""
    return any(ch.islower() for ch in password)


def has_special(password):
    """Перевірити, чи містить пароль спеціальний символ."""
    return any(ch in SPECIAL_CHARS for ch in password)


def evaluate_password(password, password_list):
    """Оцінити надійність пароля згідно з критеріями варіанту.

    Повертає одну з категорій: "Заборонений", "Слабкий",
    "Середній", "Сильний", "Дуже сильний".
    """
    if password in FORBIDDEN_PASSWORDS:
        return "Заборонений"
    if len(password) < CRITERIA["min_length"]:
        return "Заборонений"

    meets_all_required = (
        has_digit(password) and has_upper(password) and has_special(password)
    )

    if meets_all_required:
        if len(password) >= CRITERIA["min_length"] + 4:
            is_unique = password_list.count(password) == 1
            return "Дуже сильний" if is_unique else "Сильний"
        return "Сильний"

    groups_ok = sum(
        [
            has_digit(password),
            has_upper(password),
            has_lower(password),
            has_special(password),
        ]
    )

    if groups_ok >= 2:
        return "Середній"
    return "Слабкий"


def main():
    """Запустити демонстрацію аналізатора надійності паролів."""
    print(f"Студент: {STUDENT_NAME}, Варіант: {VARIANT_NUMBER}\n")

    working_list = PASSWORDS.copy()
    for _ in range(3):
        random_index = random.randint(0, len(PASSWORDS) - 1)
        working_list.append(PASSWORDS[random_index])

    print(f"{'Пароль':<20}{'Оцінка надійності'}")
    print("-" * 40)
    for pwd in working_list:
        result = evaluate_password(pwd, working_list)
        print(f"{pwd:<20}{result}")


if __name__ == "__main__":
    main()
