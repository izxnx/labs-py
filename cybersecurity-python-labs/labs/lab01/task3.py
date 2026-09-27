"""Завдання 3: Безпечне хешування, CSV-база та JSON-логування.

Варіант 8: алгоритм sha256, мінімальна довжина пароля - 11.
"""

import csv
import hashlib
import json
import os
import sys
from datetime import UTC, datetime

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

from shared.student import VARIANT_NUMBER  # noqa: E402

MIN_PASSWORD_LENGTH = 11
MY_SALT = str(VARIANT_NUMBER).zfill(5)  # "00008"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FOLDER = os.path.join(BASE_DIR, "data")
USERS_FILE = os.path.join(DATA_FOLDER, "users.csv")
LOG_FILE = os.path.join(DATA_FOLDER, "log.json")


class ValidationError(Exception):
    """Виникає, коли пароль не відповідає вимогам довжини."""


def generate_hash(password: str, salt: str = "00000") -> str:
    """Згенерувати sha256-хеш від конкатенації пароля та солі."""
    if not password or not salt:
        raise ValueError("Пароль і сіль не можуть бути порожніми")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль коротший за {MIN_PASSWORD_LENGTH} символів"
        )
    return hashlib.sha256((password + salt).encode()).hexdigest()


USERS_TO_REGISTER = (
    ("oleksandr_k", "Passw0rd!2024"),
    ("mariia_p", "SecureKey#88"),
    ("dmytro_h", "StrongPass_777"),
    ("kateryna_l", "MyP@ssword2023"),
    ("andrii_s", "Qwerty12345!"),
    ("natalia_b", "SunnyDay#2024"),
    ("ihor_m", "GreenForest99!"),
    ("yuliia_r", "BlueOcean2023$"),
    ("serhii_t", "RedApple777#"),
    ("olena_v", "shortpw"),  # закоротко -> ValidationError
)


def create_user(username, password):
    """Створити пару (логін, хеш пароля) для запису в базу."""
    return username, generate_hash(password, MY_SALT)


def create_users(users_list):
    """Створити CSV-базу користувачів, пропускаючи некоректні записи."""
    os.makedirs(DATA_FOLDER, exist_ok=True)
    try:
        with open(USERS_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            for username, password in users_list:
                try:
                    writer.writerow(create_user(username, password))
                except (ValueError, ValidationError) as e:
                    print(f"Пропущено '{username}': {e}")
    except (OSError, PermissionError) as e:
        print("Помилка запису файлу користувачів:", e)


def read_users_db():
    """Зчитати базу користувачів із CSV-файлу."""
    if not os.path.exists(USERS_FILE):
        print("Файл бази даних не знайдено.")
        return []

    try:
        with open(USERS_FILE, encoding="utf-8") as f:
            return [tuple(row) for row in csv.reader(f) if row]
    except FileNotFoundError as e:
        print("Файл бази даних не знайдено:", e)
        return []
    except (OSError, PermissionError) as e:
        print("Помилка читання файлу користувачів:", e)
        return []


def print_users_table():
    """Вивести базу користувачів у вигляді таблиці."""
    users_db = read_users_db()
    print(f"{'Логін':<15} | Хеш пароля")
    print("-" * 80)
    for username, password_hash in users_db:
        print(f"{username:<15} | {password_hash}")


def save_log_entry(user, result):
    """Додати запис про спробу входу у JSON-журнал подій."""
    os.makedirs(DATA_FOLDER, exist_ok=True)
    entry = {
        "event": "login",
        "user": user,
        "result": result,
        "timestamp": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "args": [],
        "kwargs": {},
    }
    logs = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, encoding="utf-8") as f:
                logs = json.load(f)
        except (OSError, json.JSONDecodeError):
            logs = []

    logs.append(entry)
    try:
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(logs, f, ensure_ascii=False, indent=2)
    except (OSError, PermissionError) as e:
        print("Помилка запису лог-файлу:", e)


def log_event(func):
    """Декоратор, що логує результат кожної спроби входу."""

    def wrapper(username, password):
        try:
            success = func(username, password)
        except Exception:
            save_log_entry(username, "failure")
            raise
        save_log_entry(username, "success" if success else "failure")
        return success

    return wrapper


@log_event
def login(username: str, password: str) -> bool:
    """Перевірити логін і пароль користувача за даними з CSV-бази."""
    if not username or not password:
        raise ValueError("Логін і пароль не можуть бути порожніми")
    users_db = read_users_db()
    for stored_username, stored_hash in users_db:
        if stored_username == username:
            return generate_hash(password, MY_SALT) == stored_hash
    return False


def main():
    """Запустити демонстрацію реєстрації, зберігання та входу."""
    print(f"Варіант: {VARIANT_NUMBER}, сіль: {MY_SALT}, алгоритм: sha256\n")
    create_users(list(USERS_TO_REGISTER))
    print_users_table()
    print("\nПеревірка входу:")
    test_logins = [
        ("oleksandr_k", "Passw0rd!2024"),
        ("oleksandr_k", "wrong_password"),
        ("unknown_user", "some_password_123"),
        ("", ""),
    ]
    for username, password in test_logins:
        try:
            success = login(username, password)
            status = "успішно" if success else "відмовлено"
            print(f"'{username}' -> {status}")
        except ValueError as e:
            print(f"'{username}' -> помилка: {e}")


if __name__ == "__main__":
    main()
