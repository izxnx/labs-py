# Завдання 3: Безпечне хешування, CSV-база та JSON-логування
# Варіант 8: sha256, мінімальна довжина пароля - 11

import csv
import hashlib
import json
import os
from datetime import datetime

VARIANT = 8
MIN_PASSWORD_LENGTH = 11
MY_SALT = str(VARIANT).zfill(5)          # "00008"

DATA_FOLDER = "labs/lab01/data"
USERS_FILE = DATA_FOLDER + "/users.csv"
LOG_FILE = DATA_FOLDER + "/log.json"


class ValidationError(Exception):
    pass

def generate_hash(password: str, salt: str = "00000") -> str:
    if not password or not salt:
        raise ValueError("Пароль і сіль не можуть бути порожніми")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(f"Пароль коротший за {MIN_PASSWORD_LENGTH} символів")
    return hashlib.sha256((password + salt).encode()).hexdigest()


users_to_register = (
    ("oleksandr_k", "Passw0rd!2024"), ("mariia_p", "SecureKey#88"),
    ("dmytro_h", "StrongPass_777"), ("kateryna_l", "MyP@ssword2023"),
    ("andrii_s", "Qwerty12345!"), ("natalia_b", "SunnyDay#2024"),
    ("ihor_m", "GreenForest99!"), ("yuliia_r", "BlueOcean2023$"),
    ("serhii_t", "RedApple777#"), ("olena_v", "shortpw"),  # закоротко -> ValidationError
)


def create_user(username, password):
    return username, generate_hash(password, MY_SALT)


def create_users(users_list):
    os.makedirs(DATA_FOLDER, exist_ok=True)
    try:
        with open(USERS_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            for username, password in users_list:
                try:
                    writer.writerow(create_user(username, password))
                except (ValueError, ValidationError) as e:
                    print(f"Пропущено '{username}': {e}")
    except (FileNotFoundError, PermissionError, IOError) as e:
        print("Помилка запису файлу:", e)


def read_users_db():
    users_db = []
    try:
        with open(USERS_FILE, encoding="utf-8") as f:
            users_db = [tuple(row) for row in csv.reader(f) if row]
    except FileNotFoundError as e:
        print("Файл не знайдено:", e)
    except (PermissionError, IOError) as e:
        print("Помилка читання файлу:", e)
    return users_db


def print_users_table(users_db):
    print(f"{'Логін':<15} | Хеш пароля")
    print("-" * 80)
    for username, password_hash in users_db:
        print(f"{username:<15} | {password_hash}")


def save_log_entry(user, result):
    os.makedirs(DATA_FOLDER, exist_ok=True)
    entry = {
        "event": "login", "user": user, "result": result,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "args": [], "kwargs": {},   # пароль у лог не пишемо - це небезпечно
    }
    try:
        with open(LOG_FILE, encoding="utf-8") as f:
            logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        logs = []
    logs.append(entry)
    try:
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(logs, f, ensure_ascii=False, indent=2)
    except (PermissionError, IOError) as e:
        print("Помилка запису лог-файлу:", e)


def log_event(func):
    def wrapper(username, password):
        try:
            success = func(username, password)
        except Exception:
            save_log_entry(username, "failure")
            raise  # без raise e, щоб зберегти оригінальний traceback помилки
        save_log_entry(username, "success" if success else "failure")
        return success
    return wrapper


users_db = []


@log_event
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError("Логін і пароль не можуть бути порожніми")
    for stored_username, stored_hash in users_db:
        if stored_username == username:
            return generate_hash(password, MY_SALT) == stored_hash
    return False


def main():
    global users_db

    print(f"Варіант: {VARIANT}, сіль: {MY_SALT}, алгоритм: sha256\n")

    create_users(list(users_to_register))

    users_db = read_users_db()
    print_users_table(users_db)

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
            print(f"'{username}' -> {'успішно' if success else 'відмовлено'}")
        except ValueError as e:
            print(f"'{username}' -> помилка: {e}")


if __name__ == "__main__":
    main()