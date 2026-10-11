"""Модель користувача, безпечного сеансу та аудиту подій."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

PASSWORD_ITERATIONS = 310_000
SESSION_TIMEOUT_SEC = 900
EMAIL_PATTERN = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]{2,63}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$"
)


class User:
    """Обліковий запис із перевірюваною адресою та хешем пароля."""

    def __init__(self, username: str, email: str, role: str = "user") -> None:
        self.username = username
        self._email = ""
        self.email = email
        self.role = role
        self.active = True
        self.__password_hash: bytes | None = None
        self.__password_salt: bytes | None = None

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not isinstance(value, str) or not EMAIL_PATTERN.fullmatch(value):
            raise ValueError("Некоректний формат email")
        self._email = value

    def set_password(self, password: str) -> None:
        if not isinstance(password, str) or len(password) < 8:
            raise ValueError("Пароль має містити щонайменше 8 символів")
        self.__password_salt = os.urandom(16)
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PASSWORD_ITERATIONS,
        )

    def check_password(self, password: str) -> bool:
        if self.__password_hash is None or self.__password_salt is None:
            return False
        candidate = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PASSWORD_ITERATIONS,
        )
        return hmac.compare_digest(candidate, self.__password_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        return (
            f"User(username={self.username!r}, email={self.email!r}, "
            f"role={self.role!r}, active={self.active})"
        )


class Admin(User):
    """Користувач-адміністратор із керованим набором дозволів."""

    def __init__(
        self, username: str, email: str, permissions: set[str] | None = None
    ) -> None:
        super().__init__(username, email, role="admin")
        self.permissions = (
            set(permissions) if permissions is not None else set()
        )

    def grant_permission(self, permission: str) -> None:
        if not permission.strip():
            raise ValueError("Дозвіл не може бути порожнім")
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        return f"{super().__str__()}, permissions={sorted(self.permissions)!r}"


class Session:
    """Сеанс користувача з часовими мітками UTC."""

    def __init__(self, ip: str) -> None:
        self.ip = ip
        self.login_time = datetime.now(UTC)
        self.last_activity = self.login_time

    def touch(self) -> None:
        self.last_activity = datetime.now(UTC)

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("timeout_sec має бути додатним")
        return datetime.now(UTC) - self.last_activity < timedelta(
            seconds=timeout_sec
        )


@dataclass(frozen=True)
class AuditRecord:
    """Одна структурована подія аудиту."""

    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Зберігає події автентифікації без секретних даних."""

    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def add_log(self, username: str, action: str) -> None:
        self.records.append(AuditRecord(datetime.now(UTC), username, action))

    def show_all(self) -> None:
        if not self.records:
            print("Записів аудиту немає.")
            return
        for record in self.records:
            print(
                f"{record.timestamp.isoformat()} {record.username}: "
                f"{record.action}"
            )


class UserAccount:
    """Об'єднує користувача, його активний сеанс і журнал аудиту."""

    _ALLOWED_KEYS = {"user", "session", "audit_log"}

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.user = user
        self.session = session
        self.audit_log = audit_log if audit_log is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        if username != self.user.username or not self.user.active:
            self.audit_log.add_log(username, "login_failure")
            return False
        if not self.user.check_password(password):
            self.audit_log.add_log(username, "login_failure")
            return False
        self.session = Session(ip)
        self.session.touch()
        self.audit_log.add_log(username, "login_success")
        return True

    def is_authenticated(self) -> bool:
        return self.session is not None and self.session.is_active(
            SESSION_TIMEOUT_SEC
        )

    def logout(self) -> None:
        if self.session is not None:
            self.session = None
            self.audit_log.add_log(self.user.username, "logout")

    def __getitem__(self, key: str) -> User | Session | AuditLog | None:
        if key not in self._ALLOWED_KEYS:
            raise KeyError(key)
        return getattr(self, key)

    def __setitem__(
        self, key: str, value: User | Session | AuditLog | None
    ) -> None:
        expected = {"user": User, "session": Session, "audit_log": AuditLog}
        if key not in expected:
            raise KeyError(key)
        if value is not None and not isinstance(value, expected[key]):
            raise TypeError(f"Для ключа {key!r} неприпустимий тип")
        if key == "user" and value is None:
            raise TypeError("user не може бути None")
        setattr(self, key, value)


def run_demo() -> None:
    """Показує основні сценарії користувача та журналювання."""
    user = User("vlad", "vladislav@example.com")
    user.set_password("StrongPass!2026")
    admin = Admin("admin", "admin@example.com", {"read_logs"})
    admin.grant_permission("manage_users")
    account = UserAccount(user)

    print("=== User and session demo ===")
    successful_login = account.login("vlad", "StrongPass!2026", "127.0.0.1")
    print(f"Успішний вхід: {successful_login}")
    failed_login = account.login("vlad", "wrong-password", "127.0.0.1")
    print(f"Невдалий вхід: {failed_login}")
    print(f"Автентифіковано: {account.is_authenticated()}")
    try:
        user.email = "invalid-email"
    except ValueError as exc:
        print(f"Email відхилено: {exc}")
    user.email = "vladislav_new@example.com"
    print(f"Оновлений email: {user.email}")
    has_permission = admin.has_permission("manage_users")
    print(f"Адміністратор має manage_users: {has_permission}")

    if account.session is not None:
        account.session.last_activity -= timedelta(
            seconds=SESSION_TIMEOUT_SEC + 1
        )
    print(f"Сеанс після таймауту: {account.is_authenticated()}")
    account.logout()
    print("Журнал аудиту:")
    account.audit_log.show_all()
