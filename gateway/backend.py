"""Backend interface + the real adapter around app.mt5_service.

Only this module touches the MT5 Manager API. Everything tenant-related lives
in guard.py and is tested against a fake backend.
"""
from __future__ import annotations

import logging
import os
from typing import Dict, List, Protocol

from . import config

log = logging.getLogger("gateway.backend")


class Backend(Protocol):
    lock: object  # reentrant context manager; held across "check owner + move money"

    def start(self) -> None: ...
    def stop(self) -> None: ...
    def connected(self) -> bool: ...
    def user_groups(self, logins: List[int]) -> Dict[int, str]: ...
    def get_user(self, login: int) -> dict: ...
    def list_users(self, mask: str, limit: int, offset: int) -> dict: ...
    def balance(self, login: int) -> dict: ...
    def accounts(self, logins: List[int]) -> dict: ...
    def deposit(self, login: int, amount: float, comment: str) -> dict: ...
    def withdraw(self, login: int, amount: float, comment: str) -> dict: ...
    def create_user(self, data: dict) -> dict: ...
    def check_password(self, login: int, password: str, kind: str) -> bool: ...


class RealBackend:
    """Wraps the existing MT5Service (Windows + MT5Manager package required)."""

    def __init__(self):
        from app.mt5_service import service  # lazy: MT5Manager only exists on Windows

        self.svc = service
        self.lock = service._lock  # RLock: nested calls inside service are fine

    def start(self):
        server = os.getenv("MT5_SERVER")
        login = int(os.getenv("MT5_LOGIN", "0") or 0)
        password = os.getenv("MT5_PASSWORD")
        if not (server and login and password):
            log.error("MT5_SERVER / MT5_LOGIN / MT5_PASSWORD not set; gateway starts disconnected")
            return
        try:
            self.svc.connect(server, login, password, pump_mode=config.PUMP_MODE)
            log.warning("connected to MT5 %s as manager %s (pump=%s)", server, login, config.PUMP_MODE)
        except Exception as exc:
            log.error("MT5 connect failed: %s", exc)

    def stop(self):
        self.svc.disconnect()

    def connected(self):
        return self.svc.connected()

    def reconnect(self, pump_mode: str = None):
        server = os.getenv("MT5_SERVER")
        login = int(os.getenv("MT5_LOGIN", "0") or 0)
        password = os.getenv("MT5_PASSWORD")
        return self.svc.connect(server, login, password, pump_mode=pump_mode or config.PUMP_MODE)

    def user_groups(self, logins):
        """login -> Group for logins that exist. Missing logins are simply absent."""
        svc = self.svc
        svc._check_connection()
        logins = [int(x) for x in logins]
        with self.lock:
            found: Dict[int, str] = {}
            users = svc._try("UserGetByLogins", logins)  # pump cache; needs PUMP_MODE_USERS
            if users is None or users is False:
                # cache unavailable -> ask the server per login (slower, still correct)
                for lg in logins:
                    u = svc._try("UserGet", lg)
                    if u is None or u is False:
                        u = svc._try("UserRequest", lg)
                    if u is not None and u is not False:
                        found[int(u.Login)] = u.Group
            else:
                for u in users:
                    found[int(u.Login)] = u.Group
        return found

    def get_user(self, login):
        return self.svc.get_user(login)

    def list_users(self, mask, limit, offset):
        return self.svc.list_users(mask, limit, offset)

    def balance(self, login):
        return self.svc.balance(login)

    def accounts(self, logins):
        return self.svc.accounts(logins)

    def deposit(self, login, amount, comment):
        return self.svc.deposit(login, amount, comment)

    def withdraw(self, login, amount, comment):
        return self.svc.withdraw(login, amount, comment)

    def create_user(self, data):
        return self.svc.create_user(data)

    def check_password(self, login, password, kind):
        """kind: 'main' | 'investor' (UserPasswordCheck). True only if the password is correct."""
        return bool(self.svc.password_check(int(login), password, kind)["valid"])
