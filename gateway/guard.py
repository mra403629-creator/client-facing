"""Tenant enforcement. Every client-facing operation goes through here.

Rules:
  * Ownership = the user's live MT5 group matches the tenant mask (fail closed).
  * Not-yours and doesn't-exist are indistinguishable (same 404).
  * Ownership check and money movement happen under ONE lock (no check/act gap).
  * Clients can never set account rights; created users are forced into
    the tenant's own groups.
  * Upstream error details are logged/audited, never returned to clients.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import re
import uuid
from typing import Dict, List, Optional

from .backend import Backend
from .errors import Conflict, Forbidden, GatewayError, Invalid, NotFound, Upstream
from .masks import match_group
from .store import Store, Tenant

log = logging.getLogger("gateway.guard")

MAX_ACCOUNT_LOGINS = 500  # SDK-side practical limit used by the existing service

USER_FIELDS = (
    "Login", "Group", "Name", "FirstName", "LastName", "EMail", "Phone", "Country",
    "City", "State", "ZIPCode", "Address", "Leverage", "Balance", "Credit",
    "Registration", "LastAccess",
)
CREATE_FIELDS = (
    "group", "leverage", "first_name", "last_name", "name", "email", "phone",
    "country", "city", "state", "zipcode", "address", "password", "investor_password",
)
NOT_FOUND_MSG = "not found"


def _pick(d: dict, keys) -> dict:
    return {k: d.get(k) for k in keys if k in d}


def _check_password(pw: str, label: str):
    # SDK (UserAdd): 8-16 chars, lower + upper + digit + special
    if not (8 <= len(pw) <= 16):
        raise Invalid(f"{label} must be 8-16 characters")
    if not (re.search(r"[a-z]", pw) and re.search(r"[A-Z]", pw)
            and re.search(r"\d", pw) and re.search(r"[^A-Za-z0-9]", pw)):
        raise Invalid(f"{label} needs lowercase, uppercase, digit and special character")


class Gateway:
    def __init__(self, backend: Backend, store: Store):
        self.backend = backend
        self.store = store

    # ------------------------------------------------------------ helpers
    @staticmethod
    def _need(tenant: Tenant, perm: str):
        if perm not in tenant.permissions:
            raise Forbidden(f"permission '{perm}' required")

    def _upstream(self, tenant: Tenant, action: str, fn, *args):
        try:
            return fn(*args)
        except GatewayError:
            raise
        except KeyError:
            raise NotFound(NOT_FOUND_MSG)
        except ValueError as exc:  # business errors from the service (no money, too large, ...)
            raise Invalid(str(exc))
        except Exception as exc:
            ref = uuid.uuid4().hex[:12]
            log.error("[%s] upstream %s failed for tenant %s: %s", ref, action, tenant.name, exc)
            self.store.audit(tenant.id, action, None, None, "upstream_error", f"{ref}: {exc}")
            raise Upstream(f"upstream error (ref {ref})")

    def _owned_groups(self, tenant: Tenant, logins: List[int]) -> Dict[int, str]:
        """login -> group, only for logins owned by `tenant`. Fails closed."""
        groups = self._upstream(tenant, "ownership_check", self.backend.user_groups, list(logins))
        return {lg: g for lg, g in groups.items() if match_group(g, tenant.masks)}

    def _assert_owned(self, tenant: Tenant, login: int, action: str):
        if login not in self._owned_groups(tenant, [login]):
            self.store.audit(tenant.id, action, login, None, "not_owned")
            raise NotFound(NOT_FOUND_MSG)

    # ------------------------------------------------------------ reads
    def get_user(self, tenant: Tenant, login: int) -> dict:
        self._need(tenant, "read")
        self._assert_owned(tenant, login, "get_user")
        user = self._upstream(tenant, "get_user", self.backend.get_user, login)
        if not match_group(user.get("Group", ""), tenant.masks):  # defence in depth
            raise NotFound(NOT_FOUND_MSG)
        return _pick(user, USER_FIELDS)

    def list_users(self, tenant: Tenant, limit: int, offset: int, group: Optional[str] = None) -> dict:
        self._need(tenant, "read")
        if group is not None:
            # exact group name only (no wildcards), and it must be inside the tenant scope
            if any(c in group for c in "*,!") or not match_group(group, tenant.masks):
                raise NotFound(NOT_FOUND_MSG)
            mask = group
        else:
            mask = tenant.masks
        res = self._upstream(tenant, "list_users", self.backend.list_users, mask, limit, offset)
        users = [u for u in res["users"] if match_group(u.get("Group", ""), tenant.masks)]
        if len(users) != len(res["users"]):
            log.error("backend returned out-of-scope users for tenant %s", tenant.name)
        return {
            "total": res["total"], "count": len(users), "offset": res["offset"],
            "users": [_pick(u, USER_FIELDS) for u in users],
        }

    def balance(self, tenant: Tenant, login: int) -> dict:
        self._need(tenant, "read")
        self._assert_owned(tenant, login, "balance")
        return self._upstream(tenant, "balance", self.backend.balance, login)

    def accounts(self, tenant: Tenant, logins: List[int]) -> dict:
        self._need(tenant, "read")
        logins = list(dict.fromkeys(int(x) for x in logins))
        if not logins:
            raise Invalid("logins list is empty")
        if len(logins) > MAX_ACCOUNT_LOGINS:
            raise Invalid(f"max {MAX_ACCOUNT_LOGINS} logins per request")
        owned = self._owned_groups(tenant, logins)
        mine = [lg for lg in logins if lg in owned]
        items, found = [], set()
        if mine:
            res = self._upstream(tenant, "accounts", self.backend.accounts, mine)
            for a in res.get("accounts", []):
                if a.get("Login") in owned:
                    items.append(a)
                    found.add(a["Login"])
        return {
            "requested": len(logins), "found": len(items),
            "not_found": [lg for lg in logins if lg not in found],  # foreign + unknown look the same
            "accounts": items,
        }

    # ------------------------------------------------------------ money
    def money(self, tenant: Tenant, login: int, amount: float, comment: str,
              kind: str, idem_key: str):
        """kind: 'deposit' | 'withdraw'. Returns (response, replayed)."""
        self._need(tenant, kind)
        try:
            amount = float(amount)
        except (TypeError, ValueError):
            raise Invalid("amount must be a number")
        if not math.isfinite(amount) or amount <= 0:
            raise Invalid("amount must be a number greater than 0")
        if amount > tenant.max_amount:
            self.store.audit(tenant.id, kind, login, amount, "over_limit")
            raise Invalid(f"amount exceeds your per-operation limit ({tenant.max_amount:g})")
        comment = (comment or "")[:31]

        req_hash = hashlib.sha256(f"{kind}|{login}|{amount:.8f}|{comment}".encode()).hexdigest()
        state, stored = self.store.idem_begin(tenant.id, idem_key, req_hash)
        if state == "replay":
            return json.loads(stored), True
        if state == "conflict":
            raise Conflict("Idempotency-Key was already used with a different request")
        if state == "inflight":
            raise Conflict("a request with this Idempotency-Key is still in progress or its "
                           "outcome is unknown; check the balance before retrying")

        unknown_outcome = False
        try:
            op = self.backend.deposit if kind == "deposit" else self.backend.withdraw
            with self.backend.lock:  # ownership check + money move are one atomic step
                self._assert_owned(tenant, login, kind)
                try:
                    result = self._upstream(tenant, kind, op, login, amount, comment)
                except Upstream:
                    # The SDK call blew up mid-flight: we cannot know if money moved.
                    # Keep the key 'pending' so a blind retry gets 409 instead of paying twice.
                    unknown_outcome = True
                    raise
        except GatewayError as exc:
            if not unknown_outcome:
                self.store.idem_abort(tenant.id, idem_key)  # definite failure: retry is allowed
            self.store.audit(tenant.id, kind, login, amount,
                             "unknown_outcome" if unknown_outcome else "failed", str(exc))
            raise

        response = {
            "login": login, "type": kind, "amount": amount,
            "deal_id": result.get("deal_id"), "account_after": result.get("account_after"),
        }
        self.store.idem_finish(tenant.id, idem_key, response)
        self.store.audit(tenant.id, kind, login, amount, "ok", f"deal={response['deal_id']}")
        return response, False

    # ------------------------------------------------------------ create user
    def create_user(self, tenant: Tenant, data: dict) -> dict:
        self._need(tenant, "create_user")
        group = (data.get("group") or "").strip()
        if not group or any(c in group for c in "*,!") or not match_group(group, tenant.masks):
            self.store.audit(tenant.id, "create_user", None, None, "bad_group", group)
            raise Forbidden("group is outside your allowed groups")
        _check_password(data.get("password") or "", "password")
        if data.get("investor_password"):
            _check_password(data["investor_password"], "investor_password")
        if not (data.get("first_name") or data.get("last_name") or data.get("name")):
            raise Invalid("first_name, last_name or name is required")

        clean = {k: data[k] for k in CREATE_FIELDS if data.get(k) is not None}
        clean["group"] = group  # never 'rights', never 'comment'
        with self.backend.lock:
            created = self._upstream(tenant, "create_user", self.backend.create_user, clean)
        self.store.audit(tenant.id, "create_user", created.get("Login"), None, "ok", group)
        return _pick(created, USER_FIELDS)
