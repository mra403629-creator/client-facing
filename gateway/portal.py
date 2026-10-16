"""End-user (trader) layer.

Each trader logs in with THEIR OWN MT5 login + password (verified by the manager
API's UserPasswordCheck) and gets a short-lived session token. A token is bound
to that one login, so there is no way to name another account.

  * main password      -> scope 'trade' (can read + submit money REQUESTS)
  * investor password  -> scope 'read'  (read only)
  * money never moves directly: a trader files a request, the owning tenant
    (broker staff, via the tenant API key) approves or rejects it.
  * the trader's group must belong to an active tenant with 'user_portal'.
"""
from __future__ import annotations

import logging
import math
import uuid
from typing import Optional

from .errors import (Conflict, Forbidden, GatewayError, Invalid, NotFound, RateLimited,
                     Unauthorized, Upstream)
<<<<<<< HEAD
from .guard import GROUP_FIELDS, USER_FIELDS, Gateway, _pick
=======
from .guard import USER_FIELDS, Gateway, _pick
>>>>>>> b50a59827a70a7449709420a7fd53947c8282e1e
from .masks import match_group
from .store import Session, Tenant

log = logging.getLogger("gateway.portal")

SESSION_TTL = 3600           # 1 hour
FAIL_WINDOW = 300            # 5 minutes
MAX_FAILS_PER_LOGIN = 5
MAX_FAILS_PER_IP = 20
MAX_PENDING_PER_LOGIN = 5
GENERIC_LOGIN_ERROR = "invalid login or password"
REQUEST_FIELDS_USER = ("id", "kind", "amount", "comment", "status", "note", "created_at", "decided_at", "deal_id")


class Portal:
    def __init__(self, gw: Gateway):
        self.gw = gw
        self.backend = gw.backend
        self.store = gw.store

    # ------------------------------------------------------------ helpers
    def _call(self, action: str, fn, *args):
        try:
            return fn(*args)
        except GatewayError:
            raise
        except Exception as exc:
            ref = uuid.uuid4().hex[:12]
            log.error("[%s] portal %s failed: %s", ref, action, exc)
            raise Upstream(f"upstream error (ref {ref})")

    def _tenant_for_group(self, group: Optional[str]) -> Optional[Tenant]:
        if not group:
            return None
        for t in self.store.list_tenants():  # masks never overlap, so at most one matches
            if match_group(group, t.masks):
                return t
        return None

    @staticmethod
    def _eligible(t: Optional[Tenant]) -> bool:
        return bool(t and t.active and "user_portal" in t.permissions)

    # ------------------------------------------------------------ login
    def login(self, login: int, password: str, ip: str) -> dict:
        if (self.store.count_fails(login=login, window=FAIL_WINDOW) >= MAX_FAILS_PER_LOGIN
                or self.store.count_fails(ip=ip, window=FAIL_WINDOW) >= MAX_FAILS_PER_IP):
            raise RateLimited("too many failed attempts, try again in a few minutes")

        def fail():
            self.store.record_fail(login, ip)
            raise Unauthorized(GENERIC_LOGIN_ERROR)  # same answer for unknown / wrong / not eligible

        if not password or len(password) > 128:
            fail()
        groups = self._call("user_groups", self.backend.user_groups, [login])
        tenant = self._tenant_for_group(groups.get(login))
        if not self._eligible(tenant):
            fail()

        scope = None
        if self._call("check_password", self.backend.check_password, login, password, "main"):
            scope = "trade"
        elif self._call("check_password", self.backend.check_password, login, password, "investor"):
            scope = "read"
        if scope is None:
            fail()

        self.store.clear_fails(login)
        token = self.store.create_session(login, tenant.id, scope, SESSION_TTL)
        self.store.audit(tenant.id, "user_login", login, None, "ok", scope)
        return {"token": token, "token_type": "Bearer", "expires_in": SESSION_TTL, "scope": scope, "login": login}

    def logout(self, sess: Session):
        self.store.delete_session(sess.token_hash)
        return {"logged_out": True}

    # ------------------------------------------------------------ session check
    def authenticate(self, token: str) -> tuple:
        """token -> (Session, Tenant). Re-checks live ownership every call (fail closed)."""
        sess = self.store.session_for_token(token)
        if sess is None:
            raise Unauthorized("invalid or expired token")
        try:
            groups = self._call("user_groups", self.backend.user_groups, [sess.login])
        except Upstream:
            raise
        tenant = self._tenant_for_group(groups.get(sess.login))
        if not self._eligible(tenant) or tenant.id != sess.tenant_id:
            self.store.delete_session(sess.token_hash)  # moved group / tenant disabled / user deleted
            raise Unauthorized("invalid or expired token")
        return sess, tenant

    # ------------------------------------------------------------ own data (login comes from the token only)
    def me(self, sess: Session) -> dict:
        user = self._call("get_user", self.backend.get_user, sess.login)
        return {**_pick(user, USER_FIELDS), "scope": sess.scope}

    def account(self, sess: Session) -> dict:
        return self._call("balance", self.backend.balance, sess.login)

<<<<<<< HEAD
    def my_group(self, sess: Session, tenant: Tenant) -> dict:
        """The trader's OWN group only; the name comes from the live user record, never from input."""
        user = self._call("get_user", self.backend.get_user, sess.login)
        name = user.get("Group")
        if not name or not match_group(name, tenant.masks):
            raise NotFound("not found")
        try:
            g = self._call("get_group", self.backend.get_group, name)
        except KeyError:
            raise NotFound("not found")
        return _pick(g, GROUP_FIELDS)

=======
>>>>>>> b50a59827a70a7449709420a7fd53947c8282e1e
    # ------------------------------------------------------------ money requests
    def create_request(self, sess: Session, tenant: Tenant, kind: str, amount: float, comment: str) -> dict:
        if sess.scope != "trade":
            raise Forbidden("investor (read-only) login cannot submit requests")
        if kind not in ("deposit", "withdraw"):
            raise Invalid("kind must be 'deposit' or 'withdraw'")
        try:
            amount = float(amount)
        except (TypeError, ValueError):
            raise Invalid("amount must be a number")
        if not math.isfinite(amount) or amount <= 0:
            raise Invalid("amount must be a number greater than 0")
        if amount > tenant.max_amount:
            raise Invalid(f"amount exceeds the per-request limit ({tenant.max_amount:g})")
        if self.store.count_pending(sess.login) >= MAX_PENDING_PER_LOGIN:
            raise Conflict(f"you already have {MAX_PENDING_PER_LOGIN} open requests")
        req = self.store.create_request(tenant.id, sess.login, kind, amount, (comment or "")[:24])
        self.store.audit(tenant.id, f"user_request_{kind}", sess.login, amount, "pending", f"req={req['id']}")
        return _pick(req, REQUEST_FIELDS_USER)

    def my_requests(self, sess: Session, limit: int) -> list:
        return [_pick(r, REQUEST_FIELDS_USER) for r in self.store.list_requests(login=sess.login, limit=limit)]

    def cancel_request(self, sess: Session, req_id: int) -> dict:
        if not self.store.transition_request(req_id, None, "pending", "cancelled", login=sess.login):
            raise NotFound("not found or not cancellable")
        return _pick(self.store.get_request(req_id), REQUEST_FIELDS_USER)

    # ------------------------------------------------------------ tenant side (broker staff, tenant API key)
    def tenant_list(self, tenant: Tenant, status: Optional[str], limit: int) -> list:
        self.gw._need(tenant, "read")
        return self.store.list_requests(tenant_id=tenant.id, status=status, limit=limit)

    def _own_request(self, tenant: Tenant, req_id: int) -> dict:
        r = self.store.get_request(req_id)
        if r is None or r["tenant_id"] != tenant.id:
            raise NotFound("not found")
        return r

    def approve(self, tenant: Tenant, req_id: int) -> dict:
        r = self._own_request(tenant, req_id)
        self.gw._need(tenant, r["kind"])  # needs 'deposit' / 'withdraw' permission
        if r["status"] == "pending":
            if not self.store.transition_request(req_id, tenant.id, "pending", "approving"):
                raise Conflict("request was already handled")
        elif r["status"] != "approving":
            raise Conflict(f"request is {r['status']}")
        # status 'approving' (a previous attempt had an unknown outcome) falls through:
        # the fixed idempotency key makes this safe, it can never pay twice.
        comment = f"req#{req_id} {r['comment']}".strip()
        try:
            resp, _ = self.gw.money(tenant, r["login"], r["amount"], comment, r["kind"], f"request-{req_id}")
        except (Invalid, NotFound, Forbidden) as exc:   # definite failure, nothing moved
            self.store.transition_request(req_id, tenant.id, "approving", "failed", note=str(exc)[:200])
            raise
        # Upstream / Conflict(in-progress): outcome unknown -> stay 'approving' for a safe re-approve
        self.store.transition_request(req_id, tenant.id, "approving", "approved", deal_id=resp.get("deal_id"))
        return {"request": self.store.get_request(req_id), "result": resp}

    def reject(self, tenant: Tenant, req_id: int, note: str) -> dict:
        r = self._own_request(tenant, req_id)
        self.gw._need(tenant, r["kind"])
        if not self.store.transition_request(req_id, tenant.id, "pending", "rejected", note=(note or "")[:200]):
            raise Conflict(f"request is {self.store.get_request(req_id)['status']}")
        self.store.audit(tenant.id, "request_rejected", r["login"], r["amount"], "ok", f"req={req_id}")
        return self.store.get_request(req_id)
