"""Public client API + admin API.

Run:  uvicorn gateway.main:app --host 0.0.0.0 --port 8000
The old app.main (direct Manager API REST) must NOT be exposed any more.
"""
from __future__ import annotations

import ipaddress
import logging
import secrets
from contextlib import asynccontextmanager
from typing import List, Literal, Optional

from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import config
from .errors import Forbidden, GatewayError, NotFound, RateLimited, Unauthorized
from .guard import Gateway
from .portal import Portal
from .ratelimit import RateLimiter
from .store import Session, Store, Tenant

log = logging.getLogger("gateway")


# ---------------------------------GR/-------------------------------- models
class UserCreate(BaseModel):
    group: str
    leverage: int = Field(100, ge=1, le=10000)
    first_name: str = ""
    last_name: str = ""
    name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    zipcode: Optional[str] = None
    address: Optional[str] = None
    password: str
    investor_password: str = ""
    # NOTE: no 'rights' and no 'comment' field on purpose. Unknown fields are ignored.


class MoneyBody(BaseModel):
    amount: float
    comment: str = ""


class AccountsRequest(BaseModel):
    logins: List[int]


class UserLogin(BaseModel):
    login: int
    password: str = Field(..., max_length=128)


class UserRequestBody(BaseModel):
    kind: Literal["deposit", "withdraw"]
    amount: float
    comment: str = Field("", max_length=64)


class RejectBody(BaseModel):
    note: str = Field("", max_length=200)


class TenantCreate(BaseModel):
    name: str
    masks: str
    permissions: List[str] = ["read"]
    rate_per_min: Optional[int] = None
    max_amount: Optional[float] = None
    ip_allow: List[str] = []


class TenantPatch(BaseModel):
    masks: Optional[str] = None
    permissions: Optional[List[str]] = None
    rate_per_min: Optional[int] = None
    max_amount: Optional[float] = None
    ip_allow: Optional[List[str]] = None
    active: Optional[bool] = None


# ----------------------------------------------------------------- app factory
def create_app(backend=None, store: Store = None) -> FastAPI:
    store = store or Store()
    if backend is None:
        from .backend import RealBackend

        backend = RealBackend()
    gw = Gateway(backend, store)
    portal = Portal(gw)
    limiter = RateLimiter()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        backend.start()
        yield
        backend.stop()

    app = FastAPI(title="MT5 Client Gateway", version="1.0.0", lifespan=lifespan)
    app.state.gw, app.state.store, app.state.backend = gw, store, backend

    @app.exception_handler(GatewayError)
    async def _gw_error(_req: Request, exc: GatewayError):
        headers = {}
        if isinstance(exc, RateLimited):
            headers["Retry-After"] = str(getattr(exc, "retry_after", 60))
        return JSONResponse({"detail": str(exc)}, status_code=exc.status, headers=headers)

    # ------------------------------------------------------------- auth deps
    def current_tenant(request: Request, x_api_key: Optional[str] = Header(None)) -> Tenant:
        tenant = store.tenant_for_key(x_api_key or "")
        if tenant is None:
            raise Unauthorized("invalid or missing API key")
        if tenant.ip_allow:
            try:
                ip = ipaddress.ip_address(request.client.host if request.client else "")
                ok = any(ip in ipaddress.ip_network(n) for n in tenant.ip_allow)
            except ValueError:
                ok = False
            if not ok:
                store.audit(tenant.id, "auth", None, None, "ip_denied", str(request.client))
                raise Forbidden("source IP not allowed")
        wait = limiter.check(tenant.id, tenant.rate_per_min)
        if wait:
            err = RateLimited("rate limit exceeded")
            err.retry_after = wait
            raise err
        return tenant

    def admin_only(x_admin_key: Optional[str] = Header(None)):
        if not config.ADMIN_KEY:
            raise NotFound("not found")  # admin API disabled when no key configured
        if not secrets.compare_digest((x_admin_key or "").encode(), config.ADMIN_KEY.encode()):
            raise Unauthorized("invalid admin key")

    # ------------------------------------------------------------- health
    @app.get("/healthz")
    def healthz():
        return {"ok": True, "mt5_connected": backend.connected()}

    # ------------------------------------------------------------- client API
    @app.get("/v1/me")
    def me(tenant: Tenant = Depends(current_tenant)):
        d = tenant.public()
        d.pop("ip_allow")
        return d

    @app.get("/v1/users")
    def list_users(
        limit: int = Query(100, ge=1, le=1000),
        offset: int = Query(0, ge=0),
        group: Optional[str] = Query(None, description="exact group name inside your scope"),
        tenant: Tenant = Depends(current_tenant),
    ):
        return gw.list_users(tenant, limit, offset, group)

    @app.get("/v1/groups")
    def list_groups(tenant: Tenant = Depends(current_tenant)):
        return gw.list_groups(tenant)

    @app.get("/v1/groups/{group:path}")  # group names contain a backslash (client1\\retail)
    def get_group(group: str, tenant: Tenant = Depends(current_tenant)):
        return gw.get_group(tenant, group)

    @app.get("/v1/users/{login}")
    def get_user(login: int, tenant: Tenant = Depends(current_tenant)):
        return gw.get_user(tenant, login)

    @app.post("/v1/users", status_code=201)
    def create_user(req: UserCreate, tenant: Tenant = Depends(current_tenant)):
        return gw.create_user(tenant, req.model_dump())

    @app.get("/v1/users/{login}/balance")
    def balance(login: int, tenant: Tenant = Depends(current_tenant)):
        return gw.balance(tenant, login)

    def _money(kind: str, login: int, body: MoneyBody, tenant: Tenant, key: Optional[str]):
        if not key or not (8 <= len(key) <= 64) or not key.isascii() or not key.isprintable():
            from .errors import Invalid

            raise Invalid("Idempotency-Key header required (8-64 printable ASCII chars)")
        result, replayed = gw.money(tenant, login, body.amount, body.comment, kind, key)
        return JSONResponse(result, headers={"Idempotent-Replay": "true"} if replayed else None)

    @app.post("/v1/users/{login}/deposit")
    def deposit(login: int, body: MoneyBody, tenant: Tenant = Depends(current_tenant),
                idempotency_key: Optional[str] = Header(None)):
        return _money("deposit", login, body, tenant, idempotency_key)

    @app.post("/v1/users/{login}/withdraw")
    def withdraw(login: int, body: MoneyBody, tenant: Tenant = Depends(current_tenant),
                 idempotency_key: Optional[str] = Header(None)):
        return _money("withdraw", login, body, tenant, idempotency_key)

    @app.post("/v1/accounts")
    def accounts(req: AccountsRequest, tenant: Tenant = Depends(current_tenant)):
        return gw.accounts(tenant, req.logins)

    # ------------------------------------------------------------- trader (end-user) API
    def user_ctx(request: Request, authorization: Optional[str] = Header(None)):
        token = (authorization or "").removeprefix("Bearer ").strip()
        sess, tenant = portal.authenticate(token)
        wait = limiter.check(("u", sess.login), 60)
        if wait:
            err = RateLimited("rate limit exceeded")
            err.retry_after = wait
            raise err
        return sess, tenant

    @app.post("/u/v1/auth/login")
    def user_login(body: UserLogin, request: Request):
        ip = request.client.host if request.client else "unknown"
        return portal.login(body.login, body.password, ip)

    @app.post("/u/v1/auth/logout")
    def user_logout(ctx=Depends(user_ctx)):
        return portal.logout(ctx[0])

    @app.get("/u/v1/me")
    def user_me(ctx=Depends(user_ctx)):
        return portal.me(ctx[0])

    @app.get("/u/v1/account")
    def user_account(ctx=Depends(user_ctx)):
        return portal.account(ctx[0])

    @app.get("/u/v1/group")
    def user_group(ctx=Depends(user_ctx)):
        return portal.my_group(ctx[0], ctx[1])

    @app.post("/u/v1/requests", status_code=201)
    def user_create_request(body: UserRequestBody, ctx=Depends(user_ctx)):
        return portal.create_request(ctx[0], ctx[1], body.kind, body.amount, body.comment)

    @app.get("/u/v1/requests")
    def user_requests(limit: int = Query(50, ge=1, le=200), ctx=Depends(user_ctx)):
        return portal.my_requests(ctx[0], limit)

    @app.post("/u/v1/requests/{req_id}/cancel")
    def user_cancel_request(req_id: int, ctx=Depends(user_ctx)):
        return portal.cancel_request(ctx[0], req_id)

    # ------------------------------------------------------------- tenant: handle its traders' requests
    @app.get("/v1/requests")
    def tenant_requests(status: Optional[str] = Query(None, pattern="^(pending|approving|approved|rejected|failed|cancelled)$"),
                        limit: int = Query(100, ge=1, le=1000), tenant: Tenant = Depends(current_tenant)):
        return portal.tenant_list(tenant, status, limit)

    @app.post("/v1/requests/{req_id}/approve")
    def tenant_approve(req_id: int, tenant: Tenant = Depends(current_tenant)):
        return portal.approve(tenant, req_id)

    @app.post("/v1/requests/{req_id}/reject")
    def tenant_reject(req_id: int, body: RejectBody, tenant: Tenant = Depends(current_tenant)):
        return portal.reject(tenant, req_id, body.note)

    # ------------------------------------------------------------- admin API
    def _bad(exc: ValueError):
        from .errors import Invalid

        return Invalid(str(exc))

    @app.post("/admin/v1/tenants", status_code=201, dependencies=[Depends(admin_only)])
    def admin_create_tenant(body: TenantCreate):
        try:
            t = store.create_tenant(body.name, body.masks, body.permissions, body.rate_per_min,
                                    body.max_amount, body.ip_allow)
        except ValueError as exc:
            raise _bad(exc)
        key = store.issue_key(t.id)
        store.audit(t.id, "admin_create_tenant", status="ok", detail=t.masks)
        return {"tenant": t.public(), "api_key": key, "note": "store this key now; it is not shown again"}

    @app.get("/admin/v1/tenants", dependencies=[Depends(admin_only)])
    def admin_list_tenants():
        return [t.public() for t in store.list_tenants()]

    @app.patch("/admin/v1/tenants/{tenant_id}", dependencies=[Depends(admin_only)])
    def admin_patch_tenant(tenant_id: int, body: TenantPatch):
        try:
            t = store.update_tenant(tenant_id, **body.model_dump())
        except KeyError:
            raise NotFound("tenant not found")
        except ValueError as exc:
            raise _bad(exc)
        store.audit(tenant_id, "admin_update_tenant", status="ok", detail=str(body.model_dump(exclude_none=True)))
        return t.public()

    @app.post("/admin/v1/tenants/{tenant_id}/keys", status_code=201, dependencies=[Depends(admin_only)])
    def admin_new_key(tenant_id: int):
        try:
            key = store.issue_key(tenant_id)
        except KeyError:
            raise NotFound("tenant not found")
        store.audit(tenant_id, "admin_issue_key", status="ok")
        return {"api_key": key, "note": "store this key now; it is not shown again"}

    @app.get("/admin/v1/tenants/{tenant_id}/keys", dependencies=[Depends(admin_only)])
    def admin_list_keys(tenant_id: int):
        return store.list_keys(tenant_id)

    @app.delete("/admin/v1/tenants/{tenant_id}/keys/{prefix}", dependencies=[Depends(admin_only)])
    def admin_revoke_key(tenant_id: int, prefix: str):
        n = store.revoke_key(tenant_id, prefix)
        if not n:
            raise NotFound("key not found")
        store.audit(tenant_id, "admin_revoke_key", status="ok", detail=prefix)
        return {"revoked": n}

    @app.get("/admin/v1/audit", dependencies=[Depends(admin_only)])
    def admin_audit(tenant_id: Optional[int] = None, limit: int = Query(100, ge=1, le=1000)):
        return store.list_audit(tenant_id, limit)

    return app


def _default_app() -> FastAPI:
    return create_app()


# `uvicorn gateway.main:app` builds the real app lazily so importing this module
# (e.g. in tests) never needs MT5Manager.
def __getattr__(name):
    if name == "app":
        global app
        app = _default_app()
        return app
    raise AttributeError(name)
