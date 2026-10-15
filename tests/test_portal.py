import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

import gateway.config as config
from gateway.main import create_app
from gateway.store import Store
from tests.test_gateway import FakeBackend

ADMIN = {"X-Admin-Key": "adminsecret"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ADMIN_KEY", "adminsecret")
    backend = FakeBackend()
    db = str(tmp_path / "gw.db")
    store = Store(db)
    app = create_app(backend, store)
    c1 = store.create_tenant("client1", "client1\\*", ["read", "deposit", "withdraw", "user_portal"], max_amount=1000)
    # client2: has users but NO user_portal permission
    c2 = store.create_tenant("client2", "client2\\*", ["read", "deposit", "withdraw"])
    k1, k2 = store.issue_key(c1.id), store.issue_key(c2.id)
    with TestClient(app) as client:
        yield type("E", (), dict(client=client, backend=backend, store=store, db=db, c1=c1, c2=c2,
                                 h1={"X-API-Key": k1}, h2={"X-API-Key": k2}))


def login(env, lg=1001, pw="Main#1234"):
    return env.client.post("/u/v1/auth/login", json={"login": lg, "password": pw})


def bearer(r):
    return {"Authorization": "Bearer " + r.json()["token"]}


# ------------------------------------------------------------------ login
def test_login_main_and_investor_scopes(env):
    r = login(env)
    assert r.status_code == 200 and r.json()["scope"] == "trade" and r.json()["login"] == 1001
    r2 = login(env, 1001, "Inve#1234")
    assert r2.status_code == 200 and r2.json()["scope"] == "read"


def test_login_failures_are_indistinguishable(env):
    wrong = login(env, 1001, "bad")
    unknown = login(env, 777777, "whatever")
    orphan = login(env, 3001, "Main#3001")           # group with no tenant
    no_portal = login(env, 2001, "Main#2001")        # tenant without user_portal
    assert {wrong.status_code, unknown.status_code, orphan.status_code, no_portal.status_code} == {401}
    assert wrong.json() == unknown.json() == orphan.json() == no_portal.json()


def test_bruteforce_lockout_persists_and_success_clears(env):
    for _ in range(5):
        assert login(env, 1001, "bad").status_code == 401
    r = login(env, 1001, "Main#1234")                # correct password but locked
    assert r.status_code == 429
    assert login(env, 1002, "Main#5678").status_code == 200   # other login unaffected
    # lockout lives in the DB, so a "restart" (new Store on same file) keeps it
    assert Store(env.db).count_fails(login=1001) >= 5


def test_ip_lockout(env):
    for lg in range(500, 520):
        login(env, lg, "x")
    assert login(env, 1002, "Main#5678").status_code == 429


def test_login_fail_closed_when_backend_down(env):
    env.backend.fail_groups = True
    r = login(env)
    assert r.status_code == 502 and "down" not in r.text


def test_tenant_disabled_or_moved_kills_existing_session(env):
    h = bearer(login(env))
    assert env.client.get("/u/v1/account", headers=h).status_code == 200
    env.store.update_tenant(env.c1.id, active=False)
    assert env.client.get("/u/v1/account", headers=h).status_code == 401
    env.store.update_tenant(env.c1.id, active=True)
    assert env.client.get("/u/v1/account", headers=h).status_code == 401      # session was deleted, not just paused
    h = bearer(login(env))
    env.backend.users[1001]["Group"] = "client2\\retail"                       # moved to another tenant
    assert env.client.get("/u/v1/account", headers=h).status_code == 401


# ------------------------------------------------------------------ session / own data only
def test_token_only_sees_own_account(env):
    h = bearer(login(env, 1002, "Main#5678"))
    assert env.client.get("/u/v1/account", headers=h).json()["login"] == 1002
    assert env.client.get("/u/v1/me", headers=h).json()["Login"] == 1002
    # there is no way to name another login
    for path in ("/u/v1/account?login=1001", "/u/v1/me?login=1001", "/u/v1/users/1001", "/u/v1/account/1001"):
        r = env.client.get(path, headers=h)
        assert r.status_code in (200, 404, 405)
        if r.status_code == 200:
            assert r.json().get("login", r.json().get("Login")) == 1002


def test_bad_logout_expired_tokens(env):
    assert env.client.get("/u/v1/account").status_code == 401
    assert env.client.get("/u/v1/account", headers={"Authorization": "Bearer nope"}).status_code == 401
    h = bearer(login(env))
    assert env.client.post("/u/v1/auth/logout", headers=h).status_code == 200
    assert env.client.get("/u/v1/account", headers=h).status_code == 401
    h = bearer(login(env))
    con = sqlite3.connect(env.db)
    con.execute("UPDATE sessions SET expires_at=?", (time.time() - 1,)); con.commit(); con.close()
    assert env.client.get("/u/v1/account", headers=h).status_code == 401


def test_token_and_password_never_stored_in_plaintext(env):
    r = login(env)
    token = r.json()["token"]
    blob = b"".join(open(f, "rb").read() for f in (env.db, env.db + "-wal") if __import__("os").path.exists(f))
    assert token.encode() not in blob and b"Main#1234" not in blob


def test_session_cap_per_login(env):
    tokens = [login(env).json()["token"] for _ in range(8)]
    ok = [t for t in tokens if env.client.get("/u/v1/account", headers={"Authorization": "Bearer " + t}).status_code == 200]
    assert len(ok) == 5 and tokens[-1] in ok


# ------------------------------------------------------------------ requests (never execute directly)
def test_user_request_does_not_move_money(env):
    h = bearer(login(env))
    r = env.client.post("/u/v1/requests", json={"kind": "deposit", "amount": 50}, headers=h)
    assert r.status_code == 201 and r.json()["status"] == "pending"
    assert env.backend.money_calls == 0 and env.backend.users[1001]["Balance"] == 100.0
    assert [x["id"] for x in env.client.get("/u/v1/requests", headers=h).json()] == [r.json()["id"]]


def test_investor_login_is_read_only(env):
    h = bearer(login(env, 1001, "Inve#1234"))
    assert env.client.get("/u/v1/account", headers=h).status_code == 200
    assert env.client.post("/u/v1/requests", json={"kind": "withdraw", "amount": 1}, headers=h).status_code == 403


def test_request_validation_and_limits(env):
    h = bearer(login(env))
    bad = [{"kind": "deposit", "amount": 0}, {"kind": "deposit", "amount": -3}, {"kind": "deposit", "amount": 1001},
           {"kind": "transfer", "amount": 5}, {"kind": "deposit", "amount": "abc"}]
    for b in bad:
        assert env.client.post("/u/v1/requests", json=b, headers=h).status_code == 422, b
    for _ in range(5):
        assert env.client.post("/u/v1/requests", json={"kind": "deposit", "amount": 1}, headers=h).status_code == 201
    assert env.client.post("/u/v1/requests", json={"kind": "deposit", "amount": 1}, headers=h).status_code == 409


def test_user_can_cancel_only_own_pending(env):
    h1 = bearer(login(env, 1001, "Main#1234"))
    h2 = bearer(login(env, 1002, "Main#5678"))
    rid = env.client.post("/u/v1/requests", json={"kind": "deposit", "amount": 5}, headers=h1).json()["id"]
    assert env.client.post(f"/u/v1/requests/{rid}/cancel", headers=h2).status_code == 404
    assert env.client.post(f"/u/v1/requests/{rid}/cancel", headers=h1).json()["status"] == "cancelled"
    assert env.client.post(f"/u/v1/requests/{rid}/cancel", headers=h1).status_code == 404


# ------------------------------------------------------------------ tenant approves
def _file(env, kind="deposit", amount=50, lg=1001, pw="Main#1234"):
    h = bearer(login(env, lg, pw))
    return env.client.post("/u/v1/requests", json={"kind": kind, "amount": amount}, headers=h).json()["id"]


def test_tenant_approves_once_and_money_moves_once(env):
    rid = _file(env)
    pend = env.client.get("/v1/requests?status=pending", headers=env.h1).json()
    assert [p["id"] for p in pend] == [rid]
    a = env.client.post(f"/v1/requests/{rid}/approve", headers=env.h1)
    assert a.status_code == 200 and a.json()["request"]["status"] == "approved"
    assert env.backend.users[1001]["Balance"] == 150.0 and env.backend.money_calls == 1
    again = env.client.post(f"/v1/requests/{rid}/approve", headers=env.h1)
    assert again.status_code == 409
    assert env.backend.money_calls == 1


def test_withdraw_request_failure_marks_failed(env):
    rid = _file(env, "withdraw", 900)                 # balance is only 100
    r = env.client.post(f"/v1/requests/{rid}/approve", headers=env.h1)
    assert r.status_code == 422
    assert env.store.get_request(rid)["status"] == "failed"
    assert env.backend.users[1001]["Balance"] == 100.0


def test_reject_and_cross_tenant_isolation(env):
    rid = _file(env)
    assert env.client.post(f"/v1/requests/{rid}/approve", headers=env.h2).status_code == 404   # other tenant
    assert env.client.post(f"/v1/requests/{rid}/reject", headers=env.h2, json={}).status_code == 404
    assert env.client.get("/v1/requests", headers=env.h2).json() == []
    r = env.client.post(f"/v1/requests/{rid}/reject", headers=env.h1, json={"note": "no"})
    assert r.status_code == 200 and r.json()["status"] == "rejected"
    assert env.client.post(f"/v1/requests/{rid}/approve", headers=env.h1).status_code == 409
    assert env.backend.money_calls == 0


def test_permission_needed_to_approve(env):
    rid = _file(env)
    env.store.update_tenant(env.c1.id, permissions=["read", "user_portal"])      # lost 'deposit'
    assert env.client.post(f"/v1/requests/{rid}/approve", headers=env.h1).status_code == 403
    assert env.store.get_request(rid)["status"] == "pending"                     # still pending
    assert env.backend.money_calls == 0


def test_unknown_outcome_then_safe_reapprove(env):
    rid = _file(env)
    env.backend.fail_money = True
    r = env.client.post(f"/v1/requests/{rid}/approve", headers=env.h1)
    assert r.status_code == 502
    assert env.store.get_request(rid)["status"] == "approving"                   # not failed, not approved
    env.backend.fail_money = False
    retry = env.client.post(f"/v1/requests/{rid}/approve", headers=env.h1)
    assert retry.status_code == 409                                              # blind retry blocked
    assert env.backend.users[1001]["Balance"] == 100.0
