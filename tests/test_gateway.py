import threading

import pytest
from fastapi.testclient import TestClient

import gateway.config as config
from gateway.main import create_app
from gateway.masks import globs_intersect, masks_overlap, match_group, validate_mask
from gateway.store import Store


# --------------------------------------------------------------------- fake MT5
class FakeBackend:
    def __init__(self):
        self.lock = threading.RLock()
        self.users = {
            1001: {"Login": 1001, "Group": "client1\\retail", "Name": "A1", "Balance": 100.0, "Comment": "internal note"},
            1002: {"Login": 1002, "Group": "client1\\vip", "Name": "A2", "Balance": 500.0},
            2001: {"Login": 2001, "Group": "client2\\retail", "Name": "B1", "Balance": 900.0},
            3001: {"Login": 3001, "Group": "other\\x", "Name": "C1", "Balance": 5.0},
        }
        self.fail_groups = False
        self.fail_money = False
        self.money_calls = 0
        self.created = []
        self._connected = True
        # login -> (main password, investor password)
        self.passwords = {1001: ("Main#1234", "Inve#1234"), 1002: ("Main#5678", "Inve#5678"),
                          2001: ("Main#2001", "Inve#2001"), 3001: ("Main#3001", "Inve#3001")}
        self.password_calls = 0
        self.fail_group_list = False
        self.groups = [
            {"group": "client1\\retail", "server": "Demo", "company": "C1", "currency": "USD",
             "margin_call": 100.0, "margin_stopout": 50.0},
            {"group": "client1\\vip", "server": "Demo", "company": "C1", "currency": "USD",
             "margin_call": 80.0, "margin_stopout": 30.0, "rights": 999},  # extra field must not leak
            {"group": "client2\\retail", "server": "Demo", "company": "C2", "currency": "EUR",
             "margin_call": 90.0, "margin_stopout": 40.0},
            {"group": "other\\x", "server": "Demo", "company": "O", "currency": "USD",
             "margin_call": 70.0, "margin_stopout": 20.0},
        ]

    def start(self): pass
    def stop(self): pass
    def connected(self): return self._connected

    def user_groups(self, logins):
        if self.fail_groups:
            raise RuntimeError("cache down")
        return {lg: self.users[lg]["Group"] for lg in logins if lg in self.users}

    def get_user(self, login):
        if login not in self.users:
            raise KeyError("nf")
        return dict(self.users[login])

    def list_users(self, mask, limit, offset):
        sel = [u for u in self.users.values() if match_group(u["Group"], mask)]
        return {"total": len(sel), "count": len(sel[offset:offset + limit]), "offset": offset,
                "users": [dict(u) for u in sel[offset:offset + limit]]}

    def balance(self, login):
        return {"login": login, "balance": self.users[login]["Balance"]}

    def accounts(self, logins):
        return {"accounts": [{"Login": lg, "Balance": self.users[lg]["Balance"]} for lg in logins if lg in self.users]}

    def _move(self, login, amount, sign):
        self.money_calls += 1
        if self.fail_money:
            raise RuntimeError("socket died")
        if sign < 0 and amount > self.users[login]["Balance"]:
            raise ValueError("Not enough money")
        self.users[login]["Balance"] += sign * amount
        return {"deal_id": 7000 + self.money_calls, "account_after": self.balance(login)}

    def deposit(self, login, amount, comment): return self._move(login, amount, 1)
    def withdraw(self, login, amount, comment): return self._move(login, amount, -1)

    def check_password(self, login, password, kind):
        self.password_calls += 1
        if self.fail_groups:
            raise RuntimeError("down")
        pair = self.passwords.get(login)
        return bool(pair) and password == pair[0 if kind == "main" else 1]

    def list_groups(self):
        if self.fail_group_list:
            raise RuntimeError("Groups need PUMP_MODE_GROUPS (secret-server-detail)")
        return [dict(g) for g in self.groups]

    def get_group(self, name):
        if self.fail_group_list:
            raise RuntimeError("Groups need PUMP_MODE_GROUPS (secret-server-detail)")
        for g in self.groups:
            if g["group"].lower() == name.lower():
                return dict(g)
        raise KeyError(name)

    def create_user(self, data):
        self.created.append(data)
        login = 9000 + len(self.created)
        u = {"Login": login, "Group": data["group"], "Name": data.get("name") or data.get("first_name", "")}
        self.users[login] = {**u, "Balance": 0.0}
        return u


# --------------------------------------------------------------------- fixtures
@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ADMIN_KEY", "adminsecret")
    backend = FakeBackend()
    store = Store(str(tmp_path / "gw.db"))
    app = create_app(backend, store)
    c1 = store.create_tenant("client1", "client1\\*", ["read", "deposit", "withdraw", "create_user"], max_amount=1000)
    c2 = store.create_tenant("client2", "client2\\*", ["read"])
    k1, k2 = store.issue_key(c1.id), store.issue_key(c2.id)
    with TestClient(app) as client:
        yield type("E", (), dict(client=client, backend=backend, store=store, c1=c1, c2=c2,
                                 h1={"X-API-Key": k1}, h2={"X-API-Key": k2}, k1=k1, app=app))


def idem(i="idem-0001"):
    return {"Idempotency-Key": i}


# --------------------------------------------------------------------- masks
def test_match_group_semantics():
    assert match_group("client1\\retail", "client1\\*")
    assert match_group("CLIENT1\\Retail", "client1\\*")           # case-insensitive
    assert not match_group("client10\\x", "client1\\*")           # backslash is part of the prefix
    assert match_group("demoforex", "demo*")
    assert not match_group("demoforex", "demo*,!demoforex")       # exception wins
    assert match_group("demo2", "demo*,!demoforex")
    assert not match_group("", "*") and not match_group("a", "")


def test_mask_validation_and_overlap():
    with pytest.raises(ValueError): validate_mask("*")
    with pytest.raises(ValueError): validate_mask("")
    with pytest.raises(ValueError): validate_mask("!only\\exclude")
    with pytest.raises(ValueError): validate_mask("a\\*,,b\\*")
    assert globs_intersect("client1\\*", "c*")
    assert globs_intersect("a*b", "*c*b") is True
    assert not globs_intersect("client1\\*", "client2\\*")
    assert masks_overlap("client1\\*,x\\*", "y\\*,x\\vip")
    assert not masks_overlap("client1\\*", "client2\\*")


def test_tenant_overlap_rejected(env):
    with pytest.raises(ValueError, match="overlaps"):
        env.store.create_tenant("evil", "c*")
    with pytest.raises(ValueError, match="overlaps"):
        env.store.update_tenant(env.c2.id, masks="client1\\vip")


# --------------------------------------------------------------------- isolation
def test_own_user_ok_foreign_and_unknown_look_identical(env):
    r = env.client.get("/v1/users/1001", headers=env.h1)
    assert r.status_code == 200 and r.json()["Login"] == 1001
    assert "Comment" not in r.json()                                  # field whitelist
    foreign = env.client.get("/v1/users/2001", headers=env.h1)
    unknown = env.client.get("/v1/users/424242", headers=env.h1)
    assert foreign.status_code == unknown.status_code == 404
    assert foreign.json() == unknown.json()


def test_list_is_scoped_and_group_filter_cannot_escape(env):
    r = env.client.get("/v1/users", headers=env.h1).json()
    assert sorted(u["Login"] for u in r["users"]) == [1001, 1002]
    assert env.client.get("/v1/users?group=client1\\vip", headers=env.h1).json()["count"] == 1
    for g in ("client2\\retail", "*", "client1\\*,client2\\*", "!x"):
        assert env.client.get("/v1/users", params={"group": g}, headers=env.h1).status_code == 404


def test_accounts_never_returns_foreign(env):
    r = env.client.post("/v1/accounts", json={"logins": [1001, 2001, 3001, 555]}, headers=env.h1).json()
    assert [a["Login"] for a in r["accounts"]] == [1001]
    assert r["not_found"] == [2001, 3001, 555]
    assert env.client.post("/v1/accounts", json={"logins": []}, headers=env.h1).status_code == 422
    assert env.client.post("/v1/accounts", json={"logins": list(range(501))}, headers=env.h1).status_code == 422


def test_ownership_follows_live_group(env):
    env.backend.users[1001]["Group"] = "client2\\retail"             # moved to the other client
    assert env.client.get("/v1/users/1001/balance", headers=env.h1).status_code == 404
    assert env.client.get("/v1/users/1001/balance", headers=env.h2).status_code == 200


def test_fail_closed_when_lookup_breaks(env):
    env.backend.fail_groups = True
    r = env.client.post("/v1/users/1001/deposit", json={"amount": 5}, headers={**env.h1, **idem()})
    assert r.status_code == 502 and "cache down" not in r.text       # no upstream detail leaked
    assert env.backend.money_calls == 0 and env.backend.users[1001]["Balance"] == 100.0


# --------------------------------------------------------------------- auth
def test_auth_failures(env):
    assert env.client.get("/v1/users").status_code == 401
    assert env.client.get("/v1/users", headers={"X-API-Key": "nope"}).status_code == 401
    env.store.update_tenant(env.c1.id, active=False)
    assert env.client.get("/v1/users", headers=env.h1).status_code == 401
    env.store.update_tenant(env.c1.id, active=True)
    prefix = env.k1[:12]
    assert env.store.revoke_key(env.c1.id, prefix) == 1
    assert env.client.get("/v1/users", headers=env.h1).status_code == 401


def test_admin_api_disabled_without_key_and_protected(env, monkeypatch):
    assert env.client.get("/admin/v1/tenants").status_code == 401
    assert env.client.get("/admin/v1/tenants", headers={"X-Admin-Key": "adminsecret"}).status_code == 200
    assert env.client.get("/admin/v1/tenants", headers=env.h1).status_code == 401    # client key is not admin
    monkeypatch.setattr(config, "ADMIN_KEY", None)
    assert env.client.get("/admin/v1/tenants", headers={"X-Admin-Key": "adminsecret"}).status_code == 404


def test_admin_create_tenant_returns_key_once_and_it_works(env):
    h = {"X-Admin-Key": "adminsecret"}
    r = env.client.post("/admin/v1/tenants", headers=h, json={"name": "c3", "masks": "client3\\*"})
    assert r.status_code == 201
    key = r.json()["api_key"]
    assert env.client.get("/v1/me", headers={"X-API-Key": key}).json()["name"] == "c3"
    listing = env.client.get(f"/admin/v1/tenants/{r.json()['tenant']['id']}/keys", headers=h).json()
    assert key not in str(listing)                                            # only prefix stored/shown
    dup = env.client.post("/admin/v1/tenants", headers=h, json={"name": "c4", "masks": "client3\\x"})
    assert dup.status_code == 422


def test_ip_allowlist(env):
    env.store.update_tenant(env.c1.id, ip_allow=["10.0.0.0/8"])
    assert env.client.get("/v1/users", headers=env.h1).status_code == 403    # TestClient host is 'testclient'
    env.store.update_tenant(env.c1.id, ip_allow=[])
    assert env.client.get("/v1/users", headers=env.h1).status_code == 200


def test_rate_limit(env):
    env.store.update_tenant(env.c1.id, rate_per_min=3)
    codes = [env.client.get("/v1/me", headers=env.h1).status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    assert "retry-after" in env.client.get("/v1/me", headers=env.h1).headers


# --------------------------------------------------------------------- permissions
def test_permission_enforced(env):
    r = env.client.post("/v1/users/2001/deposit", json={"amount": 1}, headers={**env.h2, **idem()})
    assert r.status_code == 403
    assert env.client.post("/v1/users", json={"group": "client2\\retail", "password": "Aa1!aaaa", "name": "x"},
                           headers=env.h2).status_code == 403
    assert env.client.get("/v1/users", headers=env.h2).status_code == 200


# --------------------------------------------------------------------- money
def test_deposit_withdraw_and_idempotent_replay(env):
    r = env.client.post("/v1/users/1001/deposit", json={"amount": 50, "comment": "x" * 100},
                        headers={**env.h1, **idem("key-aaaa-1")})
    assert r.status_code == 200 and env.backend.users[1001]["Balance"] == 150.0
    again = env.client.post("/v1/users/1001/deposit", json={"amount": 50, "comment": "x" * 100},
                            headers={**env.h1, **idem("key-aaaa-1")})
    assert again.status_code == 200 and again.headers["idempotent-replay"] == "true"
    assert again.json() == r.json()
    assert env.backend.users[1001]["Balance"] == 150.0 and env.backend.money_calls == 1
    diff = env.client.post("/v1/users/1001/deposit", json={"amount": 51},
                           headers={**env.h1, **idem("key-aaaa-1")})
    assert diff.status_code == 409
    w = env.client.post("/v1/users/1001/withdraw", json={"amount": 150}, headers={**env.h1, **idem("key-aaaa-2")})
    assert w.status_code == 200 and env.backend.users[1001]["Balance"] == 0.0


def test_money_requires_idempotency_key_and_sane_amount(env):
    url = "/v1/users/1001/deposit"
    assert env.client.post(url, json={"amount": 5}, headers=env.h1).status_code == 422
    assert env.client.post(url, json={"amount": 5}, headers={**env.h1, "Idempotency-Key": "short"}).status_code == 422
    for bad in (0, -5):
        assert env.client.post(url, json={"amount": bad}, headers={**env.h1, **idem(f"bad-key-{bad}")}).status_code == 422
    over = env.client.post(url, json={"amount": 1000.01}, headers={**env.h1, **idem("over-key-1")})
    assert over.status_code == 422 and "limit" in over.json()["detail"]
    assert env.backend.money_calls == 0


def test_cannot_move_foreign_money(env):
    r = env.client.post("/v1/users/2001/deposit", json={"amount": 5}, headers={**env.h1, **idem("foreign-01")})
    assert r.status_code == 404 and env.backend.money_calls == 0
    assert env.backend.users[2001]["Balance"] == 900.0


def test_business_error_allows_retry_but_unknown_outcome_blocks_blind_retry(env):
    k = idem("nomoney-01")
    r = env.client.post("/v1/users/1001/withdraw", json={"amount": 999}, headers={**env.h1, **k})
    assert r.status_code == 422                                     # definite failure
    env.backend.users[1001]["Balance"] = 1000.0
    ok = env.client.post("/v1/users/1001/withdraw", json={"amount": 999}, headers={**env.h1, **k})
    assert ok.status_code == 200                                    # same key may be retried

    env.backend.fail_money = True
    k2 = idem("unknown-01")
    r = env.client.post("/v1/users/1001/deposit", json={"amount": 5}, headers={**env.h1, **k2})
    assert r.status_code == 502
    env.backend.fail_money = False
    retry = env.client.post("/v1/users/1001/deposit", json={"amount": 5}, headers={**env.h1, **k2})
    assert retry.status_code == 409                                 # outcome unknown -> no double pay
    assert "unknown_outcome" in [a["status"] for a in env.store.list_audit(env.c1.id)]


def test_concurrent_same_key_pays_once(env):
    results = []

    def go():
        results.append(env.client.post("/v1/users/1001/deposit", json={"amount": 10},
                                       headers={**env.h1, **idem("race-key-1")}).status_code)

    ts = [threading.Thread(target=go) for _ in range(8)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert env.backend.money_calls == 1 and env.backend.users[1001]["Balance"] == 110.0
    assert results.count(200) >= 1 and all(c in (200, 409) for c in results)


def test_audit_trail(env):
    env.client.post("/v1/users/1001/deposit", json={"amount": 5}, headers={**env.h1, **idem("audit-001")})
    env.client.post("/v1/users/2001/deposit", json={"amount": 5}, headers={**env.h1, **idem("audit-002")})
    rows = env.client.get(f"/admin/v1/audit?tenant_id={env.c1.id}", headers={"X-Admin-Key": "adminsecret"}).json()
    statuses = {r["status"] for r in rows}
    assert {"ok", "not_owned"} <= statuses


# --------------------------------------------------------------------- create user
def test_create_user_forced_into_tenant_scope(env):
    body = {"password": "Aa1!aaaa", "name": "New", "leverage": 100}
    for g in ("client2\\retail", "client1\\*", "client1\\a,client2\\b", "!x", ""):
        r = env.client.post("/v1/users", json={**body, "group": g}, headers=env.h1)
        assert r.status_code == 403, g
    assert env.backend.created == []


def test_create_user_ok_strips_rights_and_validates_password(env):
    r = env.client.post("/v1/users", headers=env.h1,
                        json={"group": "client1\\retail", "password": "Aa1!aaaa", "name": "New",
                              "rights": 999, "comment": "hax", "foo": 1})
    assert r.status_code == 201 and "password" not in r.text
    sent = env.backend.created[0]
    assert "rights" not in sent and "comment" not in sent and "foo" not in sent
    for pw in ("Sh1!", "alllowercase1!", "NOLOWER123!", "NoDigits!!!", "NoSpecial123A", "A1!a" * 5):
        r = env.client.post("/v1/users", headers=env.h1,
                            json={"group": "client1\\retail", "password": pw, "name": "x"})
        assert r.status_code == 422, pw


def test_healthz_is_public_and_leaks_nothing(env):
    r = env.client.get("/healthz")
    assert r.status_code == 200 and set(r.json()) == {"ok", "mt5_connected"}
