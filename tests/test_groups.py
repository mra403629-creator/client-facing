"""Groups endpoints: real backend data, tenant scoping, trader's own group, no leaks."""
import pytest
from fastapi.testclient import TestClient

import gateway.config as config
from gateway.main import create_app
from gateway.store import Store
from tests.test_gateway import FakeBackend


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ADMIN_KEY", "adminsecret")
    backend = FakeBackend()
    store = Store(str(tmp_path / "gw.db"))
    app = create_app(backend, store)
    c1 = store.create_tenant("client1", "client1\\*", ["read", "user_portal"])
    c2 = store.create_tenant("client2", "client2\\*", ["read"])
    c3 = store.create_tenant("noread", "other\\*", ["deposit"])  # no 'read'
    keys = {t.name: {"X-API-Key": store.issue_key(t.id)} for t in (c1, c2, c3)}
    with TestClient(app) as client:
        yield type("E", (), dict(client=client, backend=backend, store=store, keys=keys))


def test_list_groups_returns_only_own_groups_from_backend(env):
    r = env.client.get("/v1/groups", headers=env.keys["client1"])
    assert r.status_code == 200
    names = sorted(g["group"] for g in r.json()["groups"])
    assert names == ["client1\\retail", "client1\\vip"]
    assert r.json()["total"] == 2


def test_list_groups_reflects_real_backend_data(env):
    env.backend.groups.append({"group": "client1\\new", "currency": "GBP"})
    r = env.client.get("/v1/groups", headers=env.keys["client1"])
    assert "client1\\new" in [g["group"] for g in r.json()["groups"]]


def test_group_fields_are_whitelisted(env):
    r = env.client.get("/v1/groups", headers=env.keys["client1"])
    for g in r.json()["groups"]:
        assert "rights" not in g
    r = env.client.get("/v1/groups/client1%5Cvip", headers=env.keys["client1"])
    assert r.status_code == 200 and "rights" not in r.json()


def test_get_group_detail(env):
    r = env.client.get("/v1/groups/client1%5Cretail", headers=env.keys["client1"])
    assert r.status_code == 200
    assert r.json()["group"] == "client1\\retail" and r.json()["currency"] == "USD"


def test_foreign_and_unknown_group_are_same_404(env):
    foreign = env.client.get("/v1/groups/client2%5Cretail", headers=env.keys["client1"])
    unknown = env.client.get("/v1/groups/client1%5Cnope", headers=env.keys["client1"])
    assert foreign.status_code == unknown.status_code == 404
    assert foreign.json() == unknown.json()


@pytest.mark.parametrize("name", ["*", "client1%5C*", "client1%5Cretail,client2%5Cretail", "!x"])
def test_group_wildcards_rejected(env, name):
    assert env.client.get(f"/v1/groups/{name}", headers=env.keys["client1"]).status_code == 404


def test_groups_need_read_permission_and_key(env):
    assert env.client.get("/v1/groups", headers=env.keys["noread"]).status_code == 403
    assert env.client.get("/v1/groups/other%5Cx", headers=env.keys["noread"]).status_code == 403
    assert env.client.get("/v1/groups").status_code == 401
    assert env.client.get("/v1/groups", headers={"X-API-Key": "bad"}).status_code == 401


def test_upstream_error_is_generic(env):
    env.backend.fail_group_list = True
    for url in ("/v1/groups", "/v1/groups/client1%5Cretail"):
        r = env.client.get(url, headers=env.keys["client1"])
        assert r.status_code == 502
        assert "PUMP_MODE" not in r.text and "secret-server-detail" not in r.text


def test_trader_sees_only_own_group(env):
    tok = env.client.post("/u/v1/auth/login", json={"login": 1001, "password": "Main#1234"}).json()["token"]
    r = env.client.get("/u/v1/group", headers={"Authorization": "Bearer " + tok})
    assert r.status_code == 200 and r.json()["group"] == "client1\\retail"
    assert "rights" not in r.json()
    assert env.client.get("/u/v1/group").status_code == 401


def test_trader_group_has_no_credentials(env):
    tok = env.client.post("/u/v1/auth/login", json={"login": 1001, "password": "Main#1234"}).json()["token"]
    r = env.client.get("/u/v1/group", headers={"Authorization": "Bearer " + tok})
    assert "Main#1234" not in r.text and "password" not in r.text.lower()
