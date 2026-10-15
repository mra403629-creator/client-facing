"""Gateway smoke test (stdlib only).

Usage (CMD, project root, gateway already running):
    set GATEWAY_ADMIN_KEY=<same value as in .env>
    python smoke_test.py "demo\\forex"

WARNING: this creates ONE real user on the MT5 server. Use a DEMO server/group only.
Passwords and API keys are never printed.
"""
import getpass
import json
import os
import secrets
import string
import sys
import time
import urllib.error
import urllib.request

BASE = os.getenv("GATEWAY_URL", "http://127.0.0.1:8000")
results = []


def call(method, path, body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw[:200].decode("utf-8", "replace")}
    except Exception as e:
        print(f"\nGateway se connect nahi hua ({BASE}): {e}")
        print("Pehle doosri CMD me: uvicorn gateway.main:app --port 8000")
        sys.exit(1)


def check(name, ok, info=""):
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  -> {info}" if info else ""))
    return ok


def make_password():
    # MT5 policy: 8-16 chars, lower + upper + digit + special
    pool = string.ascii_letters + string.digits
    core = "".join(secrets.choice(pool) for _ in range(8))
    return "Aa1#" + core


def main():
    if len(sys.argv) < 2:
        print('Use: python smoke_test.py "demo\\forex"   (aapke demo server ka ek existing group)')
        sys.exit(2)
    group = sys.argv[1].strip()
    if "\\" not in group:
        print("Group naam me backslash hota hai, jaise demo\\forex")
        sys.exit(2)
    mask = group.split("\\")[0] + "\\*"
    admin_key = os.getenv("GATEWAY_ADMIN_KEY") or getpass.getpass("GATEWAY_ADMIN_KEY: ")

    # 1. health
    st, js = call("GET", "/healthz")
    if not check("gateway up + MT5 manager connected", st == 200 and js.get("mt5_connected") is True, str(js)):
        print("   -> .env me MT5_SERVER / MT5_LOGIN / MT5_PASSWORD check karo, aur uvicorn ka log dekho.")
        sys.exit(1)

    # 2. tenant (admin)
    name = f"smoke{int(time.time())}"
    st, js = call("POST", "/admin/v1/tenants",
                  {"name": name, "masks": mask, "permissions": ["read", "create_user", "user_portal"],
                   "max_amount": 100},
                  {"X-Admin-Key": admin_key})
    if not check(f"tenant bana (mask {mask})", st == 201, f"{st} {js.get('detail', '')}"):
        print("   -> 401: admin key galat. 404: .env me GATEWAY_ADMIN_KEY set nahi.")
        print("   -> 422: is mask se koi purana tenant overlap kar raha hai (admin API se list dekho).")
        sys.exit(1)
    tkey = {"X-API-Key": js["api_key"]}

    # 3. groups (real Manager data, only own scope)
    st, js = call("GET", "/v1/groups", headers=tkey)
    names = [g.get("group") for g in js.get("groups", [])] if st == 200 else []
    check("GET /v1/groups (asli groups)", st == 200 and len(names) > 0, f"{st} total={js.get('total')}")
    if st != 200:
        print("   -> 502 aaye to GATEWAY_PUMP_MODE=USERS|GROUPS karo aur gateway restart karo.")
    check("sab groups tenant mask ke andar", all(n.lower().startswith(mask[:-1].lower()) for n in names))
    check("tumhara group list me hai", group.lower() in [n.lower() for n in names], group)

    st, js = call("GET", "/v1/groups/" + urllib.request.quote(group, safe=""), headers=tkey)
    check("GET /v1/groups/{group}", st == 200 and js.get("group", "").lower() == group.lower(), str(st))

    # 4. create ONE trader user
    pw = make_password()
    st, js = call("POST", "/v1/users",
                  {"group": group, "leverage": 100, "first_name": "Smoke", "last_name": "Test",
                   "password": pw}, tkey)
    if not check("user bana (POST /v1/users)", st == 201 and js.get("Login"), f"{st} {js.get('detail', '')}"):
        sys.exit(1)
    login = int(js["Login"])
    print(f"   naya demo login: {login}")

    # 5. trader login with ONLY login + password (no manager credentials)
    st, js = call("POST", "/u/v1/auth/login", {"login": login, "password": pw})
    ok = check("trader login (sirf apna login+password)", st == 200 and js.get("scope") == "trade",
               f"{st} scope={js.get('scope')}")
    if not ok:
        sys.exit(1)
    bearer = {"Authorization": "Bearer " + js["token"]}

    # 6. own data
    st, js = call("GET", "/u/v1/account", headers=bearer)
    check("GET /u/v1/account", st == 200 and js.get("login") == login, f"{st} balance={js.get('balance')}")
    st, js = call("GET", "/u/v1/group", headers=bearer)
    check("GET /u/v1/group (apna group)", st == 200 and js.get("group", "").lower() == group.lower(), str(st))
    st, js = call("GET", "/u/v1/me", headers=bearer)
    check("GET /u/v1/me", st == 200 and js.get("Login") == login, str(st))

    # 7. negative checks
    st, _ = call("POST", "/u/v1/auth/login", {"login": login, "password": "Wrong#Pass1"})
    check("galat password -> 401", st == 401, str(st))
    st, _ = call("GET", "/u/v1/account")
    check("bina token -> 401", st == 401, str(st))
    st, _ = call("GET", "/v1/groups")
    check("bina API key -> 401", st == 401, str(st))

    # 8. logout invalidates token
    call("POST", "/u/v1/auth/logout", headers=bearer)
    st, _ = call("GET", "/u/v1/account", headers=bearer)
    check("logout ke baad token band", st == 401, str(st))

    print(f"\n{sum(results)}/{len(results)} checks passed")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()