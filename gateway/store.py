"""SQLite store: tenants, API keys (hashed), audit log, idempotency keys."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from . import config
from .masks import masks_overlap, validate_mask

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  masks TEXT NOT NULL,
  permissions TEXT NOT NULL,
  rate_per_min INTEGER NOT NULL,
  max_amount REAL NOT NULL,
  ip_allow TEXT NOT NULL DEFAULT '[]',
  active INTEGER NOT NULL DEFAULT 1,
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id INTEGER NOT NULL REFERENCES tenants(id),
  key_hash TEXT NOT NULL UNIQUE,
  prefix TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  tenant_id INTEGER,
  action TEXT NOT NULL,
  login INTEGER,
  amount REAL,
  status TEXT NOT NULL,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS audit_tenant ON audit(tenant_id, id);
CREATE TABLE IF NOT EXISTS idempotency(
  tenant_id INTEGER NOT NULL,
  key TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  response TEXT,
  created_at REAL NOT NULL,
  PRIMARY KEY(tenant_id, key)
);
"""


@dataclass(frozen=True)
class Tenant:
    id: int
    name: str
    masks: str
    permissions: frozenset
    rate_per_min: int
    max_amount: float
    ip_allow: Tuple[str, ...] = field(default_factory=tuple)
    active: bool = True

    def public(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "masks": self.masks,
            "permissions": sorted(self.permissions),
            "rate_per_min": self.rate_per_min,
            "max_amount": self.max_amount,
            "ip_allow": list(self.ip_allow),
            "active": self.active,
        }


def hash_key(key: str) -> str:
    # API keys are 256-bit random, so a plain SHA-256 is sufficient (no stretching needed).
    return hashlib.sha256(key.encode()).hexdigest()


def _row_to_tenant(r) -> Tenant:
    return Tenant(
        id=r["id"], name=r["name"], masks=r["masks"],
        permissions=frozenset(json.loads(r["permissions"])),
        rate_per_min=r["rate_per_min"], max_amount=r["max_amount"],
        ip_allow=tuple(json.loads(r["ip_allow"])), active=bool(r["active"]),
    )


_SCHEMA_PORTAL = """
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY,
  login INTEGER NOT NULL,
  tenant_id INTEGER NOT NULL,
  scope TEXT NOT NULL,
  expires_at REAL NOT NULL,
  created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_login ON sessions(login);
CREATE TABLE IF NOT EXISTS login_fails(ts REAL NOT NULL, login INTEGER, ip TEXT);
CREATE INDEX IF NOT EXISTS lf_login ON login_fails(login, ts);
CREATE INDEX IF NOT EXISTS lf_ip ON login_fails(ip, ts);
CREATE TABLE IF NOT EXISTS requests(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id INTEGER NOT NULL,
  login INTEGER NOT NULL,
  kind TEXT NOT NULL,
  amount REAL NOT NULL,
  comment TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL,
  note TEXT,
  deal_id INTEGER,
  created_at REAL NOT NULL,
  decided_at REAL
);
CREATE INDEX IF NOT EXISTS req_tenant ON requests(tenant_id, status, id);
CREATE INDEX IF NOT EXISTS req_login ON requests(login, id);
"""


@dataclass(frozen=True)
class Session:
    login: int
    tenant_id: int
    scope: str  # 'trade' (main password) | 'read' (investor password)
    token_hash: str


class Store:
    def __init__(self, path: str = None):
        self.path = path or config.DB_PATH
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.executescript(_SCHEMA)
            self._db.executescript(_SCHEMA_PORTAL)
            self._db.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
            self._db.execute("DELETE FROM login_fails WHERE ts < ?", (time.time() - 86400,))
            self._db.execute("DELETE FROM idempotency WHERE created_at < ?", (time.time() - 7 * 86400,))

    # ---------------- tenants ----------------
    @staticmethod
    def _clean(permissions, rate, max_amount, ip_allow):
        perms = set(permissions)
        bad = perms - config.ALL_PERMISSIONS
        if bad:
            raise ValueError(f"unknown permissions: {sorted(bad)}")
        if int(rate) < 1:
            raise ValueError("rate_per_min must be >= 1")
        if not (0 < float(max_amount) <= 1_000_000_000):
            raise ValueError("max_amount must be in (0, 1e9]")
        nets = []
        for n in ip_allow or []:
            nets.append(str(ipaddress.ip_network(n, strict=False)))
        return sorted(perms), int(rate), float(max_amount), nets

    def _check_overlap(self, masks: str, exclude_id: Optional[int] = None):
        for r in self._db.execute("SELECT id, name, masks FROM tenants"):
            if exclude_id is not None and r["id"] == exclude_id:
                continue
            if masks_overlap(masks, r["masks"]):
                raise ValueError(f"mask overlaps with tenant '{r['name']}'")

    def create_tenant(self, name, masks, permissions=("read",), rate_per_min=None,
                      max_amount=None, ip_allow=()) -> Tenant:
        name = (name or "").strip()
        if not (1 <= len(name) <= 64):
            raise ValueError("name must be 1-64 chars")
        masks = validate_mask(masks)
        perms, rate, cap, nets = self._clean(
            permissions,
            rate_per_min if rate_per_min is not None else config.DEFAULT_RATE_PER_MIN,
            max_amount if max_amount is not None else config.DEFAULT_MAX_AMOUNT,
            ip_allow,
        )
        with self._lock:
            self._check_overlap(masks)
            try:
                cur = self._db.execute(
                    "INSERT INTO tenants(name,masks,permissions,rate_per_min,max_amount,ip_allow,created_at)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (name, masks, json.dumps(perms), rate, cap, json.dumps(nets), time.time()),
                )
            except sqlite3.IntegrityError:
                raise ValueError(f"tenant '{name}' already exists")
            return self.get_tenant(cur.lastrowid)

    def update_tenant(self, tenant_id: int, **changes) -> Tenant:
        with self._lock:
            cur = self.get_tenant(tenant_id)
            if cur is None:
                raise KeyError("tenant not found")
            masks = validate_mask(changes["masks"]) if changes.get("masks") is not None else cur.masks
            perms, rate, cap, nets = self._clean(
                changes.get("permissions") if changes.get("permissions") is not None else cur.permissions,
                changes.get("rate_per_min") if changes.get("rate_per_min") is not None else cur.rate_per_min,
                changes.get("max_amount") if changes.get("max_amount") is not None else cur.max_amount,
                changes.get("ip_allow") if changes.get("ip_allow") is not None else cur.ip_allow,
            )
            active = cur.active if changes.get("active") is None else bool(changes["active"])
            self._check_overlap(masks, exclude_id=tenant_id)
            self._db.execute(
                "UPDATE tenants SET masks=?,permissions=?,rate_per_min=?,max_amount=?,ip_allow=?,active=? WHERE id=?",
                (masks, json.dumps(perms), rate, cap, json.dumps(nets), int(active), tenant_id),
            )
            return self.get_tenant(tenant_id)

    def get_tenant(self, tenant_id: int) -> Optional[Tenant]:
        with self._lock:
            r = self._db.execute("SELECT * FROM tenants WHERE id=?", (tenant_id,)).fetchone()
        return _row_to_tenant(r) if r else None

    def list_tenants(self) -> List[Tenant]:
        with self._lock:
            rows = self._db.execute("SELECT * FROM tenants ORDER BY id").fetchall()
        return [_row_to_tenant(r) for r in rows]

    # ---------------- API keys ----------------
    def issue_key(self, tenant_id: int) -> str:
        if self.get_tenant(tenant_id) is None:
            raise KeyError("tenant not found")
        key = "mt5gw_" + secrets.token_urlsafe(32)
        with self._lock:
            self._db.execute(
                "INSERT INTO api_keys(tenant_id,key_hash,prefix,created_at) VALUES(?,?,?,?)",
                (tenant_id, hash_key(key), key[:12], time.time()),
            )
        return key  # shown once; only the hash is stored

    def revoke_key(self, tenant_id: int, prefix: str) -> int:
        with self._lock:
            cur = self._db.execute(
                "UPDATE api_keys SET revoked=1 WHERE tenant_id=? AND prefix=?", (tenant_id, prefix)
            )
            return cur.rowcount

    def list_keys(self, tenant_id: int) -> List[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT prefix, revoked, created_at FROM api_keys WHERE tenant_id=? ORDER BY id", (tenant_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def tenant_for_key(self, key: str) -> Optional[Tenant]:
        if not key:
            return None
        with self._lock:
            r = self._db.execute(
                "SELECT t.* FROM api_keys k JOIN tenants t ON t.id=k.tenant_id"
                " WHERE k.key_hash=? AND k.revoked=0 AND t.active=1",
                (hash_key(key),),
            ).fetchone()
        return _row_to_tenant(r) if r else None

    # ---------------- audit ----------------
    def audit(self, tenant_id, action, login=None, amount=None, status="ok", detail=None):
        with self._lock:
            self._db.execute(
                "INSERT INTO audit(ts,tenant_id,action,login,amount,status,detail) VALUES(?,?,?,?,?,?,?)",
                (time.time(), tenant_id, action, login, amount, status, (detail or "")[:500]),
            )

    def list_audit(self, tenant_id: Optional[int] = None, limit: int = 100) -> List[dict]:
        q, args = "SELECT * FROM audit", []
        if tenant_id is not None:
            q += " WHERE tenant_id=?"
            args.append(tenant_id)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        with self._lock:
            return [dict(r) for r in self._db.execute(q, args).fetchall()]

    # ---------------- idempotency ----------------
    def idem_begin(self, tenant_id: int, key: str, req_hash: str):
        """-> ('new', None) | ('replay', response_json) | ('conflict', None) | ('inflight', None)"""
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO idempotency(tenant_id,key,request_hash,created_at) VALUES(?,?,?,?)",
                    (tenant_id, key, req_hash, time.time()),
                )
                return "new", None
            except sqlite3.IntegrityError:
                r = self._db.execute(
                    "SELECT request_hash, response FROM idempotency WHERE tenant_id=? AND key=?",
                    (tenant_id, key),
                ).fetchone()
        if r["request_hash"] != req_hash:
            return "conflict", None
        if r["response"] is None:
            return "inflight", None
        return "replay", r["response"]

    def idem_finish(self, tenant_id: int, key: str, response: dict):
        with self._lock:
            self._db.execute(
                "UPDATE idempotency SET response=? WHERE tenant_id=? AND key=?",
                (json.dumps(response), tenant_id, key),
            )

    def idem_abort(self, tenant_id: int, key: str):
        with self._lock:
            self._db.execute(
                "DELETE FROM idempotency WHERE tenant_id=? AND key=? AND response IS NULL", (tenant_id, key)
            )

    # ---------------- user sessions ----------------
    MAX_SESSIONS_PER_LOGIN = 5

    def create_session(self, login: int, tenant_id: int, scope: str, ttl: int) -> str:
        token = "mt5u_" + secrets.token_urlsafe(32)
        now = time.time()
        with self._lock:
            self._db.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            self._db.execute(
                "INSERT INTO sessions(token_hash,login,tenant_id,scope,expires_at,created_at) VALUES(?,?,?,?,?,?)",
                (hash_key(token), login, tenant_id, scope, now + ttl, now),
            )
            self._db.execute(
                "DELETE FROM sessions WHERE login=? AND token_hash NOT IN ("
                " SELECT token_hash FROM sessions WHERE login=? ORDER BY created_at DESC LIMIT ?)",
                (login, login, self.MAX_SESSIONS_PER_LOGIN),
            )
        return token  # only the hash is stored

    def session_for_token(self, token: str) -> Optional[Session]:
        if not token:
            return None
        h = hash_key(token)
        with self._lock:
            r = self._db.execute("SELECT * FROM sessions WHERE token_hash=?", (h,)).fetchone()
            if r and r["expires_at"] < time.time():
                self._db.execute("DELETE FROM sessions WHERE token_hash=?", (h,))
                r = None
        return Session(r["login"], r["tenant_id"], r["scope"], h) if r else None

    def delete_session(self, token_hash: str):
        with self._lock:
            self._db.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))

    def delete_login_sessions(self, login: int):
        with self._lock:
            self._db.execute("DELETE FROM sessions WHERE login=?", (login,))

    # ---------------- login failure tracking (persistent, survives restarts) ----------------
    def record_fail(self, login: Optional[int], ip: Optional[str]):
        with self._lock:
            self._db.execute("INSERT INTO login_fails(ts,login,ip) VALUES(?,?,?)", (time.time(), login, ip))

    def count_fails(self, login: Optional[int] = None, ip: Optional[str] = None, window: int = 300) -> int:
        since = time.time() - window
        with self._lock:
            if login is not None:
                return self._db.execute("SELECT COUNT(*) c FROM login_fails WHERE login=? AND ts>=?",
                                        (login, since)).fetchone()["c"]
            return self._db.execute("SELECT COUNT(*) c FROM login_fails WHERE ip=? AND ts>=?",
                                    (ip, since)).fetchone()["c"]

    def clear_fails(self, login: int):
        with self._lock:
            self._db.execute("DELETE FROM login_fails WHERE login=?", (login,))

    # ---------------- money requests ----------------
    def create_request(self, tenant_id: int, login: int, kind: str, amount: float, comment: str) -> dict:
        with self._lock:
            cur = self._db.execute(
                "INSERT INTO requests(tenant_id,login,kind,amount,comment,status,created_at) VALUES(?,?,?,?,?,'pending',?)",
                (tenant_id, login, kind, amount, comment, time.time()),
            )
            return self.get_request(cur.lastrowid)

    def get_request(self, req_id: int) -> Optional[dict]:
        with self._lock:
            r = self._db.execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone()
        return dict(r) if r else None

    def list_requests(self, tenant_id: Optional[int] = None, login: Optional[int] = None,
                      status: Optional[str] = None, limit: int = 100) -> List[dict]:
        q, args, cond = "SELECT * FROM requests", [], []
        if tenant_id is not None:
            cond.append("tenant_id=?"); args.append(tenant_id)
        if login is not None:
            cond.append("login=?"); args.append(login)
        if status is not None:
            cond.append("status=?"); args.append(status)
        if cond:
            q += " WHERE " + " AND ".join(cond)
        q += " ORDER BY id DESC LIMIT ?"
        args.append(int(limit))
        with self._lock:
            return [dict(r) for r in self._db.execute(q, args).fetchall()]

    def count_pending(self, login: int) -> int:
        with self._lock:
            return self._db.execute(
                "SELECT COUNT(*) c FROM requests WHERE login=? AND status IN ('pending','approving')", (login,)
            ).fetchone()["c"]

    def transition_request(self, req_id: int, tenant_id: Optional[int], frm: str, to: str,
                           note: Optional[str] = None, deal_id: Optional[int] = None,
                           login: Optional[int] = None) -> bool:
        """Atomic compare-and-set on status. Returns True if this call made the change."""
        q = "UPDATE requests SET status=?, note=COALESCE(?,note), deal_id=COALESCE(?,deal_id), decided_at=? WHERE id=? AND status=?"
        args = [to, note, deal_id, time.time(), req_id, frm]
        if tenant_id is not None:
            q += " AND tenant_id=?"; args.append(tenant_id)
        if login is not None:
            q += " AND login=?"; args.append(login)
        with self._lock:
            return self._db.execute(q, args).rowcount == 1
