from __future__ import annotations

import os

try:  # optional; the repo already uses python-dotenv
    from dotenv import load_dotenv

    load_dotenv()
except Exception:  # pragma: no cover
    pass

DB_PATH = os.getenv("GATEWAY_DB", "gateway.db")

# Separate secret for the admin API. If unset the admin API is DISABLED (fail closed).
ADMIN_KEY = os.getenv("GATEWAY_ADMIN_KEY") or None

DEFAULT_RATE_PER_MIN = int(os.getenv("GATEWAY_DEFAULT_RATE_PER_MIN", "120"))
DEFAULT_MAX_AMOUNT = float(os.getenv("GATEWAY_DEFAULT_MAX_AMOUNT", "10000"))

# Ownership checks use UserGetByLogins/UserGet, which per the SDK docs only work
# with PUMP_MODE_USERS. Do not drop USERS from this.
# The groups endpoints (GroupTotal/GroupNext/GroupGet) additionally need GROUPS.
PUMP_MODE = os.getenv("GATEWAY_PUMP_MODE", "USERS|GROUPS")

ALL_PERMISSIONS = frozenset({"read", "deposit", "withdraw", "create_user", "user_portal"})
