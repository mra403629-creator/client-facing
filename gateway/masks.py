"""MT5 group-mask matching.

SDK syntax (UserGetByGroup): comma separated list, '*' = any value,
'!' prefix = exception. e.g. "demo*,!demoforex". Group names are
case-insensitive and use backslash as path separator.
"""
from __future__ import annotations

import re
from functools import lru_cache
from typing import List, Tuple


def _tokens(mask: str) -> Tuple[List[str], List[str]]:
    inc, exc = [], []
    for raw in (mask or "").split(","):
        t = raw.strip()
        if not t:
            continue
        (exc if t.startswith("!") else inc).append(t[1:] if t.startswith("!") else t)
    return inc, exc


@lru_cache(maxsize=2048)
def _rx(token: str) -> "re.Pattern[str]":
    return re.compile("^" + ".*".join(re.escape(p) for p in token.split("*")) + "$", re.IGNORECASE)


def match_group(group: str, mask: str) -> bool:
    """True if `group` is selected by `mask`. Empty inputs never match."""
    if not group or not mask:
        return False
    inc, exc = _tokens(mask)
    if not inc:
        return False
    if not any(_rx(t).match(group) for t in inc):
        return False
    return not any(_rx(t).match(group) for t in exc)


def validate_mask(mask: str) -> str:
    """Normalise and validate a tenant mask. Raises ValueError."""
    if not mask or not mask.strip():
        raise ValueError("mask is empty")
    if len(mask) > 256:
        raise ValueError("mask too long")
    parts = [p.strip() for p in mask.split(",")]
    if any(not p or p == "!" for p in parts):
        raise ValueError("mask has an empty entry")
    inc, _ = _tokens(mask)
    if not inc:
        raise ValueError("mask needs at least one include entry")
    for t in inc:
        if re.fullmatch(r"\*+", t):
            raise ValueError("mask '*' would expose every group; use a prefix like 'client1\\*'")
    return ",".join(parts)


def globs_intersect(a: str, b: str) -> bool:
    """Can some string match both glob patterns (only '*' is special)?"""
    a, b = a.lower(), b.lower()

    @lru_cache(maxsize=None)
    def f(i: int, j: int) -> bool:
        if i == len(a) and j == len(b):
            return True
        if i < len(a) and a[i] == "*":
            return f(i + 1, j) or (j < len(b) and f(i, j + 1))
        if j < len(b) and b[j] == "*":
            return f(i, j + 1) or (i < len(a) and f(i + 1, j))
        if i < len(a) and j < len(b) and a[i] == b[j]:
            return f(i + 1, j + 1)
        return False

    return f(0, 0)


def masks_overlap(m1: str, m2: str) -> bool:
    """Conservative: only include entries are compared, so a clash that
    exclusions would have removed is still reported (safe direction)."""
    i1, _ = _tokens(m1)
    i2, _ = _tokens(m2)
    return any(globs_intersect(x, y) for x in i1 for y in i2)
