from __future__ import annotations

import threading
import time
from collections import defaultdict, deque


class RateLimiter:
    """Sliding 60s window per tenant. In-memory => single process only
    (use Redis if you run several workers)."""

    def __init__(self):
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, tenant_id: int, limit: int):
        """Returns 0 if allowed, else seconds to wait."""
        now = time.monotonic()
        with self._lock:
            q = self._hits[tenant_id]
            while q and now - q[0] >= 60:
                q.popleft()
            if len(q) >= limit:
                return max(1, int(60 - (now - q[0])) + 1)
            q.append(now)
            return 0
