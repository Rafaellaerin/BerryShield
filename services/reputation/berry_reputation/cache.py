import threading
import time
from dataclasses import dataclass


@dataclass(slots=True)
class CacheItem:
    expires_at: float
    value: object


class TTLCache:
    def __init__(self, ttl_seconds: int = 300, max_items: int = 10000):
        self.ttl = ttl_seconds
        self.max_items = max_items
        self._data: dict[str, CacheItem] = {}
        self._lock = threading.Lock()

    def get(self, key: str):
        now = time.monotonic()
        with self._lock:
            item = self._data.get(key)
            if not item:
                return None
            if item.expires_at <= now:
                self._data.pop(key, None)
                return None
            return item.value

    def put(self, key: str, value):
        now = time.monotonic()
        with self._lock:
            if len(self._data) >= self.max_items:
                expired = [k for k, v in self._data.items() if v.expires_at <= now]
                for k in expired[: max(1, len(expired))]:
                    self._data.pop(k, None)
                if len(self._data) >= self.max_items:
                    self._data.pop(next(iter(self._data)), None)
            self._data[key] = CacheItem(now + self.ttl, value)
