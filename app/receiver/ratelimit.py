class TokenBuckets:
    """Per-source-IP token bucket. Stale buckets are pruned so memory stays bounded."""

    def __init__(self, rate: float, burst: int, idle_prune_seconds: float = 600.0):
        self.rate = rate
        self.burst = float(burst)
        self.idle = idle_prune_seconds
        self._b: dict[str, list[float]] = {}  # ip -> [tokens, last_ts]

    def allow(self, key: str, now: float) -> bool:
        b = self._b.get(key)
        if b is None:
            b = self._b[key] = [self.burst, now]
        else:
            b[0] = min(self.burst, b[0] + (now - b[1]) * self.rate)
            b[1] = now
        if b[0] >= 1.0:
            b[0] -= 1.0
            return True
        return False

    def prune(self, now: float) -> None:
        for k in [k for k, (_, last) in self._b.items() if now - last > self.idle]:
            del self._b[k]

    def __len__(self) -> int:
        return len(self._b)
