import time
from collections import OrderedDict


class LRUCache[K, V]:
    def __init__(self, maxsize: int) -> None:
        self._maxsize = maxsize
        self._dict = OrderedDict[K, V]()

    def get(self, key: K) -> V | None:
        if key not in self._dict:
            return None

        self._dict.move_to_end(key)

        return self._dict[key]

    def put(self, key: K, value: V) -> None:
        if key in self._dict:
            self._dict.move_to_end(key)

        self._dict[key] = value

        if len(self._dict) > self._maxsize:
            self._dict.popitem(last=False)

    def __contains__(self, key: K) -> bool:
        return key in self._dict

    def __len__(self) -> int:
        return len(self._dict)


class TokenBucket:
    def __init__(self, *, capacity: float, fill_rate: float) -> None:
        """
        :param capacity: Maximum number of tokens in the bucket
        :param fill_rate: Tokens added per second
        """

        self._capacity = capacity
        self._fill_rate = fill_rate
        self._current_tokens = capacity
        self._last_update = time.monotonic()

    def consume(self, tokens: float = 1.0) -> bool:
        now = time.monotonic()
        seconds_elapsed = now - self._last_update
        self._last_update = now

        # Replenish
        self._current_tokens = min(self._capacity, self._current_tokens + (seconds_elapsed * self._fill_rate))

        # Consume
        if self._current_tokens >= tokens:
            self._current_tokens -= tokens
            return True

        return False


class RateLimiter[K]:
    def __init__(self, *, burst: float, rate: float, max_tracked: int) -> None:
        """
        :param burst: Maximum allowed burst of requests or connections (max tokens).
        :param rate: Allowed continuous requests per second (tokens/sec).
        :param max_tracked: Maximum unique entities tracked before LRU eviction.
        """

        self._burst = burst
        self._rate = rate
        self._cache = LRUCache[K, TokenBucket](maxsize=max_tracked)

    def is_allowed(self, key: K) -> bool:
        bucket = self._cache.get(key)

        if bucket is None:
            bucket = TokenBucket(capacity=self._burst, fill_rate=self._rate)
            self._cache.put(key, bucket)

        return bucket.consume()
