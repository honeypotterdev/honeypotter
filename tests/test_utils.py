from freezegun import freeze_time

from honeypotter.utils import LRUCache, RateLimiter, TokenBucket


def test_lru_cache() -> None:
    cache = LRUCache[str, str](maxsize=2)

    assert "foo" not in cache
    assert "bar" not in cache
    assert "baz" not in cache

    cache.put("foo", "foo_value")
    cache.put("bar", "bar_value")

    assert len(cache) == 2
    assert "foo" in cache
    assert "bar" in cache
    assert "baz" not in cache
    assert cache.get("foo") == "foo_value"
    assert cache.get("bar") == "bar_value"

    cache.put("baz", "baz_value_1")
    cache.put("baz", "baz_value_2")

    assert len(cache) == 2
    assert "foo" not in cache
    assert "bar" in cache
    assert "baz" in cache
    assert cache.get("bar") == "bar_value"
    assert cache.get("baz") == "baz_value_2"


def test_token_bucket() -> None:
    with freeze_time("2000-01-01 00:00:00"):
        bucket = TokenBucket(capacity=2, fill_rate=10 / 60)  # 10/1m

        assert bucket.consume() is True
        assert bucket.consume() is True
        assert bucket.consume() is False

    with freeze_time("2000-01-01 00:01:00"):
        assert bucket.consume() is True


def test_rate_limiter() -> None:
    limiter = RateLimiter[str](burst=1, rate=10 / 60, max_tracked=2)

    # Fill cache capacity
    assert limiter.is_allowed("1.1.1.1") is True
    assert limiter.is_allowed("1.1.1.2") is True
    assert limiter.is_allowed("1.1.1.1") is False
    assert limiter.is_allowed("1.1.1.2") is False

    # 3rd IP triggers eviction of oldest ("1.1.1.1")
    assert limiter.is_allowed("1.1.1.3") is True

    # Evicted IP acts like a new key with full burst
    assert limiter.is_allowed("1.1.1.1") is True
