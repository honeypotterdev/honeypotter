from honeypotter.redis.utils import bytes_to_human


def test_bytes_to_human() -> None:
    assert bytes_to_human(10) == "10B"
    assert bytes_to_human(1024) == "1.00K"
    assert bytes_to_human(int(1024 * 1.5)) == "1.50K"
    assert bytes_to_human(1024 * 1024) == "1.00M"
    assert bytes_to_human(int(1024 * 1024 * 1.5)) == "1.50M"
    assert bytes_to_human(1024 * 1024 * 1024) == "1.00G"
    assert bytes_to_human(int(1024 * 1024 * 1024 * 1.5)) == "1.50G"
