from honeypotter.redis.utils import InfoProvider, bytes_to_human


def test_bytes_to_human() -> None:
    assert bytes_to_human(0) == "0B"
    assert bytes_to_human(10) == "10B"
    assert bytes_to_human(1023) == "1023B"

    assert bytes_to_human(1024) == "1.00K"
    assert bytes_to_human(int(1024 * 1.5)) == "1.50K"
    assert bytes_to_human(1024**2 - 1) == "1024.00K"

    assert bytes_to_human(1024**2) == "1.00M"
    assert bytes_to_human(int(1024**2 * 1.5)) == "1.50M"
    assert bytes_to_human(1024**3 - 1) == "1024.00M"

    assert bytes_to_human(1024**3) == "1.00G"
    assert bytes_to_human(int(1024**3 * 1.5)) == "1.50G"
    assert bytes_to_human(1024**4 - 1) == "1024.00G"

    assert bytes_to_human(1024**4) == "1.00T"
    assert bytes_to_human(int(1024**4 * 1.5)) == "1.50T"
    assert bytes_to_human(1024**5 - 1) == "1024.00T"

    assert bytes_to_human(1024**5) == "1.00P"
    assert bytes_to_human(int(1024**5 * 1.5)) == "1.50P"
    assert bytes_to_human(1024**6 - 1) == "1024.00P"

    assert bytes_to_human(1024**6) == "1152921504606846976B"


class TestInfoProvider:
    def test_generate_info_uses_crlf_line_endings(self) -> None:
        info = InfoProvider().generate_info()

        assert info.endswith("\r\n")

        without_crlf = info.replace("\r\n", "")
        assert "\n" not in without_crlf
        assert "\r" not in without_crlf
