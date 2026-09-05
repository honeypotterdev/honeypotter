import pytest

from honeypotter.emulators import BusyBoxEmulator


class TestBusyBoxEmulator:
    @pytest.fixture
    def emulator(self) -> BusyBoxEmulator:
        return BusyBoxEmulator()

    def test_without_input(self, emulator: BusyBoxEmulator) -> None:
        assert emulator.execute_line() == b"/ # "

    def test_empty_command_line(self, emulator: BusyBoxEmulator) -> None:
        assert emulator.execute_line(b"") == b"/ # "

    def test_sh_command(self, emulator: BusyBoxEmulator) -> None:
        assert emulator.execute_line(b"sh") == b"/ # "

    def test_echo_command_without_arguments(self, emulator: BusyBoxEmulator) -> None:
        assert emulator.execute_line(b"echo") == b"/ # "

    def test_echo_command_with_text(self, emulator: BusyBoxEmulator) -> None:
        assert emulator.execute_line(b'echo\x00 "Hello, world!"') == b"Hello, world!\n/ # "
        assert emulator.execute_line(b"echo hello world") == b"hello world\n/ # "

    def test_echo_command_with_escaped_text(self, emulator: BusyBoxEmulator) -> None:
        assert emulator.execute_line(b'echo -e "\\x68\\x65\\x6c\\x6c\\x6f"') == b"hello\n/ # "
        assert emulator.execute_line(b'echo -e "\\x66\\x6f\\x6f" "\\x62\\x61\\x72"') == b"foo bar\n/ # "

    def test_busybox_without_arguments(self) -> None:
        emulator = BusyBoxEmulator(version="v1.2.3 (2000-01-02 03:04:05 UTC)")

        output = emulator.execute_line(b"busybox")

        assert output.startswith(b"BusyBox v1.2.3 (2000-01-02 03:04:05 UTC) multi-call binary")
        assert output.endswith(b"\n/ # ")

    def test_special_case_1(self, emulator: BusyBoxEmulator) -> None:
        assert emulator.execute_line(b"cd /proc && cat self/cmdline") == b"catself/cmdline/proc #"

    def test_busybox_unknown_applet(self, emulator: BusyBoxEmulator) -> None:
        assert emulator.execute_line(b"busybox TEST").startswith(b"TEST: applet not found\n/ # ")

    def test_unknown_command(self, emulator: BusyBoxEmulator) -> None:
        assert emulator.execute_line(b"hack") == b"sh: hack: not found\n/ # "

    def test_multiple_commands_separated_by_semicolon(self, emulator: BusyBoxEmulator) -> None:
        assert emulator.execute_line(b"test; test") == b"sh: test: not found\n/ # sh: test: not found\n/ # "

    def test_strips_nul_bytes(self, emulator: BusyBoxEmulator) -> None:
        assert emulator.execute_line(b"te\x00st\00") == b"sh: test: not found\n/ # "
