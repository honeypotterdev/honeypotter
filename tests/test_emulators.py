from honeypotter.emulators import BusyBoxEmulator


def test_busybox_emulator() -> None:
    emulator = BusyBoxEmulator()

    assert emulator.execute_line() == b"/ # "


def test_busybox_unknown_command() -> None:
    emulator = BusyBoxEmulator()

    assert emulator.execute_line(b"hack") == b"sh: hack: not found\n/ # "


def test_busybox_emulator_echo_without_arguments() -> None:
    emulator = BusyBoxEmulator()

    assert emulator.execute_line(b"echo") == b"/ # "


def test_busybox_emulator_echo_text() -> None:
    emulator = BusyBoxEmulator()

    assert emulator.execute_line(b'echo "Hello, world!"') == b"Hello, world!\n/ # "
    assert emulator.execute_line(b"echo hello world") == b"hello world\n/ # "


def test_busybox_emulator_echo_escaped_text() -> None:
    emulator = BusyBoxEmulator()

    assert emulator.execute_line(b'echo -e "\\x68\\x65\\x6c\\x6c\\x6f"') == b"hello\n/ # "
    assert emulator.execute_line(b'echo -e "\\x66\\x6f\\x6f" "\\x62\\x61\\x72"') == b"foo bar\n/ # "


def test_busybox_emulator_busybox_without_arguments() -> None:
    emulator = BusyBoxEmulator(version="v1.2.3 (2000-01-02 03:04:05 UTC)")

    assert emulator.execute_line(b"busybox").startswith(b"BusyBox v1.2.3 (2000-01-02 03:04:05 UTC) multi-call binary")
    assert emulator.execute_line(b"busybox").endswith(b"\n/ # ")


def test_busybox_emulator_busybox_unknown_applet() -> None:
    emulator = BusyBoxEmulator()

    assert emulator.execute_line(b"busybox TEST").startswith(b"TEST: applet not found\n/ # ")
