import codecs
import shlex
from pathlib import Path

_data_dir = Path(__file__).parent.parent.parent / "data"
_busybox_banner = (_data_dir / "busybox_banner.txt").read_text(encoding="utf-8").strip()


class BusyBoxEmulator:
    def __init__(self, version: str = "v1.38.0 (2026-05-13 02:21:49 UTC)") -> None:
        self._version = version

    def execute_line(self, line: bytes | None = None) -> bytes:
        if line is None:
            return b"/ # "

        line = line.decode("utf-8", errors="ignore")
        components = shlex.split(line)

        match components:
            case ["sh", "ash"]:
                return b"/ # "
            case ["echo", *rest]:
                return self._handle_echo(rest)
            case ["busybox", *rest] | ["/bin/busybox", *rest]:
                return self._handle_busybox(rest)

        return self._handle_unknown_command(components[0])

    def _handle_echo(self, arguments: list[str]) -> bytes:
        match arguments:
            case []:
                return b"/ # "
            case ["-e", *rest]:
                return self._handle_echo_escaped_texts(rest)
            case [*rest]:
                return self._handle_echo_text(rest)

    def _handle_echo_text(self, texts: list[str]) -> bytes:
        return f"{' '.join(texts)}\n/ # ".encode()

    def _handle_echo_escaped_texts(self, escaped_texts: list[str]) -> bytes:
        texts = []

        for escaped_text in escaped_texts:
            text = codecs.decode(escaped_text, encoding="unicode_escape")
            texts.append(text)

        return f"{' '.join(texts)}\n/ # ".encode()

    def _handle_busybox(self, arguments: list[str]) -> bytes:
        match arguments:
            case []:
                return self._handle_busybox_banner()

        return self._handle_busybox_unknown_applet(arguments[0])

    def _handle_busybox_banner(self) -> bytes:
        return _busybox_banner.format(version=self._version).encode() + b"\n/ # "

    def _handle_busybox_unknown_applet(self, applet: str) -> bytes:
        return f"{applet}: applet not found\n/ # ".encode()

    def _handle_unknown_command(self, command: str) -> bytes:
        return f"sh: {command}: not found\n/ # ".encode()
