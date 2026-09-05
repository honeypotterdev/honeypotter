import codecs
import shlex
from pathlib import Path

_data_dir = Path(__file__).parent / "data"
_busybox_banner = (_data_dir / "busybox_banner.txt").read_text(encoding="utf-8").strip()

Command = list[str]


class BusyBoxEmulator:
    def __init__(self, version: str = "v1.38.0 (2026-05-13 02:21:49 UTC)") -> None:
        self._version = version

    def execute_line(self, line: bytes | None = None) -> bytes:
        if line is None:
            return b"/ # "

        command_line = self._normalize_command_line(line)
        command_list = self._split_into_command_list(command_line)

        return self._handle_command_list(command_list)

    def _normalize_command_line(self, command_line: bytes) -> str:
        return command_line.replace(b"\x00", b"").decode("utf-8", errors="ignore")

    def _split_into_command_list(self, command_line: str) -> list[Command]:
        lexer = shlex.shlex(command_line, posix=True, punctuation_chars=";&")
        command_list: list[Command] = [[]]

        for token in lexer:
            if token == ";":
                command_list.append([])
            else:
                command_list[-1].append(token)

        return command_list

    def _handle_command_list(self, command_list: list[Command]) -> bytes:
        output = b""

        for command in command_list:
            output += self._handle_command(command)

        return output

    def _handle_command(self, command: Command) -> bytes:
        match command:
            case []:
                return b"/ # "
            case ["sh", *_rest] | ["ash", *_rest]:
                return b"/ # "
            case ["echo", *rest]:
                return self._handle_echo(rest)
            case ["busybox", *rest] | ["/bin/busybox", *rest]:
                return self._handle_busybox(rest)
            case ["cd", "/proc", "&&", "cat", "self/cmdline"]:
                return b"catself/cmdline/proc #"

        return self._handle_unknown_command(command[0])

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
