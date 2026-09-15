import random
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

_data_dir = Path(__file__).parent.parent / "data"
_redis_info = (_data_dir / "redis_info.txt").read_text(encoding="utf-8").strip() + "\n"


def bytes_to_human(value: float) -> str:
    """Format a byte count like Redis's bytesToHuman helper."""

    if value < 1024:
        return f"{value}B"

    for exponent, unit in enumerate("KMGTP", start=1):
        if value < 1024 ** (exponent + 1):
            return f"{value / 1024**exponent:.2f}{unit}"

    # Canonical implementation: Let's hope we never need this :D
    return f"{value}B"


class InfoProvider:
    def __init__(self) -> None:
        self._start = datetime.now(tz=UTC) - timedelta(days=30)
        self._process_id = random.randint(9_000, 10_000)
        self._run_id = secrets.token_hex(20)

    def generate_info(self) -> str:
        used_memory = self._used_memory()

        return _redis_info.format(
            run_id=self._run_id,
            process_id=self._process_id,
            server_time_use=self._server_time_usec(),
            uptime_in_seconds=self._uptime_in_seconds(),
            uptime_in_days=self._uptime_in_days(),
            connected_clients=self._connected_clients(),
            used_memory=used_memory,
            used_memory_human=bytes_to_human(used_memory),
        )

    # Server

    # TODO: Implement "run_id"

    def _server_time_usec(self) -> int:
        return int(datetime.now(tz=UTC).timestamp() * 1_000_000)

    def _uptime(self) -> timedelta:
        return datetime.now(tz=UTC) - self._start

    def _uptime_in_seconds(self) -> int:
        return int(self._uptime().total_seconds())

    def _uptime_in_days(self) -> int:
        return int(self._uptime().days)

    # TODO: Implement "lru_clock"

    # Clients

    def _connected_clients(self) -> int:
        return random.randint(5, 10)

    # TODO: Implement "client_recent_max_input_buffer"
    # TODO: Implement "client_recent_max_output_buffer"

    # Memory

    def _used_memory(self) -> int:
        low = 1024**2 * 200
        high = 1024**2 * 250

        return random.randint(low, high)
