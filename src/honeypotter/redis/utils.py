import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

_data_dir = Path(__file__).parent.parent / "data"
_redis_info = (_data_dir / "redis_info.txt").read_text(encoding="utf-8").strip() + "\n"


def bytes_to_human(value: int) -> str:
    return f"{value}B"


class InfoProvider:
    def __init__(self) -> None:
        self._start = datetime.now(tz=UTC) - timedelta(days=30)

    def generate_info(self) -> str:
        return _redis_info.format(
            server_time_use=self._server_time_usec(),
            uptime_in_seconds=self._uptime_in_seconds(),
            uptime_in_days=self._uptime_in_days(),
            connected_clients=self._connected_clients(),
        )

    # Server

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
        pass
