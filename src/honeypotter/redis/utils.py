import random
import secrets
from datetime import UTC, datetime, timedelta
from pathlib import Path

_data_dir = Path(__file__).parent.parent / "data"
_redis_info = (_data_dir / "redis_info.txt").read_text(encoding="utf-8").strip() + "\r\n"


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
        self._rss_overhead = random.randint(5 * 1024**2, 10 * 1024**2)
        self._used_memory_peak = random.randint(60 * 1024**2, 70 * 1024**2)
        self._used_memory_startup = 876_096
        self._used_memory_overhead = 898_760

    def generate_info(self) -> str:
        now = self._now()
        used_memory = self._random_used_memory()
        used_memory_rss = self._used_memory_rss(used_memory)
        used_memory_dataset = self._used_memory_dataset(used_memory)

        return _redis_info.format(
            run_id=self._run_id,
            process_id=self._process_id,
            server_time_usec=self._server_time_usec(now),
            uptime_in_seconds=self._uptime_in_seconds(now),
            uptime_in_days=self._uptime_in_days(now),
            lru_clock=self._lru_clock(now),
            connected_clients=self._random_connected_clients(),
            used_memory=used_memory,
            used_memory_human=bytes_to_human(used_memory),
            used_memory_rss=used_memory_rss,
            used_memory_rss_human=bytes_to_human(used_memory_rss),
            used_memory_peak=self._used_memory_peak,
            used_memory_peak_human=bytes_to_human(self._used_memory_peak),
            used_memory_peak_perc=self._used_memory_peak_perc(used_memory),
            used_memory_overhead=self._used_memory_overhead,
            used_memory_startup=self._used_memory_startup,
            used_memory_dataset=used_memory_dataset,
            used_memory_dataset_perc=self._used_memory_dataset_perc(used_memory, used_memory_dataset),
        )

    def _now(self) -> datetime:
        return datetime.now(tz=UTC)

    # Server

    def _server_time_usec(self, now: datetime) -> int:
        return int(now.timestamp() * 1_000_000)

    def _uptime(self, now: datetime) -> timedelta:
        return now - self._start

    def _uptime_in_seconds(self, now: datetime) -> int:
        return int(self._uptime(now).total_seconds())

    def _uptime_in_days(self, now: datetime) -> int:
        return int(self._uptime(now).days)

    def _lru_clock(self, now: datetime) -> int:
        return int(now.timestamp()) & 0xFFFFFF

    # Clients

    def _random_connected_clients(self) -> int:
        return random.randint(5, 10)

    # Memory

    def _random_used_memory(self) -> int:
        return random.randint(1024**2 * 50, 1024**2 * 55)

    def _used_memory_rss(self, used_memory: int) -> int:
        return used_memory + self._rss_overhead

    def _used_memory_peak_perc(self, used_memory: int) -> str:
        return f"{100 * used_memory / self._used_memory_peak:.2f}%"

    def _used_memory_dataset(self, used_memory: int) -> int:
        return used_memory - self._used_memory_overhead

    def _used_memory_dataset_perc(self, used_memory: int, used_memory_dataset: int) -> str:
        return f"{100 * used_memory_dataset / (used_memory - self._used_memory_startup):.2f}%"
