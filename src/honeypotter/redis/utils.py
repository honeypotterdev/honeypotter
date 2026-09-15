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
        self._total_system_memory = self._random_total_system_memory()
        self._rdb_last_save_time = self._random_rdb_last_save_time()
        self._rdb_saves = random.randint(3, 30)
        self._rdb_last_bgsave_time_sec = random.randint(0, 2)
        self._rdb_last_cow_size = random.randint(128, 512) * 4096
        self._latest_fork_usec = random.randint(200, 2_000)
        self._commands_per_second = 5
        self._average_request_bytes = 60
        self._average_response_bytes = 100

    def generate_info(self) -> str:
        now = self._now()
        uptime_in_seconds = self._uptime_in_seconds(now)
        total_commands_processed = self._total_commands_processed(uptime_in_seconds)
        used_memory = self._random_used_memory()
        used_memory_rss = self._used_memory_rss(used_memory)
        used_memory_dataset = self._used_memory_dataset(used_memory)
        allocator_allocated = self._allocator_allocated(used_memory)
        allocator_active = self._allocator_active(allocator_allocated)
        allocator_resident = self._allocator_resident(allocator_active)

        return _redis_info.format(
            run_id=self._run_id,
            process_id=self._process_id,
            server_time_usec=self._server_time_usec(now),
            uptime_in_seconds=uptime_in_seconds,
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
            allocator_allocated=allocator_allocated,
            allocator_active=allocator_active,
            allocator_resident=allocator_resident,
            total_system_memory=self._total_system_memory,
            total_system_memory_human=bytes_to_human(self._total_system_memory),
            allocator_frag_ratio=self._allocator_frag_ratio(allocator_allocated, allocator_active),
            allocator_frag_bytes=self._allocator_frag_bytes(allocator_allocated, allocator_active),
            allocator_rss_ratio=self._allocator_rss_ratio(allocator_active, allocator_resident),
            allocator_rss_bytes=self._allocator_rss_bytes(allocator_active, allocator_resident),
            rss_overhead_ratio=self._rss_overhead_ratio(allocator_resident, used_memory_rss),
            rss_overhead_bytes=self._rss_overhead_bytes(allocator_resident, used_memory_rss),
            mem_fragmentation_ratio=self._mem_fragmentation_ratio(used_memory, used_memory_rss),
            mem_fragmentation_bytes=self._mem_fragmentation_bytes(used_memory, used_memory_rss),
            rdb_last_save_time=self._rdb_last_save_time,
            rdb_last_bgsave_time_sec=self._rdb_last_bgsave_time_sec,
            rdb_saves=self._rdb_saves,
            rdb_last_cow_size=self._rdb_last_cow_size,
            total_commands_processed=total_commands_processed,
            instantaneous_ops_per_sec=self._commands_per_second,
            total_net_input_bytes=self._total_net_input_bytes(total_commands_processed),
            total_net_output_bytes=self._total_net_output_bytes(total_commands_processed),
            instantaneous_input_kbps=self._instantaneous_input_kbps(),
            instantaneous_output_kbps=self._instantaneous_output_kbps(),
            latest_fork_usec=self._latest_fork_usec,
            total_forks=self._rdb_saves,
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

    def _allocator_allocated(self, used_memory: int) -> int:
        return used_memory + self._rss_overhead // 10

    def _allocator_active(self, allocator_allocated: int) -> int:
        return allocator_allocated + self._rss_overhead // 4

    def _allocator_resident(self, allocator_active: int) -> int:
        return allocator_active + self._rss_overhead // 3

    def _random_total_system_memory(self) -> int:
        reserved_pages = random.randint(64 * 1024**2 // 4096, 128 * 1024**2 // 4096)
        return 2 * 1024**3 - reserved_pages * 4096

    def _allocator_frag_ratio(self, allocator_allocated: int, allocator_active: int) -> str:
        return f"{allocator_active / allocator_allocated:.2f}"

    def _allocator_frag_bytes(self, allocator_allocated: int, allocator_active: int) -> int:
        return allocator_active - allocator_allocated

    def _allocator_rss_ratio(self, allocator_active: int, allocator_resident: int) -> str:
        return f"{allocator_resident / allocator_active:.2f}"

    def _allocator_rss_bytes(self, allocator_active: int, allocator_resident: int) -> int:
        return allocator_resident - allocator_active

    def _rss_overhead_ratio(self, allocator_resident: int, used_memory_rss: int) -> str:
        return f"{used_memory_rss / allocator_resident:.2f}"

    def _rss_overhead_bytes(self, allocator_resident: int, used_memory_rss: int) -> int:
        return used_memory_rss - allocator_resident

    def _mem_fragmentation_ratio(self, used_memory: int, used_memory_rss: int) -> str:
        return f"{used_memory_rss / used_memory:.2f}"

    def _mem_fragmentation_bytes(self, used_memory: int, used_memory_rss: int) -> int:
        return used_memory_rss - used_memory

    # Persistence

    def _random_rdb_last_save_time(self) -> int:
        last_save = self._start + timedelta(days=29, seconds=random.randint(0, 23 * 60 * 60))
        return int(last_save.timestamp())

    # Stats

    def _total_commands_processed(self, uptime_in_seconds: int) -> int:
        return uptime_in_seconds * self._commands_per_second

    def _total_net_input_bytes(self, total_commands_processed: int) -> int:
        return total_commands_processed * self._average_request_bytes

    def _total_net_output_bytes(self, total_commands_processed: int) -> int:
        return total_commands_processed * self._average_response_bytes

    def _instantaneous_input_kbps(self) -> str:
        return f"{self._commands_per_second * self._average_request_bytes / 1024:.2f}"

    def _instantaneous_output_kbps(self) -> str:
        return f"{self._commands_per_second * self._average_response_bytes / 1024:.2f}"
