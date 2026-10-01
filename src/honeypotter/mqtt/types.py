from dataclasses import dataclass
from enum import IntEnum


class ConnectReturnCode(IntEnum):
    ACCEPTED = 0
    REFUSED_UNACCEPTABLE_PROTOCOL_VERSION = 1
    REFUSED_IDENTIFIER_REJECTED = 2
    REFUSED_SERVER_UNAVAILABLE = 3
    REFUSED_BAD_USER_NAME_OR_PASSWORD = 4
    REFUSED_NOT_AUTHORIZED = 5


@dataclass(kw_only=True)
class Subscription:
    topic_filter: str
    qos: int = 0
