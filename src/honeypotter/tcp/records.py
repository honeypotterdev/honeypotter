from datetime import datetime

from pydantic import BaseModel

from honeypotter.recorders import Peer


class TcpSessionRecord(BaseModel):
    honeypot: Peer
    client: Peer
    payload: bytes = b""
    created_at: datetime
