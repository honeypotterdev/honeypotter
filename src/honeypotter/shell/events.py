from dataclasses import dataclass


@dataclass(kw_only=True)
class UsernameReceived:
    username: bytes


@dataclass(kw_only=True)
class PasswordReceived:
    password: bytes


@dataclass(kw_only=True)
class InputReceived:
    input: bytes
