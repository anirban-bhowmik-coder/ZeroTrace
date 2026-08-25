from dataclasses import dataclass
from typing import Optional


@dataclass
class Device:
    path: str
    device_type: str
    model: Optional[str]
    serial: Optional[str]
    capacity_bytes: int
    transport: Optional[str]
    removable: bool