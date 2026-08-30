from dataclasses import dataclass


@dataclass
class DeviceProfile:
    device_id: str
    model: str
    serial: str
    capacity_gb: float
    interface: str
    media_type: str
    device_kind: str
    eligible: bool
    status: str = "DETECTED"