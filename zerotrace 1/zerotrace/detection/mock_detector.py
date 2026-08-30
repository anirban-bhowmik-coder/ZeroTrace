from .models import Device


class MockDeviceDetector:

    def detect(self):

        return [
            Device(
                path="/dev/nvme0n1",
                device_type="disk",
                model="Demo NVMe SSD",
                serial="ZT-DEMO-001",
                capacity_bytes=512 * 1024 * 1024 * 1024,
                transport="nvme",
                removable=False
            ),

            Device(
                path="/dev/sda",
                device_type="disk",
                model="Demo Hard Disk",
                serial="ZT-DEMO-002",
                capacity_bytes=1 * 1024 * 1024 * 1024 * 1024,
                transport="sata",
                removable=False
            )
        ]