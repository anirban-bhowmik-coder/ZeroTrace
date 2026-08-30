import json
import subprocess

from .models import Device


class DeviceDetector:

    def detect(self):
        """
        Detect connected storage devices.

        IMPORTANT:
        This function is READ-ONLY.
        It does not modify any storage device.
        """

        command = [
            "lsblk",
            "-J",
            "-b",
            "-o",
            "NAME,PATH,TYPE,SIZE,MODEL,SERIAL,TRAN,RM"
        ]

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )

        data = json.loads(result.stdout)

        devices = []

        for item in data.get("blockdevices", []):

            # We only want physical disk devices.
            if item.get("type") != "disk":
                continue

            device = Device(
                path=item.get("path"),
                device_type="disk",
                model=item.get("model"),
                serial=item.get("serial"),
                capacity_bytes=int(item.get("size") or 0),
                transport=item.get("tran"),
                removable=bool(item.get("rm"))
            )

            devices.append(device)

        return devices