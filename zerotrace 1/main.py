import subprocess
import json

from zerotrace.device_profile import DeviceProfile


def detect_devices():

    command = [
        "powershell",
        "-Command",
        "Get-CimInstance Win32_DiskDrive | "
        "Select-Object DeviceID,Model,SerialNumber,Size,InterfaceType,MediaType,PNPDeviceID | "
        "ConvertTo-Json"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("Could not detect storage devices.")
        return []

    if not result.stdout.strip():
        return []

    data = json.loads(result.stdout)

    if isinstance(data, dict):
        data = [data]

    return data


def classify_device(device):

    model = (device.get("Model") or "").lower()
    pnp_id = (device.get("PNPDeviceID") or "").lower()

    if "nvme" in model or "nvme" in pnp_id:
        return "NVMe SSD"

    if "ssd" in model:
        return "SSD"

    if "hard disk" in model or "hdd" in model:
        return "HDD"

    return "Unknown"


def classify_device_kind(device):

    model = (device.get("Model") or "").lower()
    device_id = (device.get("DeviceID") or "").lower()

    virtual_keywords = [
        "virtual",
        "vmware",
        "virtualbox",
        "hyper-v",
        "microsoft virtual"
    ]

    for keyword in virtual_keywords:

        if keyword in model or keyword in device_id:
            return "Virtual"

    return "Physical"


def main():

    print("=" * 50)
    print("          ZEROTRACE DEVICE DETECTOR")
    print("=" * 50)

    devices = detect_devices()

    if not devices:
        print("\nNo storage devices detected.")
        return

    for number, device in enumerate(devices, start=1):

        size = device.get("Size")

        if size:
            size_gb = round(int(size) / (1024 ** 3), 2)
        else:
            size_gb = 0

        media_type = classify_device(device)

        device_kind = classify_device_kind(device)

        # Safety gate
        eligible = device_kind == "Physical"

        # Create structured Device Profile
        profile = DeviceProfile(
            device_id=device.get("DeviceID") or "Unknown",
            model=device.get("Model") or "Unknown",
            serial=device.get("SerialNumber") or "Unknown",
            capacity_gb=size_gb,
            interface=device.get("InterfaceType") or "Unknown",
            media_type=media_type,
            device_kind=device_kind,
            eligible=eligible
        )

        print(f"\nDevice {number}")
        print("-" * 50)

        print(f"Device ID   : {profile.device_id}")
        print(f"Model       : {profile.model}")
        print(f"Serial      : {profile.serial}")
        print(f"Capacity    : {profile.capacity_gb} GB")
        print(f"Interface   : {profile.interface}")
        print(f"Media Type  : {profile.media_type}")
        print(f"Device Kind : {profile.device_kind}")
        print(f"Eligible    : {'YES' if profile.eligible else 'NO'}")
        print(f"Status      : {profile.status} ✓")


if __name__ == "__main__":
    main()