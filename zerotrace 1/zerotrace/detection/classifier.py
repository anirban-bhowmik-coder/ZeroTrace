def classify_device(device):
    """
    Classify the detected storage device.
    """

    transport = (device.transport or "").lower()
    model = (device.model or "").lower()

    # NVMe SSD
    if transport == "nvme":
        return "NVMe SSD"

    # SATA / ATA devices
    if transport in ("sata", "ata"):

        if "ssd" in model:
            return "SATA SSD"

        if "hdd" in model or "hard disk" in model:
            return "HDD"

        return "SATA Unknown"

    return "Unknown"