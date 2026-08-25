import os
import math
import json
import hashlib
from datetime import datetime, timezone

print(">>> [STEP 1/4] Initializing Verification Engine...", flush=True)

# Standard Magic Byte Signatures
MAGIC_SIGNATURES = {
    "JPEG": b"\xFF\xD8\xFF",
    "PNG": b"\x89\x50\x4E\x47",
    "PDF": b"%PDF-",
    "ZIP_OR_DOCX": b"PK\x03\x04",
    "ELF_BINARY": b"\x7FELF",
}

class VerificationEngine:
    def __init__(self, sector_size=4096):
        self.sector_size = sector_size

    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        """Calculates Shannon Entropy (0.0 = completely blank, 8.0 = pure random noise)"""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        for count in byte_counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def check_for_magic_signatures(data: bytes) -> list:
        """Probes raw sector for recoverable file headers."""
        found = []
        for file_type, signature in MAGIC_SIGNATURES.items():
            if signature in data:
                found.append(file_type)
        return found

    def verify(self, target_path: str, method: str, sample_percentage: float = 5.0) -> dict:
        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Target file {target_path} not found.")

        file_size = os.path.getsize(target_path)
        total_sectors = max(1, file_size // self.sector_size)
        sectors_to_sample = max(10, int(total_sectors * (sample_percentage / 100.0)))
        step = max(1, total_sectors // sectors_to_sample)

        non_compliant_sectors = 0
        failed_lbas = []
        carved_signatures = []
        total_entropy = 0.0
        sampled_count = 0
        hasher = hashlib.sha256()

        with open(target_path, "rb") as f:
            for lba in range(0, total_sectors, step):
                f.seek(lba * self.sector_size)
                block = f.read(self.sector_size)
                if not block:
                    break

                sampled_count += 1
                hasher.update(block)
                entropy = self.calculate_shannon_entropy(block)
                total_entropy += entropy

                # Check for recoverable file signatures
                found_signatures = self.check_for_magic_signatures(block)
                if found_signatures:
                    carved_signatures.extend(found_signatures)
                    non_compliant_sectors += 1
                    failed_lbas.append(lba)
                    continue

                # Method-specific validation
                if "Clear" in method or "Zero" in method:
                    if any(b != 0 for b in block):
                        non_compliant_sectors += 1
                        failed_lbas.append(lba)
                elif "Sanitize" in method or "Purge" in method or "Crypto" in method:
                    if entropy < 7.90:
                        non_compliant_sectors += 1
                        failed_lbas.append(lba)

        avg_entropy = total_entropy / max(1, sampled_count)
        now_utc = datetime.now(timezone.utc).isoformat()

        if non_compliant_sectors == 0 and len(carved_signatures) == 0:
            return {
                "status": "PASS",
                "verification": "COMPLETED",
                "timestamp": now_utc,
                "device_id": target_path,
                "method": method,
                "metrics": {
                    "total_sectors": total_sectors,
                    "sampled_sectors": sampled_count,
                    "sampling_percentage": round((sampled_count / total_sectors) * 100, 2),
                    "shannon_entropy": round(avg_entropy, 4),
                    "non_compliant_sectors": 0,
                    "recovery_signatures_found": 0
                },
                "verification_hash_sha256": hasher.hexdigest()
            }
        else:
            return {
                "status": "FAIL",
                "verification": "FAILED_REMANENCE_DETECTED",
                "timestamp": now_utc,
                "device_id": target_path,
                "method": method,
                "metrics": {
                    "total_sectors": total_sectors,
                    "sampled_sectors": sampled_count,
                    "non_compliant_sectors": non_compliant_sectors,
                    "failed_lba_offsets": failed_lbas[:10],
                    "recovery_signatures_found": len(carved_signatures)
                },
                "action_required": "FLAG_DEVICE_FOR_REVIEW"
            }


# --- DIRECT EXECUTION ENTRY POINT ---
def run_test():
    engine = VerificationEngine()

    print(">>> [STEP 2/4] Generating dummy wiped disk (test_wiped_disk.bin)...", flush=True)
    with open("test_wiped_disk.bin", "wb") as f:
        f.write(b"\x00" * (1024 * 1024)) # 1MB of zeros

    print(">>> [STEP 3/4] Running Verification on Clean Disk...", flush=True)
    pass_result = engine.verify("test_wiped_disk.bin", method="NIST 800-88 Clear")
    print("\n==================== PASS TEST RESULT ====================")
    print(json.dumps(pass_result, indent=2))
    print("=========================================================\n", flush=True)

    print(">>> [STEP 4/4] Generating dirty disk with remnant PDF bytes...", flush=True)
    with open("test_dirty_disk.bin", "wb") as f:
        f.write(b"\x00" * (512 * 1024))
        f.write(b"%PDF-1.4 Leaked Sensitive Forensic Document Remnant")
        f.write(b"\x00" * (512 * 1024))

    print(">>> Running Verification on Dirty Disk (Testing Safe-Failure)...", flush=True)
    fail_result = engine.verify("test_dirty_disk.bin", method="NIST 800-88 Clear")
    print("\n==================== FAIL TEST RESULT ====================")
    print(json.dumps(fail_result, indent=2))
    print("=========================================================\n", flush=True)


if __name__ == "__main__":
    run_test()