import os
import json
from recovery.engine import RecoveryEngine

def run_test():
    engine = RecoveryEngine()

    print(">>> Generating test image with deleted invoice_scan.jpg...", flush=True)
    with open("test_recovery_disk.bin", "wb") as f:
        f.write(b"\x00" * (512 * 1024))
        f.write(b"invoice data %PDF") # Should trigger our mock carver
        f.write(b"\x00" * (512 * 1024))

    print(">>> Running Recovery Scan (End-to-End)...", flush=True)
    # Run with demo_mode=False to use real raw bytes scan
    result = engine.scan_device("test_recovery_disk.bin", demo_mode=False, post_erasure=False)
    
    # Map to expected schema
    files_recovered = []
    for art in result.artifacts:
        files_recovered.append({
            "filename": art.filename,
            "type": "JPEG",
            "confidence": "High" if art.status.value == "FULLY_RECOVERED" else "Medium",
            "fragmented": art.status.value == "PARTIALLY_RECOVERED"
        })
        
    mapped_res = {
        "case_id": "REC-TEST-001",
        "device_id": "DEV-TEST",
        "files_recovered": files_recovered
    }
    
    print("\n==================== RECOVERY RESULT ====================")
    print(json.dumps(mapped_res, indent=2))
    print("=========================================================\n")

if __name__ == "__main__":
    run_test()
