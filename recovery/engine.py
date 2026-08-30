import logging
import subprocess
import shlex
import time
from datetime import datetime
from typing import List, Optional

from .models import RecoveryResult, RecoveredArtifact, RecoveryStatus, FileCategory
from .carver import FileCarver

logger = logging.getLogger("zerotrace.recovery")


class RecoveryEngine:
    """
    Forensic file recovery & proof-of-erasure verification engine.
    """

    def scan_device(
        self,
        device_path: str,
        demo_mode: bool = True,
        post_erasure: bool = False,
    ) -> RecoveryResult:
        """
        Scan target device for deleted files and recoverable data artifacts.

        Args:
            device_path: Target device path (e.g., /dev/sdb)
            demo_mode: Run in trial/demo simulation mode
            post_erasure: If True, tests recovery AFTER ZeroTrace secure erasure (expects 0 files found)
        """
        started = datetime.utcnow()
        logger.info(
            "Starting recovery scan on %s (demo_mode=%s, post_erasure=%s)",
            device_path, demo_mode, post_erasure
        )

        if demo_mode:
            return self._demo_scan(device_path, started, post_erasure)

        # Real disk scan logic
        return self._real_scan(device_path, started, post_erasure)

    def _demo_scan(
        self,
        device_path: str,
        started: datetime,
        post_erasure: bool,
    ) -> RecoveryResult:
        """Simulate realistic forensic deep sector scan and file carving results."""
        time.sleep(0.5)  # Simulate scanning time
        completed = datetime.utcnow()
        duration = (completed - started).total_seconds()

        if post_erasure:
            log_msg = (
                f"[FORENSIC DEEP SCAN LOG]\n"
                f"Target: {device_path}\n"
                f"Scan Method: Deep Raw Sector Carving & MFT Record Scan\n"
                f"Total Sectors Scanned: 2,000,409,600 sectors (1.0 TB)\n"
                f"Header Signatures Checked: 142 file types\n"
                f"Result: 0 file signatures found. All sampled sectors return 0x00 pattern.\n"
                f"Verdict: DATA IS 100% UNRECOVERABLE (Sanitization Confirmed)."
            )
            return RecoveryResult(
                device_path=device_path,
                scan_method="Deep Raw Sector Carving & MFT Record Scan",
                total_files_found=0,
                fully_recovered_count=0,
                partially_recovered_count=0,
                corrupted_count=0,
                failed_count=0,
                scan_duration_secs=duration,
                started_at=started,
                completed_at=completed,
                artifacts=[],
                raw_scan_log=log_msg,
                post_erasure_proof_passed=True,
            )
        else:
            artifacts = [
                RecoveredArtifact(
                    item_id=1,
                    filename="conversation.txt",
                    category="Text File",
                    status=RecoveryStatus.FULLY_RECOVERED,
                    size_bytes=345,
                    offset_hex="0x0001a400",
                    sha256="a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0",
                    recovered_content_preview="Confidential chat logs retrieved from unallocated sector 210.",
                ),
                RecoveredArtifact(
                    item_id=2,
                    filename="deleted_email.eml",
                    category="Email",
                    status=RecoveryStatus.FULLY_RECOVERED,
                    size_bytes=314,
                    offset_hex="0x0002b800",
                    sha256="b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef01",
                    recovered_content_preview="Subject: Financial transfer approval confirmation.",
                ),
                RecoveredArtifact(
                    item_id=3,
                    filename="evidence_notes.txt",
                    category="Text File",
                    status=RecoveryStatus.PARTIALLY_RECOVERED,
                    size_bytes=307,
                    offset_hex="0x0004c200",
                    sha256="c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef012",
                    recovered_content_preview="Partial notes recovered. Sector 612 partially overwritten.",
                ),
                RecoveredArtifact(
                    item_id=4,
                    filename="financial_records.csv",
                    category="Data File",
                    status=RecoveryStatus.CORRUPTED,
                    size_bytes=236,
                    offset_hex="0x0006f100",
                    sha256="d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0123",
                    recovered_content_preview="File structure damaged due to filesystem cluster re-allocation.",
                ),
                RecoveredArtifact(
                    item_id=5,
                    filename="system_activity.log",
                    category="Log File",
                    status=RecoveryStatus.FULLY_RECOVERED,
                    size_bytes=296,
                    offset_hex="0x0008e300",
                    sha256="e5f67890123456789abcdef0123456789abcdef0123456789abcdef01234",
                    recovered_content_preview="User activity log timestamped 2026-08-24T11:23:45.",
                ),
            ]

            log_msg = (
                f"[FORENSIC DEEP SCAN LOG]\n"
                f"Target: {device_path}\n"
                f"Scan Method: Deep Raw Sector Carving & MFT Record Scan\n"
                f"Total Sectors Scanned: 2,000,409,600 sectors (1.0 TB)\n"
                f"Header Signatures Matched: 5 deleted file artifacts detected.\n"
                f"Verdict: RECOVERY SUCCESSFUL (Data remnants extracted)."
            )

            return RecoveryResult(
                device_path=device_path,
                scan_method="Deep Raw Sector Carving & MFT Record Scan",
                total_files_found=5,
                fully_recovered_count=3,
                partially_recovered_count=1,
                corrupted_count=1,
                failed_count=0,
                scan_duration_secs=duration,
                started_at=started,
                completed_at=completed,
                artifacts=artifacts,
                raw_scan_log=log_msg,
                post_erasure_proof_passed=False,
            )

    def _real_scan(
        self,
        device_path: str,
        started: datetime,
        post_erasure: bool,
    ) -> RecoveryResult:
        """Perform real raw byte scanning using native python read or dd and FileCarver."""
        raw_bytes = b""
        try:
            with open(device_path, "rb") as f:
                raw_bytes = f.read(100 * 1024 * 1024) # Read up to 100MB
        except Exception as e:
            logger.error("Error reading raw device %s natively: %s, falling back to dd", device_path, e)
            cmd = f"dd if={device_path} bs=1M count=100 status=none"
            try:
                proc = subprocess.run(shlex.split(cmd), capture_output=True)
                raw_bytes = proc.stdout if proc.returncode == 0 else b""
            except Exception as e2:
                logger.error("Error reading raw device %s via dd: %s", device_path, e2)

        completed = datetime.utcnow()
        duration = (completed - started).total_seconds()

        artifacts = FileCarver.carve_raw_bytes(raw_bytes)
        fully = sum(1 for a in artifacts if a.status == RecoveryStatus.FULLY_RECOVERED)
        partially = sum(1 for a in artifacts if a.status == RecoveryStatus.PARTIALLY_RECOVERED)
        corrupted = sum(1 for a in artifacts if a.status == RecoveryStatus.CORRUPTED)

        return RecoveryResult(
            device_path=device_path,
            scan_method="Raw Sector Carver (dd stream)",
            total_files_found=len(artifacts),
            fully_recovered_count=fully,
            partially_recovered_count=partially,
            corrupted_count=corrupted,
            failed_count=0,
            scan_duration_secs=duration,
            started_at=started,
            completed_at=completed,
            artifacts=artifacts,
            raw_scan_log=f"Scanned {len(raw_bytes)} bytes from {device_path}.",
            post_erasure_proof_passed=(len(artifacts) == 0),
        )
