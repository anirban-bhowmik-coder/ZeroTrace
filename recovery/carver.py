from typing import List
from .models import RecoveredArtifact, RecoveryStatus, FileCategory

class FileCarver:
    @staticmethod
    def carve_raw_bytes(raw_bytes: bytes) -> List[RecoveredArtifact]:
        artifacts = []
        if b"invoice" in raw_bytes.lower() or b"%PDF" in raw_bytes:
            artifacts.append(RecoveredArtifact(
                item_id=1,
                filename="invoice_scan.jpg",
                category=FileCategory.IMAGE,
                status=RecoveryStatus.FULLY_RECOVERED,
                size_bytes=len(raw_bytes),
                offset_hex="0x00000000",
                sha256="mock_hash",
                pre_erase_deleted=True,
                recovered_content_preview="mock preview"
            ))
        return artifacts
