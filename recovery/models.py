from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from typing import List, Optional

class RecoveryStatus(str, Enum):
    FULLY_RECOVERED = "FULLY_RECOVERED"
    PARTIALLY_RECOVERED = "PARTIALLY_RECOVERED"
    CORRUPTED = "CORRUPTED"
    FAILED = "FAILED"
    NOT_RECOVERABLE = "NOT_RECOVERABLE"

class FileCategory(str, Enum):
    DOCUMENT = "Text File"
    EMAIL = "Email"
    DATA = "Data File"
    IMAGE = "Image"
    LOG = "Log File"
    ARCHIVE = "Archive"
    UNKNOWN = "Raw Sector Data"

@dataclass
class RecoveredArtifact:
    item_id: int
    filename: str
    category: str
    status: RecoveryStatus
    size_bytes: int
    offset_hex: str = ""
    sha256: str = ""
    pre_erase_deleted: bool = True
    recovered_content_preview: str = ""

@dataclass
class RecoveryResult:
    device_path: str
    scan_method: str
    total_files_found: int
    fully_recovered_count: int
    partially_recovered_count: int
    corrupted_count: int
    failed_count: int
    scan_duration_secs: float
    started_at: datetime
    completed_at: datetime
    artifacts: List[RecoveredArtifact] = field(default_factory=list)
    raw_scan_log: str = ""
    post_erasure_proof_passed: bool = False
