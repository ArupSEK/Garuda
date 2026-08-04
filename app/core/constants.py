"""Security and workflow constants."""

from enum import StrEnum

AUTHORIZED_USE_WARNING = (
    "Only scan systems that you own or have explicit written authorization to assess. "
    "Unauthorized scanning may be illegal and may disrupt third-party services."
)


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CheckStatus(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    INFORMATIONAL = "INFORMATIONAL"
    NOT_APPLICABLE = "NOT APPLICABLE"
    NOT_TESTED = "NOT TESTED"
    MANUAL = "MANUAL TEST REQUIRED"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "SCAN ERROR"
    OUT_OF_SCOPE = "OUT OF SCOPE"


FINDING_STATUSES = {
    "new",
    "open",
    "still open",
    "reopened",
    "resolved",
    "mitigated",
    "accepted risk",
    "false positive",
    "duplicate",
    "not applicable",
    "manual review required",
    "unable to verify",
}
