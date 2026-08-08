"""Tests for UTC normalization at API and dashboard boundaries."""

from datetime import UTC, datetime, timedelta, timezone

from app.api.scans import scan_dict
from app.models import Scan
from app.utils.datetime_utils import format_elapsed, normalize_utc, parse_utc


def test_normalize_utc_treats_legacy_naive_values_as_utc() -> None:
    naive = datetime(2026, 8, 9, 12, 0, 0, tzinfo=UTC).replace(tzinfo=None)
    normalized = normalize_utc(naive)

    assert normalized.tzinfo is UTC
    assert normalized.isoformat() == "2026-08-09T12:00:00+00:00"


def test_parse_utc_converts_offsets_and_z_suffix() -> None:
    india = timezone(timedelta(hours=5, minutes=30))

    assert parse_utc(datetime(2026, 8, 9, 17, 30, tzinfo=india)).hour == 12
    assert parse_utc("2026-08-09T12:00:00Z").tzinfo is UTC


def test_format_elapsed_handles_naive_and_aware_values() -> None:
    naive_now = datetime(2026, 8, 9, 12, 1, 2, tzinfo=UTC).replace(tzinfo=None)
    assert format_elapsed("2026-08-09T12:00:00", "2026-08-09T12:05:07+00:00") == "0:05:07"
    assert (
        format_elapsed(
            "2026-08-09T12:00:00+00:00",
            now=naive_now,
        )
        == "0:01:02"
    )


def test_format_elapsed_is_safe_for_invalid_or_reversed_values() -> None:
    assert format_elapsed("not-a-timestamp") == "Unavailable"
    assert format_elapsed("2026-08-09T12:01:00Z", "2026-08-09T12:00:00Z") == "0:00:00"


def test_scan_api_normalizes_sqlite_naive_timestamps() -> None:
    naive_start = datetime(2026, 8, 9, 12, 0, 0, tzinfo=UTC).replace(tzinfo=None)
    naive_end = datetime(2026, 8, 9, 12, 5, 0, tzinfo=UTC).replace(tzinfo=None)
    scan = Scan(
        public_id="SCAN-20260809-TEST",
        profile="quick",
        targets=["203.0.113.10"],
        options={},
        start_time=naive_start,
        end_time=naive_end,
    )

    payload = scan_dict(scan)

    assert payload["start_time"].tzinfo is UTC
    assert payload["end_time"].tzinfo is UTC
