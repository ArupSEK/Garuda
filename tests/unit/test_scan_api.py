"""Regression tests for scan API execution context."""

import inspect

from app.api.scans import create_scan


def test_create_scan_runs_on_the_application_event_loop() -> None:
    """The endpoint must not enter FastAPI's worker thread before creating its task."""
    assert inspect.iscoroutinefunction(create_scan)
