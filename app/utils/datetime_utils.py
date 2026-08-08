"""UTC normalization helpers for API and dashboard timestamps."""

from datetime import UTC, datetime, timedelta


def normalize_utc(value: datetime) -> datetime:
    """Return an aware UTC datetime, treating legacy naive database values as UTC."""

    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def parse_utc(value: str | datetime) -> datetime:
    """Parse an ISO timestamp and normalize it to aware UTC."""

    if isinstance(value, datetime):
        return normalize_utc(value)
    text = str(value).strip()
    if text.lower().endswith("z"):
        text = f"{text[:-1]}+00:00"
    return normalize_utc(datetime.fromisoformat(text))


def format_elapsed(
    started: str | datetime,
    ended: str | datetime | None = None,
    *,
    now: datetime | None = None,
) -> str:
    """Format a non-negative elapsed duration without mixing naive and aware values."""

    try:
        start_time = parse_utc(started)
        end_time = parse_utc(ended) if ended is not None else normalize_utc(now or datetime.now(UTC))
    except (TypeError, ValueError):
        return "Unavailable"
    seconds = max(0, int((end_time - start_time).total_seconds()))
    return str(timedelta(seconds=seconds))
