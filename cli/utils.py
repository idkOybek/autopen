"""CLI utility functions for formatting and display."""

from datetime import datetime
from typing import Optional

from rich.style import Style


def format_datetime(dt: str) -> str:
    """Format datetime string for display.

    Args:
        dt: ISO format datetime string.

    Returns:
        Formatted datetime string (YYYY-MM-DD HH:MM:SS).
    """
    try:
        if not dt:
            return "N/A"

        # Parse ISO format with or without timezone
        if "T" in dt:
            # ISO format: 2024-01-15T10:30:00Z or 2024-01-15T10:30:00+00:00
            dt_str = dt.replace("Z", "+00:00")
            dt_obj = datetime.fromisoformat(dt_str)
        else:
            # Already formatted or simple date
            dt_obj = datetime.fromisoformat(dt)

        return dt_obj.strftime("%Y-%m-%d %H:%M:%S")

    except (ValueError, AttributeError):
        return str(dt)


def format_duration(seconds: int) -> str:
    """Format duration in seconds to human-readable format.

    Args:
        seconds: Duration in seconds.

    Returns:
        Formatted duration string (e.g., "2h 15m 30s").
    """
    if seconds < 0:
        return "0s"

    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)

    parts = []
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if secs > 0 or not parts:
        parts.append(f"{secs}s")

    return " ".join(parts)


def format_bytes(bytes_size: int) -> str:
    """Format bytes to human-readable size.

    Args:
        bytes_size: Size in bytes.

    Returns:
        Formatted size string (e.g., "1.5 MB").
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_size < 1024.0:
            return f"{bytes_size:.1f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.1f} PB"


def get_severity_style(severity: str) -> Style:
    """Get Rich style for severity level.

    Args:
        severity: Severity level (critical, high, medium, low, info).

    Returns:
        Rich Style object with appropriate color and formatting.
    """
    severity_styles = {
        "critical": Style(color="red", bold=True),
        "high": Style(color="red1"),
        "medium": Style(color="yellow"),
        "low": Style(color="blue"),
        "info": Style(color="cyan"),
    }

    return severity_styles.get(severity.lower(), Style(color="white"))


def get_severity_color(severity: str) -> str:
    """Get color name for severity level.

    Args:
        severity: Severity level.

    Returns:
        Color name string for Rich markup.
    """
    severity_colors = {
        "critical": "red",
        "high": "orange_red1",
        "medium": "yellow",
        "low": "blue",
        "info": "cyan",
    }

    return severity_colors.get(severity.lower(), "white")


def get_status_style(status: str) -> Style:
    """Get Rich style for scan status.

    Args:
        status: Scan status (pending, running, completed, failed, paused, stopped).

    Returns:
        Rich Style object with appropriate color.
    """
    status_styles = {
        "pending": Style(color="yellow"),
        "running": Style(color="blue", bold=True),
        "completed": Style(color="green", bold=True),
        "failed": Style(color="red", bold=True),
        "paused": Style(color="magenta"),
        "stopped": Style(color="orange1"),
    }

    return status_styles.get(status.lower(), Style(color="white"))


def get_status_color(status: str) -> str:
    """Get color name for scan status.

    Args:
        status: Scan status.

    Returns:
        Color name string for Rich markup.
    """
    status_colors = {
        "pending": "yellow",
        "running": "blue",
        "completed": "green",
        "failed": "red",
        "paused": "magenta",
        "stopped": "orange1",
    }

    return status_colors.get(status.lower(), "white")


def truncate_string(text: str, max_length: int, suffix: str = "...") -> str:
    """Truncate string to maximum length.

    Args:
        text: String to truncate.
        max_length: Maximum length including suffix.
        suffix: Suffix to append when truncating.

    Returns:
        Truncated string.
    """
    if len(text) <= max_length:
        return text

    return text[: max_length - len(suffix)] + suffix


def format_percentage(value: float, total: float) -> str:
    """Format percentage from value and total.

    Args:
        value: Numerator value.
        total: Denominator value.

    Returns:
        Formatted percentage string (e.g., "75.5%").
    """
    if total == 0:
        return "0.0%"

    percentage = (value / total) * 100
    return f"{percentage:.1f}%"


def pluralize(count: int, singular: str, plural: Optional[str] = None) -> str:
    """Return singular or plural form based on count.

    Args:
        count: Count value.
        singular: Singular form of the word.
        plural: Plural form (defaults to singular + 's').

    Returns:
        Appropriately pluralized string.
    """
    if plural is None:
        plural = singular + "s"

    return singular if count == 1 else plural


def format_list(items: list, max_items: int = 5, more_text: str = "more") -> str:
    """Format list for display with optional truncation.

    Args:
        items: List of items to format.
        max_items: Maximum number of items to display.
        more_text: Text to append for additional items.

    Returns:
        Comma-separated string of items.
    """
    if len(items) <= max_items:
        return ", ".join(str(item) for item in items)

    visible_items = items[:max_items]
    remaining = len(items) - max_items

    formatted = ", ".join(str(item) for item in visible_items)
    return f"{formatted}, and {remaining} {more_text}"
