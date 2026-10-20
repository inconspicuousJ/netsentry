"""Small helpers: safe display of untrusted text, formatting, safe file writing."""

from __future__ import annotations

import math
import os
import tempfile
import unicodedata
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Untrusted text
# ---------------------------------------------------------------------------
# Strings taken from packets (DNS names, for example) are controlled by whoever
# generated the traffic. Printed raw, they could contain ANSI escape sequences
# that recolour, hide or rewrite terminal output, or Unicode "bidi" characters
# that visually reorder text. Everything derived from a capture is passed
# through these functions before it is displayed or written to a report.

# Unicode categories that are invisible or alter how surrounding text renders:
# Cc = control characters (includes ESC, CR, LF, TAB, DEL and C1 controls),
# Cf = format characters (bidi overrides, zero-width joiners, BOM),
# Cs = surrogates, Co = private use, Cn = unassigned,
# Zl / Zp = line and paragraph separators.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


def _escape_char(char: str) -> str:
    code = ord(char)
    if code <= 0xFF:
        return f"\\x{code:02x}"
    if code <= 0xFFFF:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


def sanitize_text(value: object, max_length: int | None = None) -> str:
    """Return ``value`` as a single-line string safe to show in a terminal.

    Control and formatting characters are replaced by visible escapes such as
    ``\\x1b`` instead of being removed, so an analyst can see that something
    odd was present.
    """
    text = str(value)
    if any(unicodedata.category(ch) in _UNSAFE_CATEGORIES for ch in text):
        text = "".join(
            _escape_char(ch) if unicodedata.category(ch) in _UNSAFE_CATEGORIES else ch
            for ch in text
        )
    return truncate(text, max_length) if max_length else text


def escape_bytes(data: bytes) -> str:
    """Convert raw protocol bytes (such as a DNS name) into a printable string.

    Visible ASCII is kept; everything else, including spaces, becomes
    ``\\xNN``. Backslashes are doubled so the escaping is unambiguous.
    """
    parts: list[str] = []
    for byte in data:
        if byte == 0x5C:  # backslash
            parts.append("\\\\")
        elif 0x21 <= byte <= 0x7E:
            parts.append(chr(byte))
        else:
            parts.append(f"\\x{byte:02x}")
    return "".join(parts)


def truncate(text: str, max_length: int | None) -> str:
    """Shorten ``text`` to ``max_length`` characters, marking that it was cut."""
    if max_length is None or len(text) <= max_length:
        return text
    # Size the marker for the worst case first; the real hidden count can only
    # have the same number of digits or fewer, so the result never exceeds max_length.
    keep = max(1, max_length - len(f"…(+{len(text)} chars)"))
    return f"{text[:keep]}…(+{len(text) - keep} chars)"


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------


def format_timestamp(timestamp: float | None) -> str | None:
    """Format a capture timestamp as ISO 8601 UTC, e.g. ``2024-01-01T12:00:00.250000Z``."""
    if timestamp is None:
        return None
    try:
        moment = datetime.fromtimestamp(timestamp, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return f"out-of-range timestamp ({timestamp!r})"
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "unknown"
    if seconds < 1:
        return f"{seconds * 1000:.1f} ms"
    if seconds < 60:
        return f"{seconds:.2f} s"
    minutes, secs = divmod(seconds, 60)
    if minutes < 60:
        return f"{int(minutes)} min {secs:04.1f} s"
    hours, minutes = divmod(minutes, 60)
    return f"{int(hours)} h {int(minutes):02d} min {secs:04.1f} s"


def format_bytes(count: int) -> str:
    size = float(count)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GiB"  # pragma: no cover - loop always returns


def format_percent(part: int | float, whole: int | float) -> str:
    if not whole:
        return "-"
    return f"{100 * part / whole:.1f}%"


def safe_ratio(part: int | float, whole: int | float) -> float | None:
    """Return ``part / whole`` rounded for reports, or None when undefined."""
    if not whole:
        return None
    value = part / whole
    return round(value, 4) if math.isfinite(value) else None


def utc_now_iso() -> str:
    return datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Safe report writing
# ---------------------------------------------------------------------------


class ReportWriteError(Exception):
    """Raised when a report cannot be written to the requested location."""


def write_report_file(
    destination: str | Path,
    content: str,
    *,
    overwrite: bool = False,
    protected_paths: Iterable[str | Path] = (),
) -> Path:
    """Write ``content`` to ``destination`` without clobbering anything by accident.

    * An existing file is never replaced unless ``overwrite`` is True.
    * ``protected_paths`` (the input capture) can never be the destination.
    * New files are created with owner-only permissions on POSIX systems,
      because reports contain addresses and domain names from the capture.
    * When overwriting, the new report is written to a temporary file first
      and then moved into place, so a failure never leaves a half-written report.
    """
    path = Path(destination)
    if path.name in ("", ".", ".."):
        raise ReportWriteError("the output path must name a file")
    if path.is_dir():
        raise ReportWriteError(f"the output path is a directory: {sanitize_text(path)}")

    for protected in protected_paths:
        if _same_file(path, Path(protected)):
            raise ReportWriteError("refusing to write the report over the input capture file")

    parent = path.parent if str(path.parent) else Path(".")
    try:
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        raise ReportWriteError(f"cannot create the output directory: {_describe(exc)}") from exc

    data = content.encode("utf-8")
    if overwrite:
        _replace_atomically(path, parent, data)
    else:
        _create_exclusively(path, data)
    return path


def _create_exclusively(path: Path, data: bytes) -> None:
    # O_EXCL makes "create only if absent" a single atomic step, so there is no
    # window in which another file (or a symlink) could appear at the path.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        raise ReportWriteError(
            f"{sanitize_text(path)} already exists; choose another name or pass --overwrite"
        ) from None
    except OSError as exc:
        raise ReportWriteError(f"cannot create the report file: {_describe(exc)}") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
    except BaseException as exc:
        # Includes KeyboardInterrupt: never leave a partial report behind.
        path.unlink(missing_ok=True)
        if isinstance(exc, OSError):
            raise ReportWriteError(f"cannot write the report: {_describe(exc)}") from exc
        raise


def _replace_atomically(path: Path, parent: Path, data: bytes) -> None:
    try:
        descriptor, temp_name = tempfile.mkstemp(dir=parent, prefix=".netsentry-", suffix=".tmp")
    except OSError as exc:
        raise ReportWriteError(f"cannot write to the output directory: {_describe(exc)}") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        os.replace(temp_name, path)
    except BaseException as exc:
        Path(temp_name).unlink(missing_ok=True)
        if isinstance(exc, OSError):
            raise ReportWriteError(f"cannot write the report: {_describe(exc)}") from exc
        raise


def _same_file(first: Path, second: Path) -> bool:
    try:
        if first.exists() and second.exists():
            return os.path.samefile(first, second)
        return first.resolve() == second.resolve()
    except OSError:
        return False


def _describe(exc: OSError) -> str:
    return sanitize_text(exc.strerror or exc.__class__.__name__)
