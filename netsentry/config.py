"""Detection thresholds and their validation.

Every number a detection rule uses lives here, with a default chosen to be
conservative (prefer missing a borderline case over raising a false alarm).
Users can override any value with a JSON file::

    {
      "disabled_rules": ["NS-DNS-002"],
      "port_scan": {"min_distinct_ports": 30},
      "dns": {"long_name_length": 120}
    }

Unknown sections or keys are rejected rather than ignored, so a typo cannot
silently leave a threshold at a value the user did not intend.
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class ConfigError(ValueError):
    """Raised when a threshold configuration file is invalid."""


@dataclass(frozen=True)
class PortScanSettings:
    """NS-SCAN-001: one source probing many ports on one destination."""

    window_seconds: float = 60.0
    min_distinct_ports: int = 20
    # If replies are visible and more than this fraction of probed ports
    # answered positively, the activity looks like a client using many real
    # services, so it is suppressed instead of reported.
    max_success_ratio: float = 0.5


@dataclass(frozen=True)
class HostSweepSettings:
    """NS-SCAN-002: one source probing the same port on many destinations."""

    window_seconds: float = 60.0
    min_distinct_hosts: int = 30
    max_success_ratio: float = 0.5


@dataclass(frozen=True)
class RepeatedConnectionSettings:
    """NS-CONN-001: many distinct SYN attempts to one destination port."""

    window_seconds: float = 60.0
    min_attempts: int = 10
    # Remote-access and file-sharing logins (FTP, SSH, Telnet, SMB, RDP, VNC),
    # where many new connections from one client is a common password-guessing
    # pattern. These raise the severity to MEDIUM. Databases and mail are left
    # out on purpose: applications and mail relays legitimately open many short
    # connections to them. Add them here if that is unusual on your network.
    sensitive_ports: tuple[int, ...] = (21, 22, 23, 445, 3389, 5900)
    # For non-sensitive ports, many *accepted* connections are normal client
    # behaviour (for example polling an API), so they are suppressed when more
    # than this fraction of attempts were accepted.
    max_accepted_ratio: float = 0.5


@dataclass(frozen=True)
class FailedConnectionSettings:
    """NS-CONN-002: a source whose connection attempts are mostly refused."""

    window_seconds: float = 300.0
    min_refused_attempts: int = 10
    min_refused_ratio: float = 0.5


def _default_watched_ports() -> dict[int, str]:
    return {
        2323: "Alternate Telnet port widely targeted by IoT botnets such as Mirai.",
        4444: "Default listener port for common penetration-testing payload handlers "
        "(for example Metasploit).",
        5555: "Android Debug Bridge (ADB) over TCP; an exposed ADB service allows "
        "remote control of a device.",
        6667: "Default IRC port; IRC is used legitimately but has a long history as a "
        "botnet command-and-control channel.",
        31337: "Port historically associated with backdoor tools ('elite').",
    }


def _default_public_destination_ports() -> dict[int, str]:
    return {
        135: "Microsoft RPC endpoint mapper; normally kept inside a network.",
        139: "NetBIOS session service (file sharing); normally kept inside a network.",
        445: "SMB file sharing; SMB traffic to internet addresses is unusual and has "
        "been abused by worms and data theft.",
        3389: "Remote Desktop Protocol; directly reachable RDP is a frequent intrusion path.",
        5900: "VNC remote desktop; often deployed without strong authentication.",
    }


@dataclass(frozen=True)
class UnusualPortSettings:
    """NS-PORT-001: traffic to ports that merit a closer look."""

    # Flagged for any destination address.
    watched_ports: dict[int, str] = field(default_factory=_default_watched_ports)
    # Flagged only when the destination is a public (globally routable) address.
    public_destination_ports: dict[int, str] = field(
        default_factory=_default_public_destination_ports
    )


@dataclass(frozen=True)
class HighVolumeSettings:
    """NS-VOL-001: unusually high packet counts from one source."""

    window_seconds: float = 10.0
    min_packets_in_window: int = 10_000
    # A single source producing at least this share of all IP packets...
    min_share_of_capture: float = 0.8
    # ...as long as it sent at least this many packets (tiny captures are ignored).
    min_packets_for_share: int = 1_000


@dataclass(frozen=True)
class DnsSettings:
    """NS-DNS-001..004: DNS heuristics."""

    rate_window_seconds: float = 60.0
    min_queries_in_window: int = 200
    long_name_length: int = 100  # bytes; the DNS maximum is 253
    long_label_length: int = 50  # bytes; the DNS maximum is 63
    min_long_names_for_low: int = 10  # fewer distinct long names -> INFO
    min_responses_for_failure_ratio: int = 20
    min_failure_ratio: float = 0.5
    min_repeated_queries: int = 20


@dataclass(frozen=True)
class DetectionConfig:
    disabled_rules: tuple[str, ...] = ()
    port_scan: PortScanSettings = field(default_factory=PortScanSettings)
    host_sweep: HostSweepSettings = field(default_factory=HostSweepSettings)
    repeated_connections: RepeatedConnectionSettings = field(
        default_factory=RepeatedConnectionSettings
    )
    failed_connections: FailedConnectionSettings = field(default_factory=FailedConnectionSettings)
    unusual_ports: UnusualPortSettings = field(default_factory=UnusualPortSettings)
    high_volume: HighVolumeSettings = field(default_factory=HighVolumeSettings)
    dns: DnsSettings = field(default_factory=DnsSettings)

    def is_enabled(self, rule_id: str) -> bool:
        return rule_id not in self.disabled_rules

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-compatible representation (used in reports and templates)."""
        result: dict[str, Any] = {"disabled_rules": list(self.disabled_rules)}
        for section in _SECTION_NAMES:
            settings = getattr(self, section)
            values: dict[str, Any] = {}
            for item in dataclasses.fields(settings):
                value = getattr(settings, item.name)
                if isinstance(value, tuple):
                    value = list(value)
                elif isinstance(value, dict):
                    value = {str(port): text for port, text in sorted(value.items())}
                values[item.name] = value
            result[section] = values
        return result

    @classmethod
    def from_dict(cls, data: Any) -> DetectionConfig:
        if not isinstance(data, dict):
            raise ConfigError("the configuration must be a JSON object")
        unknown = sorted(set(data) - {"disabled_rules", *_SECTION_NAMES})
        if unknown:
            raise ConfigError(f"unknown configuration section(s): {', '.join(unknown)}")

        overrides: dict[str, Any] = {}
        if "disabled_rules" in data:
            rules = data["disabled_rules"]
            if not isinstance(rules, list) or not all(isinstance(r, str) for r in rules):
                raise ConfigError("'disabled_rules' must be a list of rule identifiers")
            overrides["disabled_rules"] = tuple(r.strip().upper() for r in rules)

        defaults = cls()
        for section in _SECTION_NAMES:
            if section in data:
                overrides[section] = _build_section(
                    section, getattr(defaults, section), data[section]
                )
        return dataclasses.replace(defaults, **overrides)


_SECTION_NAMES = (
    "port_scan",
    "host_sweep",
    "repeated_connections",
    "failed_connections",
    "unusual_ports",
    "high_volume",
    "dns",
)


def load_config(path: str | Path) -> DetectionConfig:
    """Load and validate a JSON threshold file."""
    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigError(f"configuration file not found: {config_path.name}")
    try:
        text = config_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"could not read configuration file: {exc.__class__.__name__}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError(
            f"configuration is not valid JSON (line {exc.lineno}: {exc.msg})"
        ) from exc
    return DetectionConfig.from_dict(data)


def _build_section(section: str, defaults: Any, values: Any) -> Any:
    if not isinstance(values, dict):
        raise ConfigError(f"section '{section}' must be a JSON object")
    known = {item.name for item in dataclasses.fields(defaults)}
    unknown = sorted(set(values) - known)
    if unknown:
        raise ConfigError(f"unknown key(s) in '{section}': {', '.join(unknown)}")
    changes = {
        name: _validate_value(f"{section}.{name}", getattr(defaults, name), value)
        for name, value in values.items()
    }
    return dataclasses.replace(defaults, **changes)


def _validate_value(name: str, default: Any, value: Any) -> Any:
    """Check ``value`` against the type and range implied by its default."""
    # bool is a subclass of int in Python, so it must be rejected explicitly.
    if isinstance(value, bool):
        raise ConfigError(f"'{name}' must be a number, not true/false")

    if isinstance(default, float):
        if not isinstance(value, int | float):
            raise ConfigError(f"'{name}' must be a number")
        number = float(value)
        if name.endswith("_ratio") or name.endswith("_share_of_capture"):
            if not 0.0 <= number <= 1.0:
                raise ConfigError(f"'{name}' must be between 0 and 1")
        elif not number > 0:
            raise ConfigError(f"'{name}' must be greater than 0")
        return number

    if isinstance(default, int):
        if not isinstance(value, int):
            raise ConfigError(f"'{name}' must be a whole number")
        if value < 1:
            raise ConfigError(f"'{name}' must be at least 1")
        return value

    if isinstance(default, tuple):
        if not isinstance(value, list):
            raise ConfigError(f"'{name}' must be a list of port numbers")
        return tuple(sorted({_validate_port(name, port) for port in value}))

    if isinstance(default, dict):
        if not isinstance(value, dict):
            raise ConfigError(f"'{name}' must be an object mapping port numbers to reasons")
        ports: dict[int, str] = {}
        for key, reason in value.items():
            port = _validate_port(name, key)
            if not isinstance(reason, str) or not reason.strip() or len(reason) > 300:
                raise ConfigError(f"'{name}' reason for port {port} must be text (1-300 chars)")
            ports[port] = reason.strip()
        return ports

    raise ConfigError(f"'{name}' cannot be configured")  # pragma: no cover - defensive


def _validate_port(name: str, value: Any) -> int:
    if isinstance(value, bool):
        raise ConfigError(f"'{name}' contains an invalid port: {value!r}")
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ConfigError(f"'{name}' contains an invalid port: {value!r}") from None
    if isinstance(value, float) or not 0 <= port <= 65535:
        raise ConfigError(f"'{name}' contains an invalid port: {value!r}")
    return port
