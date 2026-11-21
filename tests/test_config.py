"""Threshold configuration: defaults, overrides and strict validation."""

from __future__ import annotations

import json

import pytest

from netsentry.config import ConfigError, DetectionConfig, load_config


def test_defaults_round_trip_through_json():
    data = json.loads(json.dumps(DetectionConfig().to_dict()))
    assert DetectionConfig.from_dict(data) == DetectionConfig()


def test_partial_override_keeps_other_defaults():
    config = DetectionConfig.from_dict(
        {"port_scan": {"min_distinct_ports": 50}, "disabled_rules": ["ns-dns-002"]}
    )
    assert config.port_scan.min_distinct_ports == 50
    assert config.port_scan.window_seconds == 60.0
    assert config.host_sweep == DetectionConfig().host_sweep
    assert config.disabled_rules == ("NS-DNS-002",)
    assert not config.is_enabled("NS-DNS-002")


def test_integer_accepted_for_float_setting():
    config = DetectionConfig.from_dict({"port_scan": {"window_seconds": 30}})
    assert config.port_scan.window_seconds == 30.0


def test_port_maps_and_lists():
    config = DetectionConfig.from_dict(
        {
            "unusual_ports": {"watched_ports": {"8888": "Lab C2 port"}},
            "repeated_connections": {"sensitive_ports": [22, 22, 2222]},
        }
    )
    assert config.unusual_ports.watched_ports == {8888: "Lab C2 port"}
    assert config.repeated_connections.sensitive_ports == (22, 2222)


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ([], "JSON object"),
        ({"portscan": {}}, "unknown configuration section"),
        ({"port_scan": {"min_ports": 3}}, "unknown key"),
        ({"port_scan": []}, "must be a JSON object"),
        ({"port_scan": {"min_distinct_ports": True}}, "not true/false"),
        ({"port_scan": {"min_distinct_ports": 2.5}}, "whole number"),
        ({"port_scan": {"min_distinct_ports": 0}}, "at least 1"),
        ({"port_scan": {"window_seconds": -1}}, "greater than 0"),
        ({"port_scan": {"window_seconds": "60"}}, "must be a number"),
        ({"port_scan": {"max_success_ratio": 1.5}}, "between 0 and 1"),
        ({"high_volume": {"min_share_of_capture": -0.1}}, "between 0 and 1"),
        ({"unusual_ports": {"watched_ports": {"70000": "x"}}}, "invalid port"),
        ({"unusual_ports": {"watched_ports": {"80": ""}}}, "reason"),
        ({"unusual_ports": {"watched_ports": [80]}}, "object mapping"),
        ({"repeated_connections": {"sensitive_ports": ["ssh"]}}, "invalid port"),
        ({"disabled_rules": "NS-SCAN-001"}, "list of rule identifiers"),
    ],
)
def test_invalid_values_are_rejected(data, message):
    with pytest.raises(ConfigError, match=message):
        DetectionConfig.from_dict(data)


def test_load_config_errors(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.json")
    broken = tmp_path / "broken.json"
    broken.write_text('{"port_scan": ')
    with pytest.raises(ConfigError, match="not valid JSON"):
        load_config(broken)


def test_load_config_file(tmp_path):
    path = tmp_path / "ok.json"
    path.write_text(json.dumps({"dns": {"long_name_length": 120}}))
    assert load_config(path).dns.long_name_length == 120
