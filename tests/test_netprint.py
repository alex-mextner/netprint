"""netprint: the fixture zoo, the engine's scoring rules and the rule-file validation."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

import netprint
from netprint import Signals, classify, load_db
from netprint.__main__ import main as cli_main
from netprint.engine import RuleError
from netprint.mac import compact_ieee_csv, is_locally_administered, normalize, vendor
from netprint.names import clean, is_generic, pick_display_name

FIXTURES = Path(__file__).parent / "fixtures"


def _zoo() -> list[tuple[str, dict[str, Any]]]:
    out = []
    for path in sorted((FIXTURES / "devices").glob("*.json")):
        data = json.loads(path.read_text("utf-8"))
        for i, item in enumerate(data if isinstance(data, list) else [data]):
            out.append((f"{path.stem}[{i}] {item.get('comment', '')[:40]}", item))
    return out


ZOO = _zoo()


@pytest.mark.parametrize("item", [z[1] for z in ZOO], ids=[z[0] for z in ZOO])
def test_zoo(item: dict[str, Any]) -> None:
    expect = item["expect"]
    result = classify(Signals.from_dict(item))
    why = json.dumps(result.to_dict(), ensure_ascii=False, indent=1)
    assert result.category == expect["category"], why
    if "label" in expect:
        assert result.label == expect["label"], why
    if "icon" in expect:
        assert result.icon == expect["icon"], why
    if "display_name" in expect:
        assert result.display_name == expect["display_name"], why
    if "min_confidence" in expect:
        assert result.confidence >= expect["min_confidence"], why
    if "max_confidence" in expect:
        assert result.confidence <= expect["max_confidence"], why
    if "network_gear" in expect:
        assert result.network_gear is expect["network_gear"], why
    if result.category != "unknown":
        assert result.evidence and all(-1 < e.weight < 1 for e in result.evidence)
        assert 0 < result.confidence < 1


def test_zoo_covers_most_categories() -> None:
    seen = {z[1]["expect"]["category"] for z in ZOO}
    missing = set(load_db().categories) - seen
    assert len(missing) <= 1, f"add fixtures for: {sorted(missing)}"


def test_fixtures_are_synthetic() -> None:
    """Fixture MACs must end in 00:00:NN (a made-up NIC part); no real LAN addresses."""
    mac_re = re.compile(r"(?<![0-9A-Fa-f:])([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})(?![0-9A-Fa-f:])")
    ip_re = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
    for path in FIXTURES.rglob("*.json"):
        text = path.read_text("utf-8")
        for mac in mac_re.findall(text):
            assert re.fullmatch(r"([0-9a-f]{2}:){3}00:00:[0-9a-f]{2}", mac.lower()), (path, mac)
        for ip in ip_re.findall(text):
            assert re.match(r"^(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)", ip), (path, ip)


def test_rules_load_and_lint(capsys: pytest.CaptureFixture[str]) -> None:
    db = load_db()
    assert len(db.rules) > 200
    ids = [r.id for r in db.rules]
    assert len(ids) == len(set(ids))
    assert cli_main(["lint"]) == 0
    assert "ok:" in capsys.readouterr().out
    for cat in db.categories.values():
        assert cat.icon.startswith("mdi:")


def test_noisy_or_and_negative_weight(tmp_path: Path) -> None:
    rules = tmp_path / "r.json"
    rules.write_text(
        json.dumps(
            {
                "rules": [
                    {"id": "t.a", "category": "tv", "weight": 0.6, "when": {"hostname": "^zz-a"}},
                    {"id": "t.b", "category": "tv", "weight": 0.6, "when": {"hostname": "zz-.*b$"}},
                    {"id": "t.c", "category": "tv", "weight": -0.5, "when": {"hostname": "nope"}},
                ]
            }
        )
    )
    db = load_db([rules])
    r = classify(Signals(hostnames=["zz-ab"]), db)
    assert r.category == "tv" and r.confidence == pytest.approx(0.84)
    r = classify(Signals(hostnames=["zz-ab-nope"]), db)
    assert r.confidence == pytest.approx(0.3)


def test_local_rules_override_shipped(tmp_path: Path) -> None:
    rules = tmp_path / "override.json"
    rules.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "oui.tuya.plug",
                        "category": "iot-plug",
                        "weight": 0,
                        "when": {"vendor": "^Tuya"},
                    }
                ]
            }
        )
    )
    db = load_db([rules])
    assert classify(Signals(vendor="Tuya Smart"), db).category == "iot-light"


def test_unless_and_templates() -> None:
    r = classify(Signals(hostnames=["docking-station-12"]))
    assert r.category != "speaker"
    tv = classify(
        Signals.from_dict(
            {"ssdp": [{"model_name": "UE55TU7100", "manufacturer": "Samsung Electronics"}]}
        )
    )
    assert tv.label == "Samsung TV UE55TU7100"
    assert any("UE55TU7100" in e.detail for e in tv.evidence)


@pytest.mark.parametrize(
    "rule, message",
    [
        ({"id": "Bad", "category": "tv", "when": {"hostname": "x"}}, "lowercase"),
        ({"id": "x.y", "category": "toaster", "when": {"hostname": "x"}}, "unknown category"),
        ({"id": "x.y", "category": "tv", "when": {}}, "non-empty"),
        ({"id": "x.y", "category": "tv", "when": {"colour": "x"}}, "unknown condition"),
        ({"id": "x.y", "category": "tv", "when": {"hostname": "("}}, "bad regex"),
        ({"id": "x.y", "category": "tv", "weight": 1.5, "when": {"hostname": "x"}}, "weight"),
        ({"id": "x.y", "category": "tv", "when": {"ssdp": {"colour": "x"}}}, "ssdp field"),
        ({"id": "x.y", "category": "tv", "when": {"hostname": "x"}, "icon": "tv"}, "mdi:"),
        ({"id": "x.y", "category": "tv", "when": {"hostname": "x"}, "extra_key": 1}, "unknown key"),
    ],
)
def test_bad_rules_are_rejected(tmp_path: Path, rule: dict[str, Any], message: str) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"rules": [rule]}))
    with pytest.raises(RuleError, match=message):
        load_db([path])


def test_mac_helpers() -> None:
    assert normalize("AA-BB-CC-00-00-01") == "aa:bb:cc:00:00:01"
    assert normalize("aabb.cc00.0001") == "aa:bb:cc:00:00:01"
    assert normalize("nope") is None
    assert is_locally_administered("da:00:00:00:00:01")
    assert not is_locally_administered("00:03:93:00:00:01")
    assert vendor("00:03:93:00:00:01") == "Apple"
    assert vendor("da:00:00:00:00:01") is None
    csv_text = (
        "Registry,Assignment,Organization Name,Organization Address\n"
        'MA-L,0003AB,"Example, Inc.",x\n'
    )
    assert compact_ieee_csv(csv_text) == {"0003AB": "Example"}


def test_names() -> None:
    assert clean("Sams-iPhone.local.") == "Sams-iPhone"
    assert clean("printer.lan") == "printer"
    for generic in ("android-1a2b3c4d5e6f7a8b", "ESP_1A2B3C", "wlan0", "192-168-1-20", "localhost"):
        assert is_generic(generic), generic
    for good in ("Sams-iPhone", "kitchen-light", "DESKTOP-4F7G2QK", "mini-kitchen"):
        assert not is_generic(good), good
    s = Signals(hostnames=["android-1a2b3c4d5e6f7a8b"])
    assert pick_display_name(s, "Android device", None, "Phone") == "Android device"
    assert pick_display_name(s, None, "Xiaomi", "Phone") == "Xiaomi phone"
    assert pick_display_name(s, None, None, None, alias="Mum's phone") == "Mum's phone"


def test_markers() -> None:
    body = "<html><esp-app></esp-app><script src=https://oi.esphome.io/v2/www.js></script>"
    assert netprint.find_markers(body) == ["esphome"]
    assert "mainsail" in netprint.find_markers("<title>Mainsail</title><div id=app>")


def test_fingerprint_ports() -> None:
    ports = netprint.fingerprint_ports()
    for p in (6053, 7125, 8123, 62078, 9100, 1961):
        assert p in ports


def test_cli_classify(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "d.json"
    f.write_text(json.dumps({"vendor": "Tuya Smart", "open_ports": [6668]}))
    assert cli_main(["classify", str(f), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out[0]["category"] == "iot-plug"
    assert cli_main(["categories"]) == 0
    assert "access-point" in capsys.readouterr().out


def test_unknown_signal_field_rejected() -> None:
    with pytest.raises(ValueError, match="colour"):
        Signals.from_dict({"colour": "red"})
