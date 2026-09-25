"""netprint: the fixture zoo, the engine's scoring rules and the rule-file validation."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

import netprint
import netprint.tables
from netprint import (
    Signals,
    canonical_brand,
    classify,
    compose,
    is_label,
    is_module_maker,
    load_db,
    load_naming,
)
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
    for key in (
        "display_name",
        "brand",
        "product",
        "model",
        "model_id",
        "friendly_name",
        "os",
        "firmware",
    ):
        if key in expect:
            assert getattr(result, key) == expect[key], f"{key}: {why}"
    if "service_ports" in expect:
        assert [s["port"] for s in result.services] == expect["service_ports"], why
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


# ── naming, brands, lookup tables ────────────────────────────────────────────
def test_canonical_brand() -> None:
    assert canonical_brand("Samsung Electronics Co.,Ltd") == "Samsung"
    assert canonical_brand("Яндекс") == "Yandex"
    assert canonical_brand("TUYA INC.") == "Tuya"
    assert canonical_brand("Micro-Star International Co., Ltd.") == "MSI"
    assert canonical_brand("Acme Widgets GmbH") == "Acme Widgets"
    for junk in ("moonraker", "integration", "", None, "AlexxIT"):
        assert canonical_brand(junk) is None, junk
    assert is_module_maker("Espressif") and is_module_maker("Chongqing Fugui Electronics")
    assert not is_module_maker("Apple") and not is_module_maker(None)


@pytest.mark.parametrize(
    "name, vocabulary, label",
    [
        ("Кухня", ["Google", "Chromecast HD"], True),
        ("Хромкаст", ["Google", "Chromecast HD"], False),
        ("Sam's MBP", ["Apple", "MacBook Pro 16″"], True),
        ("MacBook-Pro", ["Apple", "MacBook Pro 16″"], False),
        ("[TV] UE48J5500", ["Samsung", "TV 48″ J5500", "UE48J5500"], False),
        ("Television", ["Samsung", "TV 48″ J5500"], False),
        ("K1SE-0A1B", ["Creality", "K1 SE"], False),
        ("rd28_minet_a0f1", ["Xiaomi", "Mesh System", "RD28"], False),
        ("mini-kids", ["Yandex", "Station Mini 2"], True),
        (None, ["x"], False),
    ],
)
def test_is_label(name: str | None, vocabulary: list[str], label: bool) -> None:
    assert is_label(name, vocabulary) is label


def test_compose_and_overrides() -> None:
    assert compose("Google", "Chromecast HD", None, "Кухня", True) == "Google Chromecast «Кухня»"
    assert compose("Google", "Chromecast HD", None, "Хромкаст", False) == "Google Chromecast"
    assert compose("Yandex", "Yandex Station", None, None, False) == "Yandex Station"
    assert compose("Tuya", None, "smart plug", None, False) == "Tuya smart plug"
    assert compose(None, None, "Laptop", "SYNTH-WIN", True) == "SYNTH-WIN"
    assert compose(None, None, None, None, False) is None
    custom = load_naming({"templates": {"product_label": "{friendly} ({brand} {product})"}})
    assert compose("Apple", "iPad", None, "Kids", True, custom) == "Kids (Apple iPad)"


def test_apple_table_builder() -> None:
    records = [
        {"name": "MacBook Pro (16-inch, M4 Pro, Nov 2024)", "type": "MacBook Pro",
         "identifier": ["Mac16,7"], "key": "Mac16,7", "soc": "M4 Pro", "released": "2024-11-08"},
        {"name": "HomePod mini (China Mainland)", "type": "HomePod",
         "identifier": ["AudioAccessory5,1"], "key": "AudioAccessory5,1-CHN"},
        {"name": "HomePod mini", "type": "HomePod", "identifier": ["AudioAccessory5,1"],
         "key": "AudioAccessory5,1"},
        {"name": "iPad Pro 11-inch (M4) Wi-Fi", "type": "iPad Pro", "identifier": "iPad16,3",
         "key": "iPad16,3", "soc": "M4"},
        {"name": "Apple TV 4K (3rd generation) Wi-Fi", "type": "Apple TV",
         "identifier": ["AppleTV14,1"], "key": "AppleTV14,1"},
        {"name": "Mac mini (2018)", "type": "Mac mini", "identifier": ["Macmini8,1"],
         "released": "2018-11-07"},
        {"name": "USB cable", "type": "Accessories", "identifier": []},
        "not a record",
    ]  # fmt: skip
    table = netprint.tables.build_apple_table(records)
    assert table["Mac16,7"]["model"] == "MacBook Pro 16″ (M4 Pro, 2024)"
    assert table["Mac16,7"]["product"] == "MacBook Pro 16″" and table["Mac16,7"]["kind"] == "laptop"
    assert table["AudioAccessory5,1"]["name"] == "HomePod mini"
    assert table["iPad16,3"]["model"] == "iPad Pro 11″ (M4, Wi-Fi)"
    assert table["AppleTV14,1"]["product"] == "Apple TV 4K (3rd generation)"
    assert table["Macmini8,1"]["model"] == "Mac mini (2018)"
    assert set(table) == {"Mac16,7", "AudioAccessory5,1", "iPad16,3", "AppleTV14,1", "Macmini8,1"}
    assert netprint.tables.lookup("apple", "mac16,7") is not None  # the shipped table
    assert netprint.tables.lookup("apple", "") is None
    assert "apple" in netprint.tables.names() and "yandex" in netprint.tables.names()


def test_apple_update_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = tmp_path / "main.json"
    src.write_text(json.dumps([{"name": "iPhone 15 Pro", "type": "iPhone", "identifier": ["x"]}]))
    assert cli_main(["apple-update", "--json", str(src)]) == 1  # too few to be the real list


@pytest.mark.parametrize(
    "rule, message",
    [
        ({"when": {"hostname": "x", "lookup": {"table": "nope", "key": "{x}"}}}, "unknown table"),
        ({"when": {"hostname": "x", "lookup": {"table": "apple"}}}, "lookup must be"),
        (
            {"when": {"hostname": "x", "lookup": {"table": "apple", "key": "k", "match": 1}}},
            "match",
        ),
        (
            {"when": {"hostname": "x"}, "unless": {"lookup": {"table": "apple", "key": "k"}}},
            "unless",
        ),
        ({"when": {"hostname": "x"}, "product": 5}, "template"),
        ({"when": {"hostname": "x"}, "services": [{"title": "no port"}]}, "services"),
    ],
)
def test_bad_lookup_rules(tmp_path: Path, rule: dict[str, Any], message: str) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"rules": [{"id": "x.y", "category": "tv", **rule}]}))
    with pytest.raises(RuleError, match=message):
        load_db([path])


def test_lookup_rule_and_services(tmp_path: Path) -> None:
    path = tmp_path / "r.json"
    rule = {
        "id": "t.lookup",
        "category": "speaker",
        "weight": 0.9,
        "when": {
            "hostname": "^box-(?P<p>\\w+)$",
            "lookup": {"table": "yandex", "key": "{p}", "match": {"kind": "^speaker$"}},
        },
        "vendor": "{lookup.brand}",
        "product": "{lookup.product}",
        "services": [{"port": 8080, "title": "UI of {lookup.product}"}],
    }
    path.write_text(json.dumps({"rules": [rule]}))
    db = load_db([path])
    r = classify(Signals(hostnames=["box-cucumber"]), db)
    assert (r.brand, r.product) == ("Yandex", "Station Midi")
    assert r.services == [{"port": 8080, "scheme": "http", "title": "UI of Station Midi"}]
    assert classify(Signals(hostnames=["box-goya"]), db).product is None  # a TV, not matched
    assert classify(Signals(hostnames=["box-nothing"]), db).product is None


def test_cli_prints_facts(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    f = tmp_path / "d.json"
    f.write_text(json.dumps({"mdns": [{"type": "_device-info._tcp", "txt": {"model": "Mac16,7"}}]}))
    assert cli_main(["classify", str(f)]) == 0
    assert "model_id=Mac16,7" in capsys.readouterr().out
