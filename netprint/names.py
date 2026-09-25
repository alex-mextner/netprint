"""names — clean up device names and pick the best one to show a human.

Names come from many places and most are noise: ``android-1f2e3d4c5b6a7980``,
``ESP_3A4B5C``, ``wlan0``, ``192-168-1-20``, a UUID. ``is_generic`` recognises those so a
friendlier name (a user-set mDNS instance name, an ESPHome ``friendly_name``, a UPnP
``friendlyName``) wins, and a device with no good name at all falls back to the model the
rules recognised ("Yandex Station Mini") or "<vendor> <category>".
"""

from __future__ import annotations

import re

from .signals import Signals

_LOCAL_SUFFIX = re.compile(
    r"\.(local|lan|home|localdomain|home\.arpa|internal|intranet|domain|router|dlink|fritz\.box)\.?$",
    re.I,
)

_GENERIC = [
    re.compile(p, re.I)
    for p in (
        r"^android[-_]?[0-9a-f]{6,}$",
        r"^(esp|espressif|esp32|esp8266)[-_]?[0-9a-f]{4,12}$",
        r"^(localhost|unknown|none|null|\*|-+|n/a)$",
        r"^\d{1,3}([.-]\d{1,3}){3}$",
        r"^(ip|host|dhcp|client|device|pc|nobody)[-_]?\d{1,3}([.-]\d{1,3}){0,3}$",
        r"^[0-9a-f]{12}$",
        r"^([0-9a-f]{2}[-:_]){5}[0-9a-f]{2}$",
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        r"^[0-9a-f]{16,}$",
        r"^(wlan|eth|en|wl|br|lan)\d*$",
        r"^lwip\d*$",
        r"^(tuya|wifi|smart|iot)[-_]?(device|module|plug|socket)?[-_]?[0-9a-f]{0,6}$",
        # "<model>-<serial/uuid>": yandexmini-2-M000000000000X, U1-0000000000000000XX00,
        # Chromecast-HD-0123456789abcdef..., YandexIOReceiver-M000000000000X
        r"^[a-z0-9]+([-_][a-z0-9]{1,3})?[-_](?=[0-9a-z]*\d)[0-9a-z]{12,}$",
        r"^[a-z0-9]+[-_]+[a-z0-9]+[-_]+(?=[0-9a-z]*\d)[0-9a-z]{16,}$",
    )
]


def clean(name: str) -> str:
    """Strip local DNS suffixes, surrounding junk and a trailing dot."""
    text = " ".join(str(name).replace("\x00", "").split()).strip().strip(".")
    previous = None
    while previous != text:
        previous = text
        text = _LOCAL_SUFFIX.sub("", text).strip().strip(".")
    return text


def is_generic(name: str | None) -> bool:
    if not name:
        return True
    text = clean(name)
    if len(text) < 2:
        return True
    return any(p.match(text) for p in _GENERIC)


def friendly_names(signals: Signals) -> list[str]:
    """User-facing names a device announces about itself, best first."""
    out: list[str] = []
    for key in ("miwifi.name", "name"):
        if signals.extra.get(key):
            out.append(signals.extra[key])
    for svc in signals.mdns:
        for txt_key in ("friendly_name", "fn", "n", "name"):
            if svc.txt.get(txt_key):
                out.append(svc.txt[txt_key])
    for ssdp in signals.ssdp:
        if ssdp.friendly_name:
            out.append(ssdp.friendly_name)
    preferred = (
        "_device-info._tcp",
        "_companion-link._tcp",
        "_airplay._tcp",
        "_raop._tcp",
        "_googlecast._tcp",
        "_yandexio._tcp",
        "_smb._tcp",
        "_workstation._tcp",
    )
    for kind in preferred:
        for svc in signals.mdns:
            if svc.type.lower() == kind and svc.name:
                name = svc.name.split("@", 1)[-1] if kind == "_raop._tcp" else svc.name
                if kind == "_workstation._tcp":
                    name = re.sub(r"\s*\[[0-9a-f:]{17}\]$", "", name, flags=re.I)
                out.append(name)
    return [clean(n) for n in out if n and not is_generic(n)]


_MODEL_TAG = re.compile(r"^[A-Za-z][A-Za-z0-9]{1,15}[-_][0-9A-Fa-f]{4,6}$")


def _with_model(name: str, label: str | None) -> str:
    """A vendor-default "MODEL-1A2B" name reads better with the recognised model:
    "Creality K1 SE (K1SE-0A1B)"."""
    if label and _MODEL_TAG.match(name) and label.lower() not in name.lower():
        return f"{label} ({name})"
    return name


def pick_display_name(
    signals: Signals,
    label: str | None,
    vendor: str | None,
    category_label: str | None,
    alias: str | None = None,
) -> str | None:
    """alias > a name given in a management system (``extra["name"]``, e.g. Home Assistant) >
    first non-generic hostname > announced friendly name > recognised model >
    "<vendor> <category>" > category > None."""
    if alias and alias.strip():
        return alias.strip()
    managed = signals.extra.get("name")
    if managed and not is_generic(managed):
        return _with_model(clean(managed), label)
    for name in signals.all_names():
        if not is_generic(name):
            return _with_model(clean(name), label)
    friendly = friendly_names(signals)
    if friendly:
        return friendly[0]
    if label:
        return label
    if vendor and category_label:
        kind = category_label if re.search(r"[A-Z]", category_label[1:]) else category_label.lower()
        return f"{vendor} {kind}"
    return vendor or category_label
