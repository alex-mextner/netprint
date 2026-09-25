"""markers — well-known product words in a web page body, for rules to match (``http_marker``).

Titles are often useless ("Login", "Web", the device's own name for ESPHome), but the page
body usually names the software. A collector passes the first few KiB of ``/`` through
:func:`find` and stores the result as ``HttpService.markers``.
"""

from __future__ import annotations

import re

# marker -> pattern (case-insensitive) over the page body.
MARKERS: dict[str, str] = {
    "home-assistant": r"home-assistant-main|<ha-launch-screen|\bhass-frontend\b|home-assistant\.io",
    "esphome": r"<esp-app|esphome\.io|esp-web-tools|ESPHome Web Server|oi\.esphome\.io",
    "tasmota": r"\bTasmota\b|tasmota\.github\.io",
    "wled": r"\bWLED\b.*(?:kno\.wled\.ge|wled\.me)|<title>WLED",
    "shelly": r"\bshelly\b.*(?:cloud|allterco)|Shelly (?:Plus|Pro|Gen2|1PM|2\.5)",
    "mainsail": r"\bmainsail\b",
    "fluidd": r"\bfluidd\b",
    "moonraker": r"\bmoonraker\b",
    "klipper": r"\bklipper\b",
    "octoprint": r"\boctoprint\b",
    "creality": r"\bcreality\b",
    "snapmaker": r"\bsnapmaker\b",
    "miwifi": r"miwifi|xiaomi\.com/router|/cgi-bin/luci/web|小米路由器|xqsystem",
    "luci": r"/cgi-bin/luci|\bLuCI\b",
    "openwrt": r"\bOpenWrt\b",
    "kodi": r"\bKodi\b|chorus2",
    "jellyfin": r"\bjellyfin\b",
    "plex": r"\bplex\b",
    "synology": r"\bsynology\b|\bDSM\b.*synology",
    "hikvision": r"\bhikvision\b",
    "tuya": r"\btuya\b",
    "yandex-station": r"quasar\.yandex|yandex[- ]station",
    "node-red": r"\bnode-red\b",
    "grafana": r"\bgrafana\b",
    "proxmox": r"\bproxmox\b",
}
_COMPILED = {name: re.compile(pattern, re.I | re.S) for name, pattern in MARKERS.items()}
MAX_SCAN = 64 * 1024


def find(body: str) -> list[str]:
    """Names of every marker whose pattern occurs in the first 64 KiB of ``body``."""
    head = body[:MAX_SCAN]
    return [name for name, pattern in _COMPILED.items() if pattern.search(head)]
