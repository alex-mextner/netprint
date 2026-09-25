"""mac — MAC address helpers and the shipped IEEE OUI (MA-L) vendor table.

``data/oui.tsv.gz`` is the IEEE MA-L registry compacted to ``PREFIX<TAB>short vendor``
lines ("Apple", "Espressif", "Tuya Smart"). ``python -m netprint oui-update`` rebuilds it
from https://standards-oui.ieee.org/oui/oui.csv.

A locally administered address (bit 1 of the first octet set) is not in any registry:
phones, watches, tablets and laptops use one per Wi-Fi network ("private Wi-Fi address",
"randomized MAC"), and so do VMs and containers. Such a MAC has no vendor, rotates, and
is a signal in itself.
"""

from __future__ import annotations

import csv
import gzip
import io
import re
from functools import lru_cache
from importlib import resources

_PKG = __package__ or "netprint"  # works when vendored as <pkg>._vendor.netprint too

_HEX = re.compile(r"[0-9a-fA-F]")

# Well-known locally administered prefixes that are NOT phones.
LAA_PREFIXES = {
    "02:42": "Docker container",
    "52:54:00": "QEMU/KVM virtual machine",
    "02:00:4c": "Microsoft loopback/virtual",
    "0a:00:27": "VirtualBox host-only adapter",
}


def normalize(mac: str) -> str | None:
    """'AA-BB-CC-DD-EE-FF' / 'aabb.ccdd.eeff' / 'aabbccddeeff' -> 'aa:bb:cc:dd:ee:ff'."""
    digits = "".join(_HEX.findall(mac or ""))
    stripped = re.sub(r"[\s:.\-_]", "", mac or "")
    if len(digits) != 12 or len(stripped) != 12:
        return None
    digits = digits.lower()
    return ":".join(digits[i : i + 2] for i in range(0, 12, 2))


def is_locally_administered(mac: str) -> bool:
    norm = normalize(mac)
    return bool(norm and int(norm[:2], 16) & 0x02)


def is_multicast(mac: str) -> bool:
    norm = normalize(mac)
    return bool(norm and int(norm[:2], 16) & 0x01)


def laa_kind(mac: str) -> str | None:
    """A known non-phone use of a locally administered prefix, if any."""
    norm = normalize(mac) or ""
    for prefix, kind in LAA_PREFIXES.items():
        if norm.startswith(prefix):
            return kind
    return None


def _read_table(data: bytes) -> dict[str, str]:
    table: dict[str, str] = {}
    for line in gzip.decompress(data).decode("utf-8").splitlines():
        prefix, _, vendor = line.partition("\t")
        if prefix and vendor:
            table[prefix] = vendor
    return table


@lru_cache(maxsize=1)
def oui_table() -> dict[str, str]:
    try:
        raw = resources.files(_PKG).joinpath("data", "oui.tsv.gz").read_bytes()
    except (FileNotFoundError, OSError):
        return {}
    return _read_table(raw)


def vendor(mac: str) -> str | None:
    """The registered vendor of a MAC (None for locally administered or unknown ones)."""
    norm = normalize(mac)
    if not norm or is_locally_administered(norm):
        return None
    return oui_table().get(norm.replace(":", "")[:6].upper())


_SUFFIXES = re.compile(
    r"(?:[,.]\s*|\s+)(inc|incorporated|corp|corporation|co|company|ltd|limited|llc|gmbh|ag|sa|"
    r"s\.a|bv|b\.v|oy|ab|as|srl|spa|pte|pty|plc|kg|kk|nv|sas|sarl|s\.p\.a|co\.,\s*ltd|holdings|"
    r"international|electronics?|technology|technologies|tech|communication|communications|"
    r"group|industrial|industries|manufacturing|intl|shenzhen|guangdong|beijing|shanghai)\b\.?",
    re.I,
)
_PLACES = re.compile(
    r"^(shenzhen|beijing|shanghai|guangzhou|guangdong|hangzhou|zhejiang|jiangsu|suzhou|hunan|"
    r"fujian|xiamen|dongguan|wuhan|chengdu|nanjing|qingdao|tianjin|taiwan|hong kong)\s+",
    re.I,
)


def shorten_vendor(name: str) -> str:
    """'Apple, Inc.' -> 'Apple'; 'Espressif Inc.' -> 'Espressif'."""
    text = " ".join(name.replace('"', "").replace("，", ",").replace("．", ".").split())
    text = _PLACES.sub("", text).strip() or text
    if text.isupper() and len(text) > 4:
        text = " ".join(w if len(w) <= 3 else w.capitalize() for w in text.split())
    previous = None
    while previous != text:
        previous = text
        text = _SUFFIXES.sub("", text).strip(" ,.-")
    return (text or name.strip())[:40]


def compact_ieee_csv(csv_text: str) -> dict[str, str]:
    """IEEE ``oui.csv`` -> {PREFIX: short vendor}."""
    table: dict[str, str] = {}
    for row in csv.reader(io.StringIO(csv_text)):
        if len(row) < 3 or row[0] == "Registry":
            continue
        prefix = row[1].strip().upper()
        if re.fullmatch(r"[0-9A-F]{6}", prefix):
            table[prefix] = shorten_vendor(row[2])
    return table


def encode_table(table: dict[str, str]) -> bytes:
    body = "".join(f"{k}\t{v}\n" for k, v in sorted(table.items()))
    return gzip.compress(body.encode("utf-8"), mtime=0)
