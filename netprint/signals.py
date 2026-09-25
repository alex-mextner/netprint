"""signals — everything netprint can look at, as plain dataclasses that round-trip to JSON.

A collector (an mDNS browser, an SSDP listener, a port scanner, a router API, a DHCP log
reader...) fills in whatever it observed; every field is optional. ``Signals.from_dict``
accepts the same shape the fixtures in ``tests/fixtures`` use, so a device can be described
in a JSON file and classified with ``python -m netprint classify device.json``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Any

SSDP_FIELDS = (
    "server",
    "st",
    "usn",
    "location",
    "friendly_name",
    "manufacturer",
    "model_name",
    "model_number",
    "model_description",
    "device_type",
)


@dataclass
class MdnsService:
    """One DNS-SD service instance: ``_airplay._tcp`` named "Living Room" with TXT records."""

    type: str
    name: str | None = None
    port: int | None = None
    txt: dict[str, str] = field(default_factory=dict)


@dataclass
class SsdpDevice:
    """An SSDP answer (headers) and, when fetched, its UPnP device description."""

    server: str | None = None
    st: str | None = None
    usn: str | None = None
    location: str | None = None
    friendly_name: str | None = None
    manufacturer: str | None = None
    model_name: str | None = None
    model_number: str | None = None
    model_description: str | None = None
    device_type: str | None = None

    def get(self, key: str) -> str | None:
        value = getattr(self, key, None)
        return value if isinstance(value, str) else None


@dataclass
class HttpService:
    """A web server found on the device: its port, page title, Server header, favicon hash
    (md5 hex of the favicon bytes) and well-known markers seen in the page body."""

    port: int
    title: str | None = None
    server: str | None = None
    favicon_hash: str | None = None
    markers: list[str] = field(default_factory=list)
    status: int | None = None


@dataclass
class Signals:
    """What was observed about ONE device. Every field is optional."""

    mac: str | None = None
    vendor: str | None = None  # OUI vendor; looked up from the MAC when None
    hostnames: list[str] = field(default_factory=list)  # DHCP, mDNS, reverse DNS, router
    netbios: list[str] = field(default_factory=list)
    mdns: list[MdnsService] = field(default_factory=list)
    ssdp: list[SsdpDevice] = field(default_factory=list)
    http: list[HttpService] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    ttl: int | None = None  # IP TTL of an ICMP echo reply (same L2 segment: not decremented)
    dhcp_vendor: str | None = None  # DHCP option 60 (vendor class identifier)
    extra: dict[str, str] = field(default_factory=dict)  # free-form facts, e.g. from a router API

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Signals:
        known = {f.name for f in fields(cls)}
        unknown = set(data) - known - {"expect", "_comment", "comment"}
        if unknown:
            raise ValueError(f"unknown signal field(s): {', '.join(sorted(unknown))}")
        return cls(
            mac=_opt_str(data.get("mac")),
            vendor=_opt_str(data.get("vendor")),
            hostnames=[str(h) for h in data.get("hostnames") or []],
            netbios=[str(n) for n in data.get("netbios") or []],
            mdns=[
                MdnsService(
                    type=str(m["type"]),
                    name=_opt_str(m.get("name")),
                    port=_opt_int(m.get("port")),
                    txt={str(k): str(v) for k, v in (m.get("txt") or {}).items()},
                )
                for m in data.get("mdns") or []
            ],
            ssdp=[
                SsdpDevice(**{k: _opt_str(s.get(k)) for k in SSDP_FIELDS})
                for s in data.get("ssdp") or []
            ],
            http=[
                HttpService(
                    port=int(h["port"]),
                    title=_opt_str(h.get("title")),
                    server=_opt_str(h.get("server")),
                    favicon_hash=_opt_str(h.get("favicon_hash")),
                    markers=[str(x) for x in h.get("markers") or []],
                    status=_opt_int(h.get("status")),
                )
                for h in data.get("http") or []
            ],
            open_ports=sorted({int(p) for p in data.get("open_ports") or []}),
            ttl=_opt_int(data.get("ttl")),
            dhcp_vendor=_opt_str(data.get("dhcp_vendor")),
            extra={str(k): str(v) for k, v in (data.get("extra") or {}).items()},
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def all_names(self) -> list[str]:
        """Hostnames first, then NetBIOS names, then mDNS host targets; de-duplicated."""
        out: list[str] = []
        for name in [*self.hostnames, *self.netbios]:
            if name and name not in out:
                out.append(name)
        return out

    def ports(self) -> set[int]:
        found = set(self.open_ports)
        found.update(h.port for h in self.http)
        return found


def _opt_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _opt_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
