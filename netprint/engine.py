"""engine — score device categories from signals with weighted, data-driven rules.

RULES
    Rules live in ``data/rules/*.json`` (and any extra files/dirs passed to ``load_db``).
    Each rule says: when these conditions ALL hold, this is evidence of weight ``w`` for
    ``category``::

        {"id": "apple-watch-model", "category": "watch", "weight": 0.97,
         "when": {"mdns_txt": {"model": "^Watch\\d"}},
         "label": "Apple Watch", "vendor": "Apple"}

    Conditions (see CONTRIBUTING.md for the full list): ``vendor``, ``mac``, ``random_mac``,
    ``hostname``, ``netbios``, ``mdns_service``/``mdns_name``/``mdns_txt`` (checked on the
    SAME service), ``ssdp`` ({field: regex}, on the same SSDP device), ``http_title``/
    ``http_server``/``http_marker``/``favicon`` (on the same web service), ``ports`` (any
    open), ``ports_all``, ``ttl`` ([lo, hi]), ``dhcp_vendor``, ``extra`` ({key: regex}).
    Strings are case-insensitive regular expressions (``re.search``). ``unless`` holds
    conditions that veto the rule.

SCORING
    Evidence for one category combines as a noisy-OR: ``1 - prod(1 - w)``. Two independent
    0.6 hints make 0.84; nothing reaches 1.0. A negative weight multiplies the category's
    score by ``1 + w``; ``demote`` halves the listed categories (a specific rule such as
    "ESPHome device named *ir-remote*" demotes the generic ``esp-diy``). The best category
    wins if it reaches ``MIN_CONFIDENCE``; otherwise the device is ``unknown``.

    A rule with ``"category": null`` is a hint: it contributes a label/vendor/name (e.g. the
    exact model string) without voting.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from . import mac as macmod
from . import naming as namemod
from . import tables
from .names import name_candidates, pick_display_name
from .signals import SSDP_FIELDS, HttpService, MdnsService, Signals, SsdpDevice

_PKG = __package__ or "netprint"  # works when vendored as <pkg>._vendor.netprint too

MIN_CONFIDENCE = 0.2
MAX_CONFIDENCE = 0.99  # evidence is never proof
UNKNOWN = "unknown"

CONDITIONS = frozenset(
    {
        "vendor",
        "mac",
        "random_mac",
        "hostname",
        "netbios",
        "mdns_service",
        "mdns_name",
        "mdns_txt",
        "ssdp",
        "http_title",
        "http_server",
        "http_marker",
        "favicon",
        "ports",
        "ports_all",
        "ttl",
        "dhcp_vendor",
        "extra",
        "lookup",
    }
)
_MDNS_KEYS = ("mdns_service", "mdns_name", "mdns_txt")
_HTTP_KEYS = ("http_title", "http_server", "http_marker", "favicon")
_SOURCE_OF = {
    "vendor": "oui",
    "mac": "mac",
    "random_mac": "mac",
    "hostname": "hostname",
    "netbios": "netbios",
    "mdns_service": "mdns",
    "mdns_name": "mdns",
    "mdns_txt": "mdns",
    "ssdp": "ssdp",
    "http_title": "http",
    "http_server": "http",
    "http_marker": "http",
    "favicon": "http",
    "ports": "ports",
    "ports_all": "ports",
    "ttl": "ttl",
    "dhcp_vendor": "dhcp",
    "extra": "extra",
    "lookup": "lookup",
}
RULE_KEYS = frozenset(
    {
        "id",
        "category",
        "weight",
        "when",
        "unless",
        "label",
        "vendor",
        "icon",
        "detail",
        "demote",
        "source",
        "note",
        "product",
        "model",
        "model_id",
        "friendly",
        "os",
        "firmware",
        "services",
    }
)
# Description fields a rule can fill (templates, like "label"); the best-ranked rule that
# yields a value wins each one independently.
TEXT_FIELDS = ("label", "vendor", "product", "model", "model_id", "friendly", "os", "firmware")


class RuleError(ValueError):
    """A rule file is malformed (raised at load time, with the file and rule id)."""


@dataclass(frozen=True)
class Category:
    id: str
    label: str
    icon: str
    network_gear: bool = False
    description: str = ""


@dataclass(frozen=True)
class Evidence:
    source: str
    detail: str
    weight: float
    rule: str
    category: str | None

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "detail": self.detail, "weight": round(self.weight, 3)}


@dataclass
class Result:
    category: str
    icon: str
    confidence: float
    label: str | None
    vendor: str | None
    display_name: str | None
    random_mac: bool
    network_gear: bool
    evidence: list[Evidence] = field(default_factory=list)
    scores: dict[str, float] = field(default_factory=dict)
    brand: str | None = None  # "Google": from what the device says, else a non-module OUI
    product: str | None = None  # "Chromecast HD", "MacBook Pro 16″"
    model: str | None = None  # "MacBook Pro 16″ (M4 Pro, 2024)"; the product when no more
    model_id: str | None = None  # "Mac16,7", "xiaomi.router.rd28", "UE48J5500"
    friendly_name: str | None = None  # the name the device calls itself / the user gave it
    os: str | None = None
    firmware: str | None = None
    services: list[dict[str, Any]] = field(default_factory=list)  # web UIs it should serve

    def alternatives(self, n: int = 3) -> list[dict[str, Any]]:
        ranked = sorted(self.scores.items(), key=lambda kv: -kv[1])
        return [
            {"category": c, "confidence": round(s, 3)}
            for c, s in ranked
            if c != self.category and s > 0
        ][:n]

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "icon": self.icon,
            "confidence": round(self.confidence, 3),
            "label": self.label,
            "vendor": self.vendor,
            "display_name": self.display_name,
            "brand": self.brand,
            "product": self.product,
            "model": self.model,
            "model_id": self.model_id,
            "friendly_name": self.friendly_name,
            "os": self.os,
            "firmware": self.firmware,
            "services": self.services,
            "random_mac": self.random_mac,
            "network_gear": self.network_gear,
            "evidence": [e.to_dict() for e in self.evidence],
            "alternatives": self.alternatives(),
        }


def _regex(value: Any, where: str) -> re.Pattern[str]:
    try:
        return re.compile(str(value), re.I)
    except re.error as exc:
        raise RuleError(f"{where}: bad regex {value!r}: {exc}") from exc


@dataclass
class Rule:
    id: str
    category: str | None
    weight: float
    when: dict[str, Any]
    unless: dict[str, Any]
    label: str | None = None
    vendor: str | None = None
    icon: str | None = None
    detail: str | None = None
    demote: tuple[str, ...] = ()
    source: str | None = None
    origin: str = ""
    compiled: dict[str, Any] = field(default_factory=dict)
    compiled_unless: dict[str, Any] = field(default_factory=dict)
    texts: dict[str, str] = field(default_factory=dict)  # product/model/os/... templates
    services: tuple[dict[str, Any], ...] = ()

    @classmethod
    def parse(cls, raw: Any, origin: str, categories: dict[str, Category]) -> Rule:
        if not isinstance(raw, dict):
            raise RuleError(f"{origin}: a rule must be an object, got {raw!r}")
        rid = str(raw.get("id") or "")
        where = f"{origin}:{rid or '?'}"
        if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", rid):
            raise RuleError(f"{where}: 'id' must be lowercase [a-z0-9._-]")
        extra_keys = set(raw) - RULE_KEYS
        if extra_keys:
            raise RuleError(f"{where}: unknown key(s) {sorted(extra_keys)}")
        category = raw.get("category")
        if category is not None and category not in categories:
            raise RuleError(f"{where}: unknown category {category!r}")
        weight = raw.get("weight", 0.5 if category else 0.0)
        if not isinstance(weight, int | float) or not -1.0 < float(weight) < 1.0:
            raise RuleError(f"{where}: weight must be a number in (-1, 1)")
        when = raw.get("when")
        if not isinstance(when, dict) or not when:
            raise RuleError(f"{where}: 'when' must be a non-empty object")
        unless = raw.get("unless") or {}
        demote = raw.get("demote") or []
        for c in demote:
            if c not in categories:
                raise RuleError(f"{where}: demote: unknown category {c!r}")
        icon = raw.get("icon")
        if icon is not None and not re.fullmatch(r"mdi:[a-z0-9-]+", str(icon)):
            raise RuleError(f"{where}: icon must look like mdi:name")
        texts: dict[str, str] = {}
        for key in TEXT_FIELDS:
            if key in ("label", "vendor") or raw.get(key) is None:
                continue
            if not isinstance(raw[key], str):
                raise RuleError(f"{where}: {key} must be a string (a template)")
            texts[key] = raw[key]
        services = raw.get("services") or []
        if not isinstance(services, list) or not all(
            isinstance(s, dict) and isinstance(s.get("port"), int) for s in services
        ):
            raise RuleError(f"{where}: services must be a list of {{port, scheme, title}}")
        if "lookup" in unless:
            raise RuleError(f"{where}: lookup cannot be used in 'unless'")
        rule = cls(
            id=rid,
            category=category,
            weight=float(weight),
            when=when,
            unless=unless,
            label=raw.get("label"),
            vendor=raw.get("vendor"),
            icon=icon,
            detail=raw.get("detail"),
            demote=tuple(demote),
            source=raw.get("source"),
            origin=origin,
            texts=texts,
            services=tuple(dict(s) for s in services),
        )
        rule.compiled = _compile(when, where)
        rule.compiled_unless = _compile(unless, where + " unless") if unless else {}
        return rule

    def evaluate(self, s: Signals, vendor: str | None, random: bool) -> dict[str, str] | None:
        captures = _match(self.compiled, s, vendor, random)
        if captures is None:
            return None
        if self.compiled_unless and _match(self.compiled_unless, s, vendor, random) is not None:
            return None
        if "lookup" in self.compiled:
            spec = self.compiled["lookup"]
            context = {f"extra.{k}": v for k, v in s.extra.items()}
            key = _fill(spec["key"], {**context, **captures})
            entry = tables.lookup(spec["table"], key) if key else None
            if entry is None:
                return None
            for fname, pattern in spec["match"].items():
                if not pattern.search(entry.get(fname, "")):
                    return None
            for fname, value in entry.items():
                captures[f"lookup.{fname}"] = value
        return captures

    def primary_source(self) -> str:
        if self.source:
            return self.source
        for key in self.when:
            return _SOURCE_OF.get(key, key)
        return "rule"


def _compile(when: dict[str, Any], where: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in when.items():
        if key not in CONDITIONS:
            raise RuleError(f"{where}: unknown condition {key!r}")
        if key in ("random_mac",):
            if not isinstance(value, bool):
                raise RuleError(f"{where}: random_mac must be true/false")
            out[key] = value
        elif key in ("ports", "ports_all"):
            if not isinstance(value, list) or not all(isinstance(p, int) for p in value):
                raise RuleError(f"{where}: {key} must be a list of port numbers")
            out[key] = frozenset(value)
        elif key == "ttl":
            if not (isinstance(value, list) and len(value) == 2):
                raise RuleError(f"{where}: ttl must be [lo, hi]")
            out[key] = (int(value[0]), int(value[1]))
        elif key == "favicon":
            if not isinstance(value, list):
                raise RuleError(f"{where}: favicon must be a list of md5 hex hashes")
            out[key] = frozenset(str(v).lower() for v in value)
        elif key in ("mdns_txt", "extra"):
            if not isinstance(value, dict) or not value:
                raise RuleError(f"{where}: {key} must be a non-empty object")
            out[key] = {str(k): _regex(v, where) for k, v in value.items()}
        elif key == "lookup":
            if (
                not isinstance(value, dict)
                or not isinstance(value.get("table"), str)
                or not isinstance(value.get("key"), str)
                or set(value) - {"table", "key", "match"}
            ):
                raise RuleError(f"{where}: lookup must be {{table, key, match?}}")
            if value["table"] not in tables.names():
                raise RuleError(f"{where}: lookup: unknown table {value['table']!r}")
            match = value.get("match") or {}
            if not isinstance(match, dict):
                raise RuleError(f"{where}: lookup.match must be an object")
            out[key] = {
                "table": value["table"],
                "key": value["key"],
                "match": {str(k): _regex(v, where) for k, v in match.items()},
            }
        elif key == "ssdp":
            if not isinstance(value, dict) or not value:
                raise RuleError(f"{where}: ssdp must be a non-empty object")
            bad = set(value) - set(SSDP_FIELDS)
            if bad:
                raise RuleError(f"{where}: unknown ssdp field(s) {sorted(bad)}")
            out[key] = {str(k): _regex(v, where) for k, v in value.items()}
        else:
            out[key] = _regex(value, where)
    return out


def _capture(
    captures: dict[str, str], key: str, value: str, match: re.Match[str] | None = None
) -> None:
    captures.setdefault(key, value)
    if match is not None:
        for name, group in match.groupdict().items():
            if group:
                captures.setdefault(name, group)


def _search_any(pattern: re.Pattern[str], values: Iterable[str | None]) -> tuple[str, Any] | None:
    for value in values:
        if value:
            found = pattern.search(value)
            if found:
                return value, found
    return None


def _match_mdns(c: dict[str, Any], svc: MdnsService, captures: dict[str, str]) -> bool:
    local: dict[str, str] = {}
    if "mdns_service" in c:
        hit = _search_any(c["mdns_service"], [svc.type])
        if not hit:
            return False
        _capture(local, "mdns_service", hit[0], hit[1])
    if "mdns_name" in c:
        hit = _search_any(c["mdns_name"], [svc.name])
        if not hit:
            return False
        _capture(local, "mdns_name", hit[0], hit[1])
    if "mdns_txt" in c:
        lowered = {k.lower(): v for k, v in svc.txt.items()}
        for key, pattern in c["mdns_txt"].items():
            hit = _search_any(pattern, [lowered.get(key.lower())])
            if not hit:
                return False
            _capture(local, f"mdns_txt.{key}", hit[0], hit[1])
    for k, v in local.items():
        captures.setdefault(k, v)
    captures.setdefault("mdns_service", svc.type)
    return True


def _match_ssdp(c: dict[str, Any], dev: SsdpDevice, captures: dict[str, str]) -> bool:
    local: dict[str, str] = {}
    for key, pattern in c["ssdp"].items():
        hit = _search_any(pattern, [dev.get(key)])
        if not hit:
            return False
        _capture(local, f"ssdp.{key}", hit[0], hit[1])
    for k, v in local.items():
        captures.setdefault(k, v)
    return True


def _match_http(c: dict[str, Any], svc: HttpService, captures: dict[str, str]) -> bool:
    local: dict[str, str] = {"http_port": str(svc.port)}
    if "http_title" in c:
        hit = _search_any(c["http_title"], [svc.title])
        if not hit:
            return False
        _capture(local, "http_title", hit[0], hit[1])
    if "http_server" in c:
        hit = _search_any(c["http_server"], [svc.server])
        if not hit:
            return False
        _capture(local, "http_server", hit[0], hit[1])
    if "http_marker" in c:
        hit = _search_any(c["http_marker"], svc.markers)
        if not hit:
            return False
        _capture(local, "http_marker", hit[0], hit[1])
    if "favicon" in c:
        if not svc.favicon_hash or svc.favicon_hash.lower() not in c["favicon"]:
            return False
        _capture(local, "favicon", svc.favicon_hash)
    for k, v in local.items():
        captures.setdefault(k, v)
    return True


def _match(
    c: dict[str, Any], s: Signals, vendor: str | None, random: bool
) -> dict[str, str] | None:
    captures: dict[str, str] = {}
    if "random_mac" in c and c["random_mac"] != random:
        return None
    if "random_mac" in c:
        captures["random_mac"] = "yes" if random else "no"
    if "vendor" in c:
        hit = _search_any(c["vendor"], [vendor])
        if not hit:
            return None
        _capture(captures, "vendor", hit[0], hit[1])
    if "mac" in c:
        hit = _search_any(c["mac"], [macmod.normalize(s.mac or "")])
        if not hit:
            return None
        _capture(captures, "mac", hit[0], hit[1])
    if "hostname" in c:
        hit = _search_any(c["hostname"], s.all_names())
        if not hit:
            return None
        _capture(captures, "hostname", hit[0], hit[1])
    if "netbios" in c:
        hit = _search_any(c["netbios"], s.netbios)
        if not hit:
            return None
        _capture(captures, "netbios", hit[0], hit[1])
    if any(k in c for k in _MDNS_KEYS) and not any(_match_mdns(c, m, captures) for m in s.mdns):
        return None
    if "ssdp" in c and not any(_match_ssdp(c, d, captures) for d in s.ssdp):
        return None
    if any(k in c for k in _HTTP_KEYS) and not any(_match_http(c, h, captures) for h in s.http):
        return None
    ports = s.ports()
    if "ports" in c:
        hit_ports = sorted(c["ports"] & ports)
        if not hit_ports:
            return None
        captures["ports"] = ",".join(map(str, hit_ports))
    if "ports_all" in c:
        if not c["ports_all"] <= ports:
            return None
        captures.setdefault("ports", ",".join(map(str, sorted(c["ports_all"]))))
    if "ttl" in c:
        lo, hi = c["ttl"]
        if s.ttl is None or not lo <= s.ttl <= hi:
            return None
        captures["ttl"] = str(s.ttl)
    if "dhcp_vendor" in c:
        hit = _search_any(c["dhcp_vendor"], [s.dhcp_vendor])
        if not hit:
            return None
        _capture(captures, "dhcp_vendor", hit[0], hit[1])
    if "extra" in c:
        lowered = {k.lower(): v for k, v in s.extra.items()}
        for key, pattern in c["extra"].items():
            hit = _search_any(pattern, [lowered.get(key.lower())])
            if not hit:
                return None
            _capture(captures, f"extra.{key}", hit[0], hit[1])
    return captures


_TEMPLATE = re.compile(r"\{([a-zA-Z0-9_.\-]+)\}")


def _fill(template: str | None, captures: dict[str, str]) -> str | None:
    if not template:
        return None
    missing = False

    def sub(m: re.Match[str]) -> str:
        nonlocal missing
        value = captures.get(m.group(1))
        if value is None:
            missing = True
            return ""
        return value

    text = _TEMPLATE.sub(sub, template).strip()
    return None if missing or not text else text


def _auto_detail(rule: Rule, captures: dict[str, str]) -> str:
    parts: list[str] = []
    for key, value in captures.items():
        if key in ("http_port", "random_mac") or key.startswith("lookup.") or not value:
            continue
        pretty = {
            "vendor": "vendor",
            "hostname": "name",
            "netbios": "NetBIOS",
            "mdns_service": "mDNS",
            "mdns_name": "mDNS name",
            "http_title": "title",
            "http_server": "server",
            "http_marker": "page mentions",
            "favicon": "favicon",
            "ports": "port",
            "ttl": "TTL",
            "dhcp_vendor": "DHCP vendor",
            "mac": "MAC",
        }.get(key, key.replace("mdns_txt.", "TXT ").replace("ssdp.", "UPnP ").replace("extra.", ""))
        if key.startswith(("mdns_txt.", "ssdp.", "extra.")):
            parts.append(f"{pretty}={value}")
        elif key in ("vendor", "hostname", "http_title", "http_server", "mdns_name", "netbios"):
            parts.append(f'{pretty} "{value}"')
        else:
            parts.append(f"{pretty} {value}")
    if captures.get("random_mac") == "yes":
        parts.insert(0, "randomized (locally administered) MAC")
    text = "; ".join(dict.fromkeys(parts)) or rule.id
    return text[:160]


@dataclass
class Database:
    categories: dict[str, Category]
    rules: list[Rule]

    def category(self, cid: str) -> Category:
        return self.categories.get(cid) or self.categories[UNKNOWN]


def _iter_rule_files(extra: Iterable[Path]) -> Iterator[tuple[str, Any]]:
    base = resources.files(_PKG).joinpath("data", "rules")
    names = sorted(p.name for p in base.iterdir() if p.name.endswith(".json"))
    for name in names:
        yield f"rules/{name}", json.loads(base.joinpath(name).read_text("utf-8"))
    for path in extra:
        files = sorted(path.glob("*.json")) if path.is_dir() else [path]
        for f in files:
            yield str(f), json.loads(f.read_text("utf-8"))


def load_categories() -> dict[str, Category]:
    raw = json.loads(resources.files(_PKG).joinpath("data", "categories.json").read_text("utf-8"))
    out: dict[str, Category] = {}
    for item in raw["categories"]:
        out[item["id"]] = Category(
            id=item["id"],
            label=item["label"],
            icon=item["icon"],
            network_gear=bool(item.get("network_gear", False)),
            description=item.get("description", ""),
        )
    if UNKNOWN not in out:
        raise RuleError("categories.json must define 'unknown'")
    return out


def load_db(extra: Iterable[Path] = ()) -> Database:
    """Categories + every rule file (shipped first, then ``extra`` files/directories).

    Rules from ``extra`` with the id of a shipped rule REPLACE it (so a local file can
    retune or disable one: ``"weight": 0`` never votes)."""
    categories = load_categories()
    rules: dict[str, Rule] = {}
    for origin, doc in _iter_rule_files(extra):
        items = doc.get("rules") if isinstance(doc, dict) else doc
        if not isinstance(items, list):
            raise RuleError(f"{origin}: expected {{'rules': [...]}}")
        for raw in items:
            rule = Rule.parse(raw, origin, categories)
            if rule.id in rules and rules[rule.id].origin == origin:
                raise RuleError(f"{origin}: duplicate rule id {rule.id!r}")
            if rule.id in rules and origin.startswith("rules/"):
                raise RuleError(
                    f"{origin}: rule id {rule.id!r} already used in {rules[rule.id].origin}"
                )
            rules[rule.id] = rule
    return Database(categories=categories, rules=list(rules.values()))


@lru_cache(maxsize=1)
def default_db() -> Database:
    return load_db()


def classify(signals: Signals, db: Database | None = None, alias: str | None = None) -> Result:
    """Score every category for one device and return the winner with its evidence."""
    db = db or default_db()
    norm = macmod.normalize(signals.mac or "")
    random = bool(norm and macmod.is_locally_administered(norm))
    vendor = signals.vendor or (macmod.vendor(norm) if norm else None)

    miss: dict[str, float] = {}
    factor: dict[str, float] = {}
    fired: list[tuple[Rule, dict[str, str]]] = []
    for rule in db.rules:
        if rule.weight == 0 and rule.category is not None:
            continue
        captures = rule.evaluate(signals, vendor, random)
        if captures is None:
            continue
        fired.append((rule, captures))
        if rule.category is not None:
            if rule.weight > 0:
                miss[rule.category] = miss.get(rule.category, 1.0) * (1.0 - rule.weight)
            else:
                factor[rule.category] = factor.get(rule.category, 1.0) * (1.0 + rule.weight)
        for demoted in rule.demote:
            factor[demoted] = factor.get(demoted, 1.0) * 0.5

    scores = {c: (1.0 - m) * factor.get(c, 1.0) for c, m in miss.items()}
    best = max(scores.items(), key=lambda kv: kv[1], default=(UNKNOWN, 0.0))
    category, confidence = best if best[1] >= MIN_CONFIDENCE else (UNKNOWN, 0.0)
    confidence = min(confidence, MAX_CONFIDENCE)

    winning = sorted(
        (
            (r, cap)
            for r, cap in fired
            if r.category == category or (r.category is None and category != UNKNOWN)
        ),
        key=lambda rc: -abs(rc[0].weight),
    )
    hints = sorted(
        ((r, cap) for r, cap in fired if r.category is None), key=lambda rc: -rc[0].weight
    )
    context = {f"extra.{k}": v for k, v in signals.extra.items()}
    naming = namemod.default_naming()
    values: dict[str, str] = {}
    brand = None
    icon = None
    services: dict[int, dict[str, Any]] = {}
    for r, cap in [*winning, *hints]:
        filled = {**context, **cap}
        for key in TEXT_FIELDS:
            template = (
                r.label if key == "label" else r.vendor if key == "vendor" else r.texts.get(key)
            )
            if key not in values and template:
                value = _fill(template, filled)
                if value:
                    values[key] = value
        if brand is None and r.vendor:
            brand = namemod.canonical_brand(_fill(r.vendor, filled), naming)
        if icon is None and r.icon and r.category == category:
            icon = r.icon
        for svc in r.services:
            port = int(svc["port"])
            if port not in services:
                title = _fill(str(svc.get("title") or ""), filled)
                services[port] = {
                    "port": port,
                    "scheme": str(svc.get("scheme") or "http"),
                    "title": title,
                }
    label = values.get("label")
    rule_vendor = values.get("vendor")
    if brand is None and vendor and not namemod.is_module_maker(vendor, naming):
        brand = namemod.canonical_brand(vendor, naming)
    cat = db.category(category)
    evidence = [
        Evidence(
            source=r.primary_source(),
            detail=_fill(r.detail, {**context, **cap}) or _auto_detail(r, cap),
            weight=r.weight,
            rule=r.id,
            category=r.category,
        )
        for r, cap in winning
        if r.category is not None
    ]
    if category == UNKNOWN:
        evidence = [
            Evidence(
                r.primary_source(),
                _fill(r.detail, {**context, **cap}) or _auto_detail(r, cap),
                r.weight,
                r.id,
                r.category,
            )
            for r, cap in sorted(fired, key=lambda rc: -abs(rc[0].weight))
        ][:5]
    shown_vendor = rule_vendor or vendor
    product = values.get("product")
    model = values.get("model") or product
    model_id = values.get("model_id")
    known = category != UNKNOWN
    vocabulary = [brand, product, model, model_id, label, shown_vendor]
    if known:
        vocabulary += [cat.label, cat.id]
    candidates = name_candidates(signals, alias)
    if values.get("friendly"):
        candidates.insert(1 if alias else 0, values["friendly"])
    friendly = next(
        (c for c in candidates if namemod.is_label(c, vocabulary, naming)),
        candidates[0] if candidates else None,
    )
    is_label = bool(alias and friendly == alias.strip()) or namemod.is_label(
        friendly, vocabulary, naming
    )
    if label:
        kind = label
    elif known:
        kind = cat.label if not brand or re.search(r"[A-Z]", cat.label[1:]) else cat.label.lower()
    else:
        kind = None
    display = namemod.compose(brand, product, kind, friendly, is_label, naming)
    if not display:
        display = pick_display_name(
            signals, label, shown_vendor, cat.label if known else None, alias
        )
    return Result(
        category=category,
        icon=icon or cat.icon,
        confidence=round(confidence, 3),
        label=label,
        vendor=shown_vendor,
        display_name=display,
        random_mac=random,
        network_gear=cat.network_gear,
        evidence=evidence,
        scores={c: round(v, 3) for c, v in scores.items()},
        brand=brand,
        product=product,
        model=model,
        model_id=model_id,
        friendly_name=friendly,
        os=values.get("os"),
        firmware=values.get("firmware"),
        services=sorted(services.values(), key=lambda s: int(s["port"])),
    )
