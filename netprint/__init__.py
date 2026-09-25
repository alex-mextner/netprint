"""netprint — what kind of device is that? Data-driven fingerprints for home networks.

    >>> from netprint import Signals, classify
    >>> r = classify(Signals(mac="da:00:00:00:00:01", hostnames=["Sams-iPhone"]))
    >>> r.category, r.icon
    ('phone', 'mdi:cellphone')

Stdlib only. The rules are JSON under ``netprint/data/rules``; see CONTRIBUTING.md.
"""

from __future__ import annotations

from .engine import (
    MIN_CONFIDENCE,
    UNKNOWN,
    Category,
    Database,
    Evidence,
    Result,
    Rule,
    RuleError,
    classify,
    default_db,
    load_db,
)
from .mac import is_locally_administered, normalize, vendor
from .markers import find as find_markers
from .names import clean as clean_name
from .names import is_generic as is_generic_name
from .names import name_candidates
from .naming import canonical_brand, compose, is_label, is_module_maker, load_naming
from .signals import HttpService, MdnsService, Signals, SsdpDevice

__version__ = "0.2.0"


def fingerprint_ports(db: Database | None = None) -> list[int]:
    """Every TCP port some rule looks at: what a collector should probe."""
    db = db or default_db()
    ports: set[int] = set()
    for rule in db.rules:
        for key in ("ports", "ports_all"):
            for p in rule.when.get(key, []):
                ports.add(int(p))
    return sorted(ports)


__all__ = [
    "MIN_CONFIDENCE",
    "UNKNOWN",
    "Category",
    "Database",
    "Evidence",
    "HttpService",
    "MdnsService",
    "Result",
    "Rule",
    "RuleError",
    "Signals",
    "SsdpDevice",
    "__version__",
    "canonical_brand",
    "classify",
    "clean_name",
    "compose",
    "default_db",
    "find_markers",
    "fingerprint_ports",
    "is_generic_name",
    "is_label",
    "is_locally_administered",
    "is_module_maker",
    "load_db",
    "load_naming",
    "name_candidates",
    "normalize",
    "vendor",
]
