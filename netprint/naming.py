"""naming — brand names and the display-name model.

A device is shown as ``<brand> <product> «<friendly name>»`` — "Google Chromecast
«Кухня»", "Apple MacBook Pro 16″ «Sam's MBP»" — when all three are known and the
friendly name is a LABEL: a room, a person, a nickname, something the brand and product do
not already say. A friendly name that only repeats the product ("MacBook-Pro", "Хромкаст",
"[TV] UE48J5500") is not a label and is left out. Without a known product the kind of device
stands in ("Tuya smart plug / relay"), and a label alone is shown as is ("SAM-PC").

Everything here is data (``data/naming.json``, ``data/brands.json``): the templates, the
display rewrites of product names, the synonyms that make "Хромкаст" mean "Chromecast", the
brand aliases that make "Samsung Electronics Co.,Ltd" and "Яндекс" one brand each.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any

_PKG = __package__ or "netprint"
_WORD = re.compile(r"[^\W_]+", re.U)
_SUFFIX = re.compile(
    r"[,.]?\s+(co\.?,?\s*)?(ltd\.?|inc\.?|llc|gmbh|corp\.?|corporation|limited|s\.a\.|ag|b\.v\.)"
    r"\.?$",
    re.I,
)
_HEX_TAG = re.compile(r"(?=.*\d)[0-9a-f]{3,8}")


@dataclass(frozen=True)
class Naming:
    templates: dict[str, str]
    display_product: tuple[tuple[re.Pattern[str], str], ...]
    groups: dict[str, frozenset[str]]  # word -> every word that means the same
    filler: frozenset[str]
    aliases: tuple[tuple[re.Pattern[str], str], ...]
    not_brands: tuple[re.Pattern[str], ...]
    module_makers: tuple[re.Pattern[str], ...]


def _read(name: str) -> dict[str, Any]:
    raw = json.loads(resources.files(_PKG).joinpath("data", name).read_text("utf-8"))
    return raw if isinstance(raw, dict) else {}


def load_naming(override: dict[str, Any] | None = None) -> Naming:
    """The shipped naming + brand data, with ``override`` keys (same shape as
    ``naming.json`` / ``brands.json``) replacing or extending them: ``templates`` and
    ``synonyms`` are merged key by key, lists are prepended (they win)."""
    data = {**_read("brands.json"), **_read("naming.json")}
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(data.get(key), dict):
            data[key] = {**data[key], **value}
        elif isinstance(value, list) and isinstance(data.get(key), list):
            data[key] = [*value, *data[key]]
        else:
            data[key] = value
    groups: dict[str, set[str]] = {}
    for head, words in (data.get("synonyms") or {}).items():
        members = {str(head).lower(), *(str(w).lower() for w in words)}
        for member in members:
            groups.setdefault(member, set()).update(members)
    return Naming(
        templates={str(k): str(v) for k, v in (data.get("templates") or {}).items()},
        display_product=tuple(
            (re.compile(str(p), re.I), str(r)) for p, r in data.get("display_product") or []
        ),
        groups={k: frozenset(v) for k, v in groups.items()},
        filler=frozenset(str(w).lower() for w in data.get("filler") or []),
        aliases=tuple((re.compile(str(p), re.I), str(c)) for p, c in data.get("aliases") or []),
        not_brands=tuple(re.compile(str(p), re.I) for p in data.get("not_brands") or []),
        module_makers=tuple(re.compile(str(p), re.I) for p in data.get("module_makers") or []),
    )


@lru_cache(maxsize=1)
def default_naming() -> Naming:
    return load_naming()


def canonical_brand(text: str | None, naming: Naming | None = None) -> str | None:
    """'Samsung Electronics Co.,Ltd' -> 'Samsung', 'Яндекс' -> 'Yandex', 'moonraker' -> None."""
    naming = naming or default_naming()
    value = " ".join(str(text or "").split()).strip(" .,")
    if not value:
        return None
    if any(p.search(value) for p in naming.not_brands):
        return None
    for pattern, canonical in naming.aliases:
        if pattern.fullmatch(value):
            return canonical
    stripped = _SUFFIX.sub("", value).strip(" .,")
    return stripped or None


def is_module_maker(vendor: str | None, naming: Naming | None = None) -> bool:
    """A chip / Wi-Fi module vendor, whose OUI says nothing about the brand on the box."""
    naming = naming or default_naming()
    return bool(vendor) and any(p.search(str(vendor)) for p in naming.module_makers)


def words(text: str | None) -> list[str]:
    return [w.lower() for w in _WORD.findall(str(text or ""))]


def is_label(
    name: str | None, vocabulary: Iterable[str | None], naming: Naming | None = None
) -> bool:
    """Does ``name`` say something the brand/product/model (``vocabulary``) do not?

    "Кухня", "Sam's MBP", "mini-kids" are labels; "Хромкаст", "MacBook-Pro",
    "[TV] UE48J5500", "K1SE-0A1B" (product + hex tag) are not."""
    naming = naming or default_naming()
    if not name:
        return False
    known: set[str] = set()
    compact: list[str] = []
    for item in vocabulary:
        if not item:
            continue
        compact.append(re.sub(r"[\W_]+", "", item.lower()))
        for w in words(item):
            known.add(w)
            known.update(naming.groups.get(w, ()))
    for w in words(name):
        if w in known or w in naming.filler or w.isdigit() or len(w) < 2:
            continue
        if any(w in naming.groups.get(k, ()) for k in known):
            continue
        if _HEX_TAG.fullmatch(w):
            continue
        if len(w) >= 3 and any(w in c for c in compact):
            continue
        return True
    return False


def display_product(product: str | None, naming: Naming | None = None) -> str | None:
    naming = naming or default_naming()
    if not product:
        return None
    for pattern, replacement in naming.display_product:
        if pattern.search(product):
            return pattern.sub(replacement, product).strip() or product
    return product


def compose(
    brand: str | None,
    product: str | None,
    kind: str | None,
    friendly: str | None,
    label: bool,
    naming: Naming | None = None,
) -> str | None:
    """Fill the display-name template: see the module docstring."""
    naming = naming or default_naming()
    shown = display_product(product, naming)
    if shown:
        key = "product_label" if friendly and label else "product"
    else:
        key = "kind_label" if friendly and label else "kind"
    template = naming.templates.get(key) or ""
    head = shown or kind or ""
    if brand and head.lower().startswith(brand.lower()):
        brand = None  # "Yandex" + "Yandex Station" -> "Yandex Station"
    values = {
        "brand": brand or "",
        "product": shown or "",
        "kind": kind or "",
        "friendly": friendly,
    }
    text = re.sub(r"\{(\w+)\}", lambda m: str(values.get(m.group(1)) or ""), template)
    text = re.sub(r"«\s*»|\(\s*\)", "", text)
    text = " ".join(text.split())
    return text or None
