"""python -m netprint — classify signal files, lint rules, list categories, refresh the OUI table.

python -m netprint classify device.json [more.json ...] [--rules DIR] [--json]
python -m netprint lint [--rules DIR]
python -m netprint categories
python -m netprint oui-update [--csv oui.csv]     (maintainers: rebuilds data/oui.tsv.gz)
python -m netprint apple-update [--json main.json] (maintainers: rebuilds data/tables/apple.json)
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path

from . import __version__, fingerprint_ports, tables
from .engine import RuleError, classify, load_db
from .mac import compact_ieee_csv, encode_table
from .signals import Signals

IEEE_URL = "https://standards-oui.ieee.org/oui/oui.csv"


def _load_signal_files(paths: list[str]) -> list[tuple[str, Signals, dict[str, object]]]:
    out = []
    for p in paths:
        data = json.loads(Path(p).read_text("utf-8"))
        items = data if isinstance(data, list) else [data]
        for i, item in enumerate(items):
            name = p if len(items) == 1 else f"{p}[{i}]"
            out.append((name, Signals.from_dict(item), item))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="netprint", description=__doc__.splitlines()[0])
    ap.add_argument("--version", action="version", version=f"netprint {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("classify", help="classify devices described in JSON signal files")
    c.add_argument("files", nargs="+")
    c.add_argument("--rules", action="append", default=[], help="extra rule file or directory")
    c.add_argument("--json", action="store_true")
    lint = sub.add_parser("lint", help="load and validate every rule")
    lint.add_argument("--rules", action="append", default=[])
    sub.add_parser("categories", help="list categories and icons")
    upd = sub.add_parser("oui-update", help="rebuild netprint/data/oui.tsv.gz from the IEEE CSV")
    upd.add_argument("--csv", help="a local oui.csv instead of downloading it")
    apple = sub.add_parser(
        "apple-update", help="rebuild data/tables/apple.json (model ids) from AppleDB"
    )
    apple.add_argument("--json", dest="source", help="a local AppleDB main.json")
    args = ap.parse_args(argv)

    if args.cmd == "apple-update":
        if args.source:
            raw = Path(args.source).read_text("utf-8")
        else:
            req = urllib.request.Request(tables.APPLEDB_URL, headers={"User-Agent": "netprint"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                raw = resp.read().decode("utf-8")
        apple_table = tables.build_apple_table(json.loads(raw))
        if len(apple_table) < 100:
            print(f"error: only {len(apple_table)} identifiers parsed", file=sys.stderr)
            return 1
        target = Path(__file__).parent / "data" / "tables" / "apple.json"
        doc = tables.apple_document(apple_table)
        target.write_text(json.dumps(doc, ensure_ascii=False, indent=1) + "\n", "utf-8")
        print(f"wrote {len(apple_table)} Apple model identifiers to {target}")
        return 0

    if args.cmd == "categories":
        db = load_db()
        for cat in db.categories.values():
            gear = "  (network gear)" if cat.network_gear else ""
            print(f"{cat.id:14} {cat.icon:28} {cat.label}{gear}")
        return 0
    if args.cmd == "lint":
        try:
            db = load_db([Path(p) for p in args.rules])
        except RuleError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        voting = sum(1 for r in db.rules if r.category)
        print(
            f"ok: {len(db.rules)} rules ({voting} voting, {len(db.rules) - voting} hints), "
            f"{len(db.categories)} categories, {len(fingerprint_ports(db))} fingerprint ports"
        )
        return 0
    if args.cmd == "oui-update":
        if args.csv:
            text = Path(args.csv).read_text("utf-8", errors="replace")
        else:
            req = urllib.request.Request(IEEE_URL, headers={"User-Agent": "netprint"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                text = resp.read().decode("utf-8", errors="replace")
        table = compact_ieee_csv(text)
        if len(table) < 1000:
            print(f"error: only {len(table)} rows parsed", file=sys.stderr)
            return 1
        target = Path(__file__).parent / "data" / "oui.tsv.gz"
        target.write_bytes(encode_table(table))
        print(f"wrote {len(table)} prefixes to {target}")
        return 0

    db = load_db([Path(p) for p in args.rules])
    results = []
    for name, signals, _raw in _load_signal_files(args.files):
        result = classify(signals, db)
        results.append({"file": name, **result.to_dict()})
    if args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return 0
    for r in results:
        print(
            f"{r['file']}: {r['category']} ({r['confidence']:.2f}) {r['icon']}  {r['display_name']}"
        )
        facts = [
            f"{key}={r[key]}"
            for key in ("brand", "product", "model", "model_id", "friendly_name", "os", "firmware")
            if r.get(key)
        ]
        if facts:
            print("    " + "  ".join(facts))
        for e in r["evidence"]:
            print(f"    {e['weight']:+.2f}  [{e['source']}] {e['detail']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
