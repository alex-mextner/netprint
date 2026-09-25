# Contributing rules

Most contributions are a rule and a fixture. No Python needed.

## 1. Describe the device (a fixture)

Add an object to a file in `tests/fixtures/devices/` (or a new file there) with what a
collector would see, and what netprint should conclude:

```json
{"comment": "Bambu Lab P1S over mDNS",
 "vendor": "Espressif",
 "mdns": [{"type": "_bambu._tcp", "name": "P1S-0001", "txt": {}}],
 "expect": {"category": "3d-printer", "label": "Bambu Lab printer", "min_confidence": 0.9}}
```

`expect` keys: `category` (required), `label`, `icon`, `display_name`, `min_confidence`,
`max_confidence`, `network_gear`.

**Keep it synthetic.** MACs must end in `00:00:NN` (keep a real OUI prefix if the vendor
matters, or give `vendor` directly and no MAC); IPs only from 192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24; replace serials, device ids, SSIDs and people's names.
`test_fixtures_are_synthetic` fails otherwise.

## 2. Write the rule

Rules live in `netprint/data/rules/<source>.json`:

```json
{"id": "mdns.bambu", "category": "3d-printer", "weight": 0.95,
 "when": {"mdns_service": "^_bambu"},
 "label": "Bambu Lab printer", "vendor": "Bambu Lab"}
```

| key | meaning |
| --- | --- |
| `id` | unique, lowercase, `source.what[.variant]` |
| `category` | a category id from `data/categories.json`, or `null` for a *hint* (label/vendor only, no vote) |
| `weight` | (-1, 1). How sure this signal alone makes you. See below. For hints: label priority. |
| `when` | conditions; ALL must hold |
| `unless` | conditions that veto the rule |
| `label` | model/kind to show ("Yandex Station Mini"); may use `{captures}` |
| `vendor` | brand to show when the OUI is a module maker ("Yandex" for "Intertech Services") |
| `icon` | `mdi:*` override for this specific kind |
| `detail` | evidence text; auto-generated when omitted; may use `{captures}` |
| `demote` | categories to halve when this fires (specific beats generic) |
| `source` | evidence source name, if not implied by the first condition |
| `note` | free text for reviewers |

### Conditions

Strings are case-insensitive regular expressions (`re.search`); anchor them (`^...$`) when
you mean it.

| condition | matches |
| --- | --- |
| `vendor` | OUI vendor (short form: "Apple", "Espressif", "Tuya Smart") |
| `mac` | normalized MAC `aa:bb:cc:dd:ee:ff` (for well-known prefixes like Docker's `02:42:`) |
| `random_mac` | `true`/`false`: locally administered MAC |
| `hostname` | any hostname or NetBIOS name |
| `netbios` | a NetBIOS name |
| `mdns_service` | DNS-SD service type, e.g. `^_airplay\\._tcp$` |
| `mdns_name` | service instance name |
| `mdns_txt` | `{key: regex}` TXT records |
| `ssdp` | `{field: regex}` on one SSDP device: server, st, usn, location, friendly_name, manufacturer, model_name, model_number, model_description, device_type |
| `http_title`, `http_server`, `http_marker` | web UI page title / Server header / a marker from `netprint.markers` |
| `favicon` | list of md5 hex digests of favicon bytes |
| `ports` / `ports_all` | any / all of these TCP ports open |
| `ttl` | `[lo, hi]` IP TTL of an echo reply |
| `dhcp_vendor` | DHCP option 60 |
| `extra` | `{key: regex}` collector facts (`gateway`, `self`, `miwifi.model`, ...) |

`mdns_*` conditions in one rule are checked against the **same** service instance, `ssdp`
fields against the same device, `http_*`/`favicon` against the same web service.

### Captures and templates

Every matched value is available as `{condition}` (`{vendor}`, `{hostname}`, `{http_title}`,
`{ports}`, `{ttl}`, `{mdns_txt.model}`, `{ssdp.model_name}`, `{extra.miwifi.hardware}`), and
so is every named regex group: `"model_name": "^(?P<m>UE\\d{2}\\w+)"` then `"label": "Samsung
TV {m}"`. A template whose capture is missing yields nothing (the next rule's label is used).

### Choosing a weight

| weight | when |
| --- | --- |
| 0.95 - 0.98 | the device says what it is: an Apple model id, a UPnP model name, a product-specific service (`_esphomelib`, `_yandexio`, Moonraker's port) |
| 0.8 - 0.9 | a vendor default name (`LAPTOP-XXXX`, `android-...`), a product web UI title |
| 0.5 - 0.7 | a user-chosen word in a name ("tv", "lamp"), a vendor that makes mostly one thing |
| 0.2 - 0.45 | a vendor that makes several kinds of things, a generic protocol (SMB, AirPlay) |
| 0.1 - 0.2 | a nudge (TTL, a Wi-Fi module maker) |
| negative | "this is evidence AGAINST" (TTL 128 is not a phone) |

Remember that several weak rules add up (noisy-OR); a vendor rule for Espressif should not be
able to outvote an ESPHome service that names the device a light.

## 3. Check

```
python -m netprint lint
python -m pytest -q
ruff check . && ruff format --check . && mypy netprint
```

`python -m netprint classify tests/fixtures/devices/yours.json` prints the evidence, which is
the fastest way to tune weights.
