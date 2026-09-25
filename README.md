# netprint

**What kind of device is that?** netprint turns what you can observe about a device on a home
network (MAC vendor, hostname, mDNS/DNS-SD services and TXT records, SSDP/UPnP descriptions,
web UI titles, open ports, TTL, NetBIOS names, router API facts) into a **category**, a
**Material Design icon**, a **confidence**, a **display name** and the **evidence** behind it.

```
$ python -m netprint classify tv.json
tv.json: tv (0.99) mdi:television  [TV] Samsung 5 Series (48)
    +0.95  [ssdp] Samsung TV model UE48J5500
    +0.90  [ssdp] UPnP name [TV] Samsung 5 Series (48)
    +0.85  [ssdp] UPnP st=urn:samsung.com:device:RemoteControlReceiver:1
    +0.70  [ports] port 7676,9197 (Samsung TV control/DLNA)
    ...
```

- **Data, not code.** ~440 rules in `netprint/data/rules/*.json`; adding a device family is
  a JSON edit plus a fixture. See [CONTRIBUTING.md](CONTRIBUTING.md).
- **Stdlib only**, Python 3.11+. No network access: netprint classifies, it does not scan.
  Collectors (an mDNS browser, an SSDP listener, a port probe, a router API) live in the
  tools that use it, e.g. [router-cli](https://github.com/alex-mextner/router-cli).
- **Ships the IEEE OUI (MA-L) table** and handles randomized / locally administered MACs
  (the "private Wi-Fi address" phones, watches and laptops use) as a signal of its own.

## Categories

| id | icon | |
| --- | --- | --- |
| `phone` | `mdi:cellphone` | |
| `tablet` | `mdi:tablet` | |
| `watch` | `mdi:watch` | |
| `laptop` | `mdi:laptop` | |
| `desktop` | `mdi:desktop-tower-monitor` | |
| `tv` | `mdi:television` | |
| `media-player` | `mdi:cast` | Chromecast, Apple TV, Android TV boxes, Roku |
| `speaker` | `mdi:speaker` | smart speakers **and voice assistants** (Yandex Station, Echo, HomePod) |
| `printer` | `mdi:printer` | |
| `3d-printer` | `mdi:printer-3d` | Klipper/Moonraker, OctoPrint, Creality, Bambu, Prusa |
| `camera` | `mdi:cctv` | |
| `router` | `mdi:router-network` | network gear |
| `access-point` | `mdi:router-wireless` | APs, **mesh nodes**, routers in bridge mode; network gear |
| `nas` | `mdi:nas` | |
| `server` | `mdi:server` | home servers, Home Assistant hosts, VMs, containers |
| `iot-plug` | `mdi:power-socket-eu` | Tuya, Shelly, Sonoff, Tasmota |
| `iot-light` | `mdi:lightbulb` | WLED, Yeelight, Hue |
| `iot-sensor` | `mdi:home-automation` | sensors, climate, appliances |
| `ir-remote` | `mdi:remote` | Broadlink, ESPHome IR blasters |
| `esp-diy` | `mdi:chip` | self-built ESP8266/ESP32 (ESPHome) |
| `game-console` | `mdi:gamepad-variant` | |
| `raspberry-pi` | `mdi:raspberry-pi` | Raspberry Pi and other SBCs |
| `unknown` | `mdi:help-network` | not enough evidence |

A rule may override the icon (e.g. `mdi:home-assistant`, `mdi:watch-variant`).

## Use it

```python
from netprint import Signals, MdnsService, classify

signals = Signals(
    mac="da:a1:19:00:00:01",  # locally administered -> "random MAC"
    hostnames=["Sams-iPhone"],
    mdns=[MdnsService("_companion-link._tcp", "Sam's iPhone", txt={"rpMd": "iPhone15,2"})],
)
r = classify(signals)
r.category, r.icon, r.confidence, r.display_name
# ('phone', 'mdi:cellphone', 0.99, 'Sams-iPhone')
[e.to_dict() for e in r.evidence]
# [{'source': 'mdns', 'detail': 'Apple model iPhone15,2', 'weight': 0.98}, ...]
```

`Signals` fields (all optional): `mac`, `vendor` (looked up from the MAC when omitted),
`hostnames`, `netbios`, `mdns` (type, name, port, txt), `ssdp` (server, st, usn, location,
friendly_name, manufacturer, model_name, model_number, model_description, device_type),
`http` (port, title, server, favicon_hash, markers), `open_ports`, `ttl`, `dhcp_vendor`,
`extra` (free-form facts such as `gateway=1` or `miwifi.model=...`).

Helpers for collectors:

- `netprint.fingerprint_ports()` — every TCP port a rule looks at (what to probe).
- `netprint.find_markers(html)` — product words in a page body (`esphome`, `mainsail`,
  `miwifi`, ...), for `HttpService.markers`.
- `netprint.vendor(mac)`, `netprint.is_locally_administered(mac)`.
- `netprint.is_generic_name(name)` — `android-1f2e...`, `ESP_1A2B3C`, `wlan0` and friends.

Local rules: `load_db([Path("my-rules/")])` adds rule files; a rule with the id of a shipped
rule replaces it (set `"weight": 0` to disable one).

## How scoring works

Every rule that matches is evidence of weight *w* for its category. Evidence for one category
combines as a noisy-OR, `1 - Π(1 - w)`: two independent 0.6 hints make 0.84, and nothing is
ever certain (confidence is capped at 0.99). Negative weights and `demote` lower a category.
The best category wins if it reaches 0.2; otherwise the device is `unknown`.

## CLI

```
python -m netprint classify device.json [--rules my-rules/] [--json]
python -m netprint lint [--rules my-rules/]
python -m netprint categories
python -m netprint oui-update            # maintainers: refresh data/oui.tsv.gz from the IEEE
```

## Privacy

Fixtures are synthetic: MACs end in `00:00:NN`, addresses come from documentation ranges, and
names are made up. `test_fixtures_are_synthetic` enforces it. Never commit captures from a
real network.

## License

MIT. The OUI table is derived from the public IEEE registry.
