# BTAK

Real-time attack visualization for Security Onion labs. Polls Elasticsearch for Suricata alerts, Zeek logs, and IDS detections, then renders animated attack arcs on a browser-based canvas map.

Built for cyber range and SOC training environments where instructors need a wall-mounted display showing who is attacking what, in real time.

## Features

- **Real-time visualization** -- animated arcs from attacker stations to target machines, color-coded by kill chain phase
- **Multi-source correlation** -- Suricata alerts, Zeek HTTP/conn/software/notice/weird logs, and high-severity IDS detections
- **237 offensive tool signatures** -- user-agent fingerprinting from mthcht/awesome-lists (Cobalt Strike, Sliver, sqlmap, Burp, nmap, etc.)
- **Kill chain classification** -- every event mapped to Scan, Recon, Exploit, Auth, or Shell phase
- **Fair-share algorithm** -- guarantees every active student gets map representation even when one station dominates traffic
- **Session management** -- auto-decay after configurable hours, manual reset via `/clear` endpoint, automatic archival
- **Debug overlay** -- press `D` in the browser for real-time poller diagnostics, phase breakdown, enrichment stats
- **Zero dependencies frontend** -- single HTML file, vanilla JS, HTML5 Canvas; no npm, no build step
- **YAML configuration** -- all IPs, targets, students, and tuning knobs in one config file

## Architecture

The system has three components that run independently:

**Poller** (`src/poller.py`) -- A Python daemon that queries Elasticsearch every 2 seconds. It pulls Suricata alerts (last 30 min), Zeek HTTP/conn/software/notice/weird logs (10-30 min windows), and high-severity IDS detections. Each event is classified into a kill chain phase using signature keyword matching, user-agent fingerprinting (237 patterns), and URI analysis. Events are deduplicated, filtered for infrastructure noise, balanced via fair-share allocation, and written to `events.json`.

**HTTP Server** (`src/server.py`) -- A lightweight Python HTTP server that serves the static frontend and exposes two API endpoints: `/clear` (trigger session reset) and `/archives` (list past sessions).

**Frontend** (`frontend/index.html`) -- A single-page canvas application that polls `events.json` every 2 seconds. Attacker stations are drawn as terminals at the top; targets as servers at the bottom. Events spawn animated particle arcs between nodes. A live feed panel shows the most recent events with smart deduplication (high-value events always shown; scan/recon collapsed per pair).

Data flow: `Elasticsearch --> Poller --> events.json --> Frontend`

## Prerequisites

- Security Onion 2.x (or any Elasticsearch instance with Suricata/Zeek indices)
- Python 3.10+
- `pyyaml` Python package
- Network access from the attack map host to Elasticsearch (port 9200)

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/yourorg/BTAK.git
cd BTAK

# 2. Run the installer (as root)
sudo bash install.sh

# 3. Edit the configuration
sudo nano /opt/BTAK/config.yaml

# 4. Start the services
sudo systemctl start attackmap-poller attackmap-http

# 5. Open in a browser
# http://<your-server-ip>/
```

## Configuration

All configuration lives in `/opt/BTAK/config.yaml` (copy from `config.example.yaml`).

| Section | Key | Default | Description |
|---------|-----|---------|-------------|
| `elasticsearch.host` | | `https://localhost:9200` | Elasticsearch URL |
| `elasticsearch.username` | | `so_elastic` | ES username |
| `poller.interval_seconds` | | `2` | Polling frequency |
| `poller.max_events_per_poll` | | `100` | Max events per cycle |
| `poller.session_decay_hours` | | `8` | Auto-reset interval |
| `server.port` | | `80` | HTTP server port |
| `students.stations` | | `[]` | Attacker station IPs and names |
| `targets` | | `[]` | Vulnerable target IPs and names |
| `netmap.enabled` | | `false` | Enable VLAN-based attribution |
| `netmap.vlans` | | `[120, 130, 140]` | VLAN IDs for NETMAP |
| `network.infrastructure_ips` | | `[]` | IPs to filter as noise |

Elasticsearch credentials should be set via the `ES_PASSWORD` environment variable, not in the config file.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Attack map frontend |
| `/events.json` | GET | Current event data (polled by frontend) |
| `/debug.json` | GET | Poller diagnostics, phase stats, student activity |
| `/clear` | GET | Trigger session reset (archived first) |
| `/archives` | GET | List archived session JSON files |

## Kill Chain Phases

| Phase | Color | Detection Sources | Signature Count |
|-------|-------|-------------------|-----------------|
| **Scan** | Blue | Nmap, masscan, Zeek conn, protocol anomalies | 6 UA + conn heuristics |
| **Recon** | Green | Gobuster, ffuf, Nikto, Nuclei, Zeek HTTP | 57 UA + URI patterns |
| **Exploit** | Orange | SQLmap, Metasploit, Burp, Suricata alerts | 30 UA + URI + alert rules |
| **Auth** | Yellow | Hydra, Kerbrute, brute-force detection | 16 UA + port heuristics |
| **Shell** | Pink | Cobalt Strike, Sliver, reverse shell ports, C2 UAs | 71 UA + port detection |

Total: **237 offensive tool user-agent signatures** plus Suricata classtype mapping, URI pattern matching, reverse shell port detection, and Zeek behavioral analysis.

## Performance

| Metric | Value |
|--------|-------|
| Poll interval | 2 seconds |
| ES queries per cycle | 10 (Suricata + 8 Zeek + detections) |
| Max events per cycle | 100 (configurable) |
| Frontend render | 60fps canvas animation |
| Memory footprint | ~30MB (poller) |
| Session archive | Auto-rotated, last 20 kept |

## Troubleshooting

**No events appearing on the map**
Check `debug.json` -- if `suricata_raw` and `zeek_raw` are both 0, verify Elasticsearch connectivity: `curl -k -u so_elastic:PASS https://localhost:9200/_cat/indices?v`

**Events in debug.json but no arcs on the map**
The frontend can only draw arcs between known nodes. Make sure the source/destination IPs in your events match the IPs defined in `config.yaml` under `students.stations` and `targets`. Check the `dropped` count in the debug overlay (press `D`).

**Poller crashes on startup**
Verify `config.yaml` syntax: `python3 -c "import yaml; yaml.safe_load(open('/opt/BTAK/config.yaml'))"`. Check that `ES_PASSWORD` is set in the environment or `.env` file.

**High dropped event count**
Events are dropped when source or destination IP cannot be mapped to a configured node. Add missing IPs to `students.stations`, `targets`, or `network.infrastructure_ips` (to filter noise).

**Session reset not working**
The `/clear` endpoint creates a trigger file that the poller picks up on its next cycle. Verify the poller is running: `systemctl status attackmap-poller`. Check that the `clear_trigger` path in config is writable.

## Project Structure

```
BTAK/
├── README.md
├── LICENSE
├── install.sh
├── config.example.yaml
├── src/
│   ├── poller.py           # ES polling, classification, fair-share
│   └── server.py           # HTTP server with /clear endpoint
├── frontend/
│   └── index.html          # Canvas visualization (single file)
├── rules/
│   ├── suricata/
│   │   ├── local.rules     # Custom Suricata rules for lab tools
│   │   └── threshold.conf  # Alert suppression
│   └── elastalert/         # ElastAlert rule templates
├── fixes/
│   ├── fix-elastic-agent-hosts.sh      # Fix EA hostname resolution
│   ├── fix-elastic-agent-hosts.service # Systemd oneshot for the fix
│   ├── fix-elastic-agent-hosts.cron    # Cron entry for periodic fix
│   └── logstash-mtls-fix.conf         # Logstash mTLS input config
├── systemd/
│   ├── attackmap-poller.service
│   └── attackmap-http.service
└── docs/
    ├── ARCHITECTURE.md
    └── TROUBLESHOOTING.md
```

## License

MIT License. See [LICENSE](LICENSE).
