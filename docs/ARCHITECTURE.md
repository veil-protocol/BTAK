# Architecture

## Overview

BTAK is a three-component system: a Python poller, a Python HTTP server, and a browser-based canvas frontend. There is no database, no message queue, and no build system. The poller writes JSON files to disk; the HTTP server serves them; the frontend polls them.

## Data Flow

```
Elasticsearch (Suricata + Zeek indices)
        |
        v
   Poller (Python, every 2s)
   - 10 ES queries per cycle
   - Classify each event into kill chain phase
   - Deduplicate by ES document ID
   - Filter infrastructure noise
   - Fair-share balance across students
   - Write events.json + debug.json (atomic rename)
        |
        v
   Static Files (events.json, debug.json)
        |
        v
   HTTP Server (Python, port 80)
   - Serves static files
   - /clear endpoint (trigger file)
   - /archives endpoint (list JSON)
        |
        v
   Browser Frontend (HTML5 Canvas)
   - Polls events.json every 2s
   - Draws animated arcs (attacker -> target)
   - Color-coded by kill chain phase
   - Smart feed deduplication
   - Debug overlay (press D)
```

## Poller Classification Pipeline

Each event passes through a multi-stage classification pipeline:

1. **Source routing** -- Events are routed based on their origin index (Suricata alert, Zeek HTTP, Zeek conn, Zeek software, Zeek notice, Zeek weird, IDS detection).

2. **Signature matching** -- Suricata alerts are classified by signature keywords (TROJAN, EXPLOIT, BRUTE, etc.) and classtype mapping (19 Suricata categories mapped to 5 kill chain phases).

3. **User-agent fingerprinting** -- Zeek HTTP events are matched against 237 offensive tool signatures organized by severity: shell (71 tools), exploit (30), auth (16), recon (57), scan (6).

4. **URI analysis** -- HTTP URIs are checked for exploit patterns (path traversal, SQL injection, command injection, webshell access) and administrative paths.

5. **Connection heuristics** -- Zeek conn logs without HTTP data are classified by destination port (SSH/RDP brute force on ports 22/3389/5900/445/139) and reverse shell callback detection (ports 4444, 1337, 9001, etc.).

6. **Behavioral detection** -- Zeek software.log entries are matched against the same UA fingerprint database. Zeek notice.log events are classified by notice type. Zeek weird.log entries are flagged as protocol anomalies.

## Fair-Share Algorithm

The fair-share algorithm prevents a single noisy student from monopolizing the event feed:

1. Group all events by source student name.
2. Reserve 1 slot per active student (guaranteed representation).
3. Fill remaining slots (up to `max_events_per_poll`) from the overflow pool, sorted by timestamp.
4. Filter infrastructure noise before allocation (prevents SOC-internal traffic from consuming slots).

## Session Management

Sessions auto-decay after a configurable period (default: 8 hours). Before reset, the current state is archived to a timestamped JSON file. Manual resets are triggered by the `/clear` HTTP endpoint, which creates a trigger file that the poller picks up on its next cycle. Only the last 20 archives are retained.

## Frontend Node Layout

The frontend uses a fixed layout computed from configuration arrays:

- **Attacker nodes** (terminals) are evenly spaced across the top of the canvas, grouped by team.
- **Target nodes** (servers) are evenly spaced across the bottom.
- IP addresses are mapped to nodes using a lookup table that includes real IPs and NETMAP VLAN translations.

Events spawn animated arcs (quadratic Bezier curves) and particles between nodes. Arcs fade over time. Nodes glow when active and dim when idle.

## Security Considerations

- Elasticsearch credentials are loaded from environment variables, never hardcoded.
- The `.env` file is created with mode 600 by the installer.
- The HTTP server runs on a configurable port and has no authentication (intended for internal lab networks only).
- SSL certificate verification for Elasticsearch is disabled by default (common for Security Onion self-signed certs).
