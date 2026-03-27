# Troubleshooting

## Diagnostic Tools

**Debug JSON** -- The poller writes a diagnostic file every cycle:
```bash
cat /opt/btak/static/debug.json | python3 -m json.tool
```

Key fields to check:
- `poller.suricata_raw` -- number of Suricata events from last query
- `poller.zeek_raw` -- number of Zeek events from last query
- `poller.errors` -- any Elasticsearch query errors
- `poller.noise_filtered` -- events dropped as infrastructure noise
- `poller.deduped` -- duplicate events across sources
- `gaps` -- auto-detected issues (missing data sources, inactive students)

**Debug Overlay** -- Press `D` in the browser to toggle a real-time overlay showing phase breakdown, poller stats, active connections, and node mapping counts.

**Poller Log** -- Error-level events are written to `/tmp/poller.log`:
```bash
tail -f /tmp/poller.log
```

**Systemd Journals**:
```bash
journalctl -u attackmap-poller -f
journalctl -u attackmap-http -f
```

## Common Issues

### No events on the map

**Symptom**: Map loads but no arcs or events appear.

**Check 1**: Is the poller running?
```bash
systemctl status attackmap-poller
```

**Check 2**: Is events.json being written?
```bash
ls -la /opt/btak/static/events.json
```

**Check 3**: Can the poller reach Elasticsearch?
```bash
curl -sk -u so_elastic:$ES_PASSWORD https://localhost:9200/_cat/health
```

**Check 4**: Are there events in Elasticsearch?
```bash
curl -sk -u so_elastic:$ES_PASSWORD https://localhost:9200/.ds-so-suricata-*/_count
```

### Events in debug.json but no arcs

**Symptom**: `debug.json` shows events, but the map canvas is empty.

**Cause**: The frontend can only draw arcs between nodes it knows about. If source or destination IPs are not in the GROUPS or RANGE_TARGETS arrays in `index.html`, events are dropped client-side.

**Fix**: Check the `dropped` counter in the debug overlay (press `D`). Add missing IPs to the `students.stations` and `targets` sections of `config.yaml`, and update the `GROUPS` and `RANGE_TARGETS` arrays in `frontend/index.html` to match.

### High "dropped" count

**Symptom**: Debug overlay shows a large `dropped (no node)` count.

**Cause**: Events have source/destination IPs that do not match any configured node.

**Fix**:
1. Check `debug.json` for `enrichment.src_unresolved` and `dst_unresolved` counts.
2. Look at `recent_events` in `debug.json` to see which IPs are unresolved.
3. Either add the IPs to config, or add them to `network.infrastructure_ips` if they are noise.

### Poller crashes with "Config not found"

**Symptom**: Poller exits immediately with a config error.

**Fix**: Ensure `config.yaml` exists and the `ATTACKMAP_CONFIG` environment variable points to it:
```bash
ls -la /opt/btak/config.yaml
cat /opt/btak/.env
```

### Elasticsearch authentication errors

**Symptom**: `debug.json` shows query errors with 401 status.

**Fix**: Verify credentials:
```bash
source /opt/btak/.env
curl -sk -u so_elastic:$ES_PASSWORD https://localhost:9200/
```

If using Security Onion, the password is typically set during SO installation. Check with `so-elastic-auth`.

### Session not resetting

**Symptom**: `/clear` returns success but the map does not reset.

**Check**: The `/clear` endpoint creates a trigger file. The poller checks for this file at the start of each cycle (every 2 seconds). Verify:
```bash
# Trigger manually
touch /opt/btak/static/clear.trigger
# Check if poller picks it up
tail -f /tmp/poller.log
```

### Elastic Agent not shipping logs

**Symptom**: Suricata and Zeek indices have no recent data.

This is a Security Onion issue, not an attack map issue. The `fixes/` directory contains workarounds:

```bash
# Fix elastic-agent hostname resolution
sudo bash fixes/fix-elastic-agent-hosts.sh

# Install as a cron job for persistence
sudo cp fixes/fix-elastic-agent-hosts.cron /etc/cron.d/fix-elastic-agent-hosts
```

### Frontend shows "POLL ERROR"

**Symptom**: Debug overlay shows a red POLL ERROR message.

**Cause**: The frontend cannot fetch or parse `events.json`.

**Check**: Open `http://<server>/events.json` directly in the browser. If it returns an error or malformed JSON, check poller logs.

## Performance Tuning

**Reduce ES load**: Increase `poller.interval_seconds` from 2 to 5 or 10.

**Reduce event volume**: Lower `poller.max_events_per_poll` from 100 to 50.

**Shorter sessions**: Reduce `poller.session_decay_hours` for more frequent resets.

**Filter noise**: Add noisy IPs to `network.infrastructure_ips` so they are dropped before the fair-share algorithm runs.
