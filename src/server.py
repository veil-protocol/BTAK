#!/usr/bin/env python3
"""
Attack Map HTTP Server with /clear and /archives endpoints.
Serves static files on a configurable port, plus handles session management.
"""
import http.server
import json
import os
import sys

try:
    import yaml
    CONFIG_PATH = os.environ.get("ATTACKMAP_CONFIG", "/opt/btak/config.yaml")
    with open(CONFIG_PATH) as f:
        CFG = yaml.safe_load(f)
except Exception:
    CFG = {}

WEBROOT = os.environ.get("ATTACKMAP_WEBROOT", CFG.get("poller", {}).get("events_file", "/opt/btak/static/events.json").rsplit("/", 1)[0] if CFG else "/opt/btak/static")
CLEAR_TRIGGER = CFG.get("poller", {}).get("clear_trigger", "/opt/btak/static/clear.trigger")
HOST = CFG.get("server", {}).get("host", "0.0.0.0")
PORT = int(os.environ.get("ATTACKMAP_PORT", CFG.get("server", {}).get("port", 80)))

class MapHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEBROOT, **kwargs)

    def do_GET(self):
        if self.path == "/clear" or self.path == "/clear/":
            # Create trigger file -- poller picks it up next cycle
            try:
                with open(CLEAR_TRIGGER, "w") as f:
                    f.write("clear")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(b'{"status":"ok","message":"Session reset triggered. Map will clear in ~2 seconds."}')
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(f'{{"status":"error","message":"{e}"}}'.encode())
            return

        if self.path == "/config.json" or self.path == "/config.json/":
            # Serve frontend config generated from config.yaml
            # This eliminates the dual-config problem -- frontend reads from here
            try:
                students_cfg = CFG.get("students", {}).get("stations", [])
                targets_cfg = CFG.get("targets", [])
                netmap_cfg = CFG.get("netmap", {})
                site_name = CFG.get("site_name", "BTAK")
                brand = CFG.get("brand", "CYBER OPERATIONS CENTER")

                # Build GROUPS for frontend (split students into groups of 4-5)
                group_names = ["Alpha", "Bravo", "Charlie", "Delta", "Echo",
                               "Foxtrot", "Golf", "Hotel", "India", "Juliet"]
                group_colors = ["#4a9eff", "#5b7fff", "#6b6fff", "#7b5fff", "#8b4fff",
                                "#9b3fff", "#ab2fff", "#bb1fff", "#cb0fff", "#db00ff"]
                group_size = max(4, len(students_cfg) // min(len(group_names), max(1, len(students_cfg) // 4)))
                groups = []
                for i in range(0, len(students_cfg), group_size):
                    gi = i // group_size
                    chunk = students_cfg[i:i + group_size]
                    groups.append({
                        "name": group_names[gi % len(group_names)],
                        "students": [{"ip": s["ip"], "name": s["name"]} for s in chunk],
                        "color": group_colors[gi % len(group_colors)],
                    })

                # Build targets for frontend
                targets = [{"ip": t["ip"], "name": t["name"],
                            "color": "#ff6b4a" if "target" in t.get("role", "target") else "#ff4a8d"}
                           for t in targets_cfg]

                # NETMAP VLAN mappings
                vlans = netmap_cfg.get("vlans", []) if netmap_cfg.get("enabled", False) else []

                frontend_config = {
                    "site_name": site_name,
                    "brand": brand,
                    "groups": groups,
                    "targets": targets,
                    "netmap_vlans": vlans,
                }
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps(frontend_config).encode())
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(f'{{"error":"{e}"}}'.encode())
            return

        if self.path == "/archives" or self.path == "/archives/":
            # List archived sessions
            archive_dir = os.path.join(WEBROOT, "archive")
            try:
                files = sorted(os.listdir(archive_dir), reverse=True) if os.path.isdir(archive_dir) else []
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({"archives": files}).encode())
            except Exception as e:
                self.send_response(500)
                self.end_headers()
            return

        # Default: serve static files
        return super().do_GET()

    def log_message(self, format, *args):
        # Suppress access logs to keep journal clean
        pass

if __name__ == "__main__":
    server = http.server.HTTPServer((HOST, PORT), MapHandler)
    print(f"Attack Map HTTP Server on {HOST}:{PORT} (webroot: {WEBROOT})")
    server.serve_forever()
