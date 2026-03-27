#!/usr/bin/env python3
"""
Attack Map Poller — ES-direct, multi-source, with debug.json output.
Sources: Suricata alerts, Zeek HTTP/conn/software/notice/weird, SO Detections (Sigma/YARA)
Outputs: events.json (map feed) + debug.json (machine-readable diagnostics)
UA detection: 237 offensive tool signatures (mthcht/awesome-lists)
Features: Auto-decay session reset + manual clear trigger + archive before reset

Requires: pyyaml (`pip install pyyaml`)
"""
import json, time, os, sys, urllib.request, ssl, base64, shutil, glob
import yaml

# ─── Configuration ───
CONFIG_PATH = os.environ.get("ATTACKMAP_CONFIG", "/opt/btak/config.yaml")

def load_config():
    try:
        with open(CONFIG_PATH) as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Config not found at {CONFIG_PATH}. Copy config.example.yaml and customize.")
        print("Or set ATTACKMAP_CONFIG env var to your config path.")
        sys.exit(1)

CFG = load_config()

ES = CFG.get("elasticsearch", {}).get("host", "https://localhost:9200")
_user = CFG.get("elasticsearch", {}).get("username", "so_elastic")
_pass = os.environ.get("ES_PASSWORD", CFG.get("elasticsearch", {}).get("password", ""))
AUTH = base64.b64encode(f"{_user}:{_pass}".encode()).decode()

OUT = CFG.get("poller", {}).get("events_file", "/opt/btak/static/events.json")
DEBUG_OUT = CFG.get("poller", {}).get("debug_file", "/opt/btak/static/debug.json")
ARCHIVE_DIR = CFG.get("poller", {}).get("archive_dir", "/opt/btak/static/archive")
CLEAR_TRIGGER = CFG.get("poller", {}).get("clear_trigger", "/opt/btak/static/clear.trigger")
POLL_INTERVAL = CFG.get("poller", {}).get("interval_seconds", 2)

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

# ─── Local IP → name map (never depends on ES enrichment) ───
IP_NAME = {}

# Load targets from config
for target in CFG.get("targets", []):
    IP_NAME[target["ip"]] = target["name"]

# Load students from config
student_cfg = CFG.get("students", {})
for student in student_cfg.get("stations", []):
    IP_NAME[student["ip"]] = student["name"]
    # Add NETMAP VLANs if enabled
    if CFG.get("netmap", {}).get("enabled", False):
        n = int(student["ip"].split(".")[-1])
        for vlan in CFG.get("netmap", {}).get("vlans", []):
            IP_NAME[f"10.{vlan}.0.{n}"] = student["name"]

def resolve_name(ip, lab_field):
    """Get vm_name from ES enrichment or local IP map."""
    if lab_field and lab_field.get("vm_name"):
        return lab_field["vm_name"]
    return IP_NAME.get(ip, "")

# Infrastructure IPs to filter from the events feed (SOC internal noise)
INFRA_NOISE = set(CFG.get("network", {}).get("infrastructure_ips", []))

def is_noise(src_ip, dest_ip):
    """Return True if both src and dst are infrastructure (not student/target traffic)."""
    return src_ip in INFRA_NOISE or (src_ip not in IP_NAME and dest_ip not in IP_NAME and not src_ip.startswith("10.10.0."))

# ─── Persistent state across cycles ───
cycle_count = 0
cumulative = {"scan":0,"recon":0,"exploit":0,"auth":0,"shell":0,"total":0}
all_students = {}   # {vm_name: {events, targets: set, phases: {}}}
all_targets = {}    # {ip: {name, events}}
recent_events = []  # rolling last 100

# ─── Session management (auto-decay + manual clear) ───
SESSION_DURATION = CFG.get("poller", {}).get("session_decay_hours", 8) * 3600
session_start = time.time()

def archive_state(reason="auto"):
    """Save current state to archive before clearing. Nothing is lost."""
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S", time.localtime())
    archive = {
        "archived_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "reason": reason,
        "session_duration_hours": round((time.time() - session_start) / 3600, 1),
        "cycle_count": cycle_count,
        "phases_cumulative": dict(cumulative),
        "students": {k: {"events": v["events"], "targets": sorted(v["targets"]), "phases": v["phases"]} for k, v in all_students.items()},
        "targets": dict(all_targets),
        "recent_events": recent_events[-50:],
    }
    path = os.path.join(ARCHIVE_DIR, f"session-{ts}-{reason}.json")
    try:
        with open(path, "w") as f:
            json.dump(archive, f, indent=1)
        # Keep only last 20 archives
        archives = sorted(glob.glob(os.path.join(ARCHIVE_DIR, "session-*.json")))
        for old in archives[:-20]:
            os.remove(old)
    except Exception as e:
        with open("/tmp/poller.log", "a") as f:
            f.write(f"{time.strftime('%H:%M:%S')} ARCHIVE ERROR: {e}\n")
    return path

def reset_state():
    """Clear all cumulative counters. Called after archiving."""
    global cycle_count, cumulative, all_students, all_targets, recent_events, session_start
    cycle_count = 0
    cumulative = {"scan":0,"recon":0,"exploit":0,"auth":0,"shell":0,"total":0}
    all_students = {}
    all_targets = {}
    recent_events = []
    session_start = time.time()

def check_session():
    """Check for auto-decay or manual clear trigger."""
    global session_start
    cleared = False
    reason = None

    # Manual clear trigger (file-based)
    if os.path.exists(CLEAR_TRIGGER):
        try:
            os.remove(CLEAR_TRIGGER)
        except: pass
        reason = "manual"
        cleared = True

    # Auto-decay after SESSION_DURATION
    elif (time.time() - session_start) > SESSION_DURATION:
        reason = f"auto-{CFG.get('poller', {}).get('session_decay_hours', 8)}h"
        cleared = True

    if cleared:
        path = archive_state(reason=reason)
        reset_state()
        with open("/tmp/poller.log", "a") as f:
            f.write(f"{time.strftime('%H:%M:%S')} SESSION RESET ({reason}): archived to {path}\n")
    return cleared

# ─── Suricata classtype → phase ───
SURI_CATEGORY_MAP = {
    "a network trojan was detected":"shell","trojan-activity":"shell",
    "shellcode-detect":"shell","successful-admin":"shell","successful-user":"shell",
    "web-application-attack":"exploit","attempted-admin":"exploit",
    "web-application-activity":"exploit","attempted-dos":"exploit",
    "default-login-attempt":"auth","unsuccessful-user":"auth","credential-theft":"auth",
    "network-scan":"scan","potentially bad traffic":"scan",
    "attempted information leak":"recon","attempted-recon":"recon",
    "misc-activity":"recon","protocol-command-decode":"recon",
    "policy-violation":"recon","not-suspicious":"recon",
}
SURI_SIG_MAP = [
    (["TROJAN","BACKDOOR","C2","BEACON","REVERSE","SHELL","MALWARE"], "shell"),
    (["EXPLOIT","WEB_SERVER","ATTACK_RESPONSE","RCE","OVERFLOW","INJECTION","CVE"], "exploit"),
    (["BRUTE","LOGIN","CREDENTIAL","PASSWORD","PHISHING"], "auth"),
    (["MYSQL","MSSQL","ORACLE","POSTGRES","VNC","SSH","NMAP","OS DETECT","FINGER"], "recon"),
    (["SCAN"], "scan"),
]

# ─── Comprehensive offensive tool UA detection (237 signatures from mthcht/awesome-lists) ───
UA_SHELL = ["9002rat","antsword","arbitrium-rat","arkei stealer","asyncrat","awscli","brute ratel","bunnyloader","canisrufus","caploader","ccminer","clipper-socket","cloudflarepagesredirector","cobalt","coin miner","cryptominer","cuba ransomware","darkcloud","darkrat","decoyloader","dslog backdoor","empire","enigma stealer","ethernity clipper stealer","fakebat","formbook","gh0strat","graphstrike","havoc","helpud","janelarat","katz stealer","lemon-duck","loki","lokibot","lumma stealer","lummastealer","malware","matanbuchus 3.0","medusastealer","mirai","mirai botnet","mythic","netsupport","netsupport rat","ngrok","nighthawk","nimplant","nitedrem","picosh","poshc2","power automate","pyramid","raccoon stealer","remoteit","robotdropper","serverlessredirector","silver","sliver","smartloader","specula","ssload","stratus red team","trident ursa","trojanproxy","trokanclicker","tunnelto","uncommun user agent","unk backdoor","villain","xmrig","zerodium backdoor"]
UA_EXPLOIT = ["/bin/bash","/etc/passwd","127.0.0.1","; echo $","aiohttp/","azurecli","burp","cmd.exe","commix","cve-2021-21985 poc","dalfox","dirtycow","evilginx","exploitation","kali linux","lilin dvr rce","log4j exploitation","metasploit","mitmproxy","pacu","pivotnacci","reac2shell","redpill","roadtools","ruler","sqlmap","tokenflare","tplmap","xsstrike","ysoserial"]
UA_AUTH = ["bav2ropc","cr3dov3r","credmaster","devicecodephishing","hydra","kerbrute","krbrelayup","lyncsmash","raccoono365","rubeus","shadowspray","spraycharles","sprayhound","teamfiltration","thc-hydra","trevorspray"]
UA_RECON = ["aadinternals","acunetix","amass","arachni","argus","arjun","axios","azurehound","bloodhound","callstranger","certipy","cmseek","curl","dirb","dirbuster","dirhunt","dnstwist","droopescan","fasthttp","feroxbuster","ffuf","gau","go-http-client","gobuster","hakrawler","httpie","httpx","joomscan","katana","nessus","nikto","node-fetch","nuclei","openvas","owasp","paramspider","pcapxray","pingcastle","python","python-requests","python-urllib","scrapy","sharpbuster","sslscan","sslyze","subfinder","testssl","trufflehog","undici","wafw00f","waybackurls","wfuzz","wget","whatweb","wpscan","yakit","zaproxy","zoho assist"]
UA_SCAN = ["angryip","masscan","nmap","rustscan","unicornscan","zmap"]

# ─── Reverse shell callback ports ───
REVSHELL_PORTS = {4444, 1337, 9001, 5555, 6666, 8888, 1234, 31337, 9999}

def classify_suricata(alert):
    sig = alert.get("signature", "")
    sig_upper = sig.upper()
    for keywords, phase in SURI_SIG_MAP:
        if any(kw in sig_upper for kw in keywords):
            return phase, sig
    phase = SURI_CATEGORY_MAP.get(alert.get("category", "").lower())
    if phase: return phase, sig
    return "scan", sig

def classify_zeek_http(msg):
    ua = msg.get("user_agent", "").lower()
    uri = msg.get("uri", "") or ""
    method = msg.get("method", "") or ""
    status = msg.get("status_code", 0)
    # Check UA against 237 offensive tool signatures (ordered by severity)
    if any(x in ua for x in UA_SHELL):
        return "shell", f"C2/malware UA: {msg.get('user_agent','')[:40]}"
    if any(x in ua for x in UA_AUTH):
        return "auth", f"Brute force tool: {msg.get('user_agent','')[:40]}"
    if any(x in ua for x in UA_EXPLOIT):
        return "exploit", f"Exploit tool: {msg.get('user_agent','')[:40]}"
    if any(x in ua for x in UA_SCAN):
        return "scan", f"Scanner: {msg.get('user_agent','')[:40]}"
    if any(x in ua for x in UA_RECON):
        return "recon", f"Recon tool: {msg.get('user_agent','')[:40]}"
    # URI-based classification
    if method == "POST" and any(x in uri for x in ["wp-login","xmlrpc","login","auth","admin","signin"]):
        return "auth", f"POST {uri[:40]}"
    if any(x in uri for x in ["etc/passwd","etc/shadow","../","<script","UNION","SELECT","1=1","cmd=","exec(","eval(","system(","phpinfo","%00",".env",".git/config"]):
        return "exploit", f"{method} {uri[:50]}"
    if any(x in uri.lower() for x in ["shell","c99","r57","webshell","reverse","backdoor",".php?cmd"]):
        return "shell", f"{method} {uri[:50]}"
    if status and status < 400 and any(x in uri for x in ["/admin","/wp-admin","/manager","/phpmyadmin"]):
        return "recon", f"{method} {uri[:40]} [{status}]"
    if method:
        return "recon", f"{method} {uri[:40]}"
    return "recon", uri[:40] if uri else "http connection"

def classify_zeek_software(msg):
    name = msg.get("name", "").lower()
    unparsed = msg.get("unparsed_version", "").lower()
    combined = f"{name} {unparsed}"
    if any(x in combined for x in ["shellshock","() {","){ :; }"]):
        return "exploit", "Shellshock payload detected"
    if any(x in combined for x in UA_SCAN):
        return "scan", f"Scanner fingerprint: {name}"
    if any(x in combined for x in UA_EXPLOIT):
        return "exploit", f"Exploit tool: {name}"
    if any(x in combined for x in UA_RECON):
        return "recon", f"Recon tool: {name}"
    if any(x in combined for x in UA_AUTH):
        return "auth", f"Brute forcer: {name}"
    if any(x in combined for x in UA_SHELL):
        return "shell", f"C2 tool: {name}"
    return "recon", f"Software: {name}"

def classify_zeek_notice(msg):
    note = msg.get("note", "").lower()
    notice_msg = msg.get("msg", "")
    if any(x in note for x in ["scan","portscan","address_scan","port_scan"]):
        return "scan", f"Zeek notice: {notice_msg[:60]}"
    if any(x in note for x in ["ssl","certificate","expired"]):
        return "recon", f"Zeek SSL: {notice_msg[:60]}"
    if any(x in note for x in ["exploit","attack","injection"]):
        return "exploit", f"Zeek alert: {notice_msg[:60]}"
    return "recon", f"Zeek notice: {notice_msg[:60]}"

def classify_detection(det):
    pid = det.get("publicId", "")
    title = det.get("title", "")
    combined = (pid + " " + title).upper()
    if any(x in combined for x in ["SHELL","MALWARE","TROJAN","C2","BEACON","BACKDOOR"]):
        return "shell", title or pid
    if any(x in combined for x in ["EXPLOIT","CVE","INJECTION","VULN","ATTACK"]):
        return "exploit", title or pid
    if any(x in combined for x in ["BRUTE","LOGIN","CREDENTIAL","PASSWORD","AUTH"]):
        return "auth", title or pid
    if any(x in combined for x in ["SCAN","DISCOVERY","ENUM"]):
        return "scan", title or pid
    return "recon", title or pid

def es_search(index, body):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{ES}/{index}/_search", data=data,
        headers={"Content-Type":"application/json","Authorization":f"Basic {AUTH}"},
        method="POST"
    )
    try:
        t0 = time.time()
        with urllib.request.urlopen(req, context=CTX, timeout=8) as resp:
            result = json.loads(resp.read())
        result["_query_ms"] = int((time.time() - t0) * 1000)
        return result
    except Exception as e:
        return {"_error": str(e), "_query_ms": 0}

def track_event(debug, src_lab, dest_lab, phase, sig, src_ip, dest_ip, ts):
    """Update debug stats for one event."""
    debug["phases"][phase] = debug["phases"].get(phase, 0) + 1

    # Resolve names via ES enrichment OR local IP map
    src_name = resolve_name(src_ip, src_lab)
    dst_name = resolve_name(dest_ip, dest_lab)

    # Enrichment tracking (counts local resolution too)
    debug["enrichment"]["src_resolved" if src_name else "src_unresolved"] += 1
    debug["enrichment"]["dst_resolved" if dst_name else "dst_unresolved"] += 1

    # Per-student tracking
    if src_name and src_name.startswith("kali-"):
        if src_name not in all_students:
            all_students[src_name] = {"events": 0, "targets": set(), "phases": {}}
        all_students[src_name]["events"] += 1
        all_students[src_name]["phases"][phase] = all_students[src_name]["phases"].get(phase, 0) + 1
        if dst_name:
            all_students[src_name]["targets"].add(dst_name)

    # Per-target tracking
    if dest_ip:
        if dest_ip not in all_targets:
            all_targets[dest_ip] = {"name": dst_name or dest_ip, "events": 0}
        all_targets[dest_ip]["events"] += 1

    # Recent events
    recent_events.append({
        "src": src_name or src_ip,
        "dst": dst_name or dest_ip,
        "phase": phase,
        "sig": sig[:80],
        "ts": ts[11:19] if ts and len(ts) > 19 else ts,
    })
    if len(recent_events) > 100:
        recent_events.pop(0)

    cumulative[phase] = cumulative.get(phase, 0) + 1
    cumulative["total"] += 1

def poll():
    global cycle_count
    cycle_count += 1
    hits = []
    seen = set()
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # Debug state for this cycle
    debug = {
        "ts": now,
        "cycle": cycle_count,
        "poller": {"suricata_raw":0,"zeek_raw":0,"sigma_raw":0,"deduped":0,"final_events":0,"query_ms":[],"errors":[]},
        "phases": {},
        "enrichment": {"src_resolved":0,"src_unresolved":0,"dst_resolved":0,"dst_unresolved":0},
    }

    # ─── Elasticsearch index patterns from config ───
    suri_index = CFG.get("indices", {}).get("suricata", ".ds-so-suricata-*")
    zeek_index = CFG.get("indices", {}).get("zeek", ".ds-so-zeek-*")

    # ─── Source 1: Suricata alerts ───
    r = es_search(suri_index, {
        "size": 50, "sort": [{"@timestamp": "desc"}],
        "_source": ["@timestamp","src_ip","dest_ip","dest_port","alert","src_lab","dest_lab"],
        "query": {"range": {"@timestamp": {"gte": "now-30m"}}}
    })
    debug["poller"]["query_ms"].append(r.get("_query_ms", 0))
    if r.get("_error"):
        debug["poller"]["errors"].append(f"suricata: {r['_error']}")
    suri_hits = r.get("hits",{}).get("hits",[])
    debug["poller"]["suricata_raw"] = len(suri_hits)
    for h in suri_hits:
        s = h["_source"]
        fid = h["_id"]
        if fid in seen:
            debug["poller"]["deduped"] += 1
            continue
        seen.add(fid)
        phase, sig = classify_suricata(s.get("alert", {}))
        track_event(debug, s.get("src_lab"), s.get("dest_lab"), phase, sig, s.get("src_ip",""), s.get("dest_ip",""), s.get("@timestamp",""))
        hits.append({"_id": fid, "_source": {
            "@timestamp": s.get("@timestamp",""),
            "src_ip": s.get("src_ip",""), "dest_ip": s.get("dest_ip",""),
            "dest_port": s.get("dest_port",""),
            "alert": {"signature": sig, "category": phase},
            "src_lab": s.get("src_lab", {}), "dest_lab": s.get("dest_lab", {}),
        }})

    # ─── Source 2: Zeek — targeted queries per attack phase ───
    zeek_base = ["@timestamp","src_ip","dest_ip","dest_port","src_lab","dest_lab","message","log"]
    zeek_queries = [
        ("exploit", {"bool":{"filter":[
            {"range":{"@timestamp":{"gte":"now-30m"}}},
            {"bool":{"should":[{"wildcard":{"log.file.path":"*http*"}},{"wildcard":{"log.file.path":"*conn*"}}],"minimum_should_match":1}},
            {"bool":{"should":[
                {"wildcard":{"message":"*nikto*"}},{"wildcard":{"message":"*sqlmap*"}},
                {"wildcard":{"message":"*wpscan*"}},{"wildcard":{"message":"*etc/passwd*"}},
                {"wildcard":{"message":"*<script*"}},{"wildcard":{"message":"*UNION*"}},
                {"wildcard":{"message":"*cmd=*"}},{"wildcard":{"message":"*shell*"}},
                {"wildcard":{"message":"*exec*"}},{"wildcard":{"message":"*revslider*"}},
                {"wildcard":{"message":"*vulnerabilities*"}},{"wildcard":{"message":"*injection*"}},
            ],"minimum_should_match":1}}
        ]}}, 50),
        ("auth", {"bool":{"filter":[
            {"range":{"@timestamp":{"gte":"now-30m"}}},
            {"wildcard":{"log.file.path":"*http*"}},
            {"bool":{"should":[
                {"wildcard":{"message":"*wp-login*"}},{"wildcard":{"message":"*xmlrpc*"}},
                {"wildcard":{"message":"*login*"}},{"wildcard":{"message":"*brute*"}},
                {"wildcard":{"message":"*POST*"}},
            ],"minimum_should_match":1}}
        ]}}, 30),
        ("recon", {"bool":{"filter":[
            {"range":{"@timestamp":{"gte":"now-15m"}}},
            {"wildcard":{"log.file.path":"*http*"}}
        ]}}, 50),
        # Zeek conn logs — catch port scans (NULL, SYN, FIN, Xmas) that have no HTTP
        ("scan", {"bool":{"filter":[
            {"range":{"@timestamp":{"gte":"now-10m"}}},
            {"wildcard":{"log.file.path":"*conn*"}},
            {"bool":{"must_not":[{"wildcard":{"log.file.path":"*http*"}}]}},
        ]}}, 50),
        # Zeek conn logs — catch brute force (many connections to same port from same src)
        ("auth", {"bool":{"filter":[
            {"range":{"@timestamp":{"gte":"now-10m"}}},
            {"wildcard":{"log.file.path":"*conn*"}},
            {"bool":{"must_not":[{"wildcard":{"log.file.path":"*http*"}}]}},
            {"terms":{"dest_port": [22, 3389, 5900, 445, 139]}},
        ]}}, 30),
        # Zeek software.log — detect offensive tool fingerprints
        ("software", {"bool":{"filter":[{"range":{"@timestamp":{"gte":"now-15m"}}},{"wildcard":{"log.file.path":"*software*"}}]}}, 20),
        # Zeek notice.log — detect scan/exploit notices
        ("notice", {"bool":{"filter":[{"range":{"@timestamp":{"gte":"now-15m"}}},{"wildcard":{"log.file.path":"*notice*"}}]}}, 20),
        # Zeek weird.log — detect protocol anomalies
        ("weird", {"bool":{"filter":[{"range":{"@timestamp":{"gte":"now-10m"}}},{"wildcard":{"log.file.path":"*weird*"}}]}}, 20),
    ]
    for phase_hint, query, limit in zeek_queries:
        r = es_search(zeek_index, {"size": limit, "sort": [{"@timestamp": "desc"}], "_source": zeek_base, "query": query})
        debug["poller"]["query_ms"].append(r.get("_query_ms", 0))
        if r.get("_error"):
            debug["poller"]["errors"].append(f"zeek_{phase_hint}: {r['_error']}")
        zeek_hits = r.get("hits",{}).get("hits",[])
        debug["poller"]["zeek_raw"] += len(zeek_hits)
        for h in zeek_hits:
            s = h["_source"]
            fid = h["_id"]
            if fid in seen:
                debug["poller"]["deduped"] += 1
                continue
            seen.add(fid)
            msg = {}
            try:
                raw = s.get("message","")
                if isinstance(raw, str) and raw.startswith("{"):
                    msg = json.loads(raw)
            except: pass
            if phase_hint == "software":
                if not msg.get("name"): continue
                phase, sig = classify_zeek_software(msg)
                src_ip = s.get("src_ip","") or msg.get("host","")
                dest_ip = s.get("dest_ip","") or ""
                track_event(debug, s.get("src_lab"), s.get("dest_lab"), phase, sig, src_ip, dest_ip, s.get("@timestamp",""))
                hits.append({"_id": fid, "_source": {"@timestamp": s.get("@timestamp",""), "src_ip": src_ip, "dest_ip": dest_ip, "dest_port": s.get("dest_port",""), "alert": {"signature": sig, "category": phase}, "src_lab": s.get("src_lab", {}), "dest_lab": s.get("dest_lab", {})}})
                continue
            if phase_hint == "notice":
                if not msg.get("note"): continue
                phase, sig = classify_zeek_notice(msg)
                src_ip = s.get("src_ip","") or msg.get("src","")
                dest_ip = s.get("dest_ip","") or msg.get("dst","")
                track_event(debug, s.get("src_lab"), s.get("dest_lab"), phase, sig, src_ip, dest_ip, s.get("@timestamp",""))
                hits.append({"_id": fid, "_source": {"@timestamp": s.get("@timestamp",""), "src_ip": src_ip, "dest_ip": dest_ip, "dest_port": s.get("dest_port",""), "alert": {"signature": sig, "category": phase}, "src_lab": s.get("src_lab", {}), "dest_lab": s.get("dest_lab", {})}})
                continue
            if phase_hint == "weird":
                name = msg.get("name", "unknown")
                src_ip = s.get("src_ip","") or msg.get("id.orig_h","")
                dest_ip = s.get("dest_ip","") or msg.get("id.resp_h","")
                track_event(debug, s.get("src_lab"), s.get("dest_lab"), "scan", f"Protocol anomaly: {name}", src_ip, dest_ip, s.get("@timestamp",""))
                hits.append({"_id": fid, "_source": {"@timestamp": s.get("@timestamp",""), "src_ip": src_ip, "dest_ip": dest_ip, "dest_port": s.get("dest_port",""), "alert": {"signature": f"Protocol anomaly: {name}", "category": "scan"}, "src_lab": s.get("src_lab", {}), "dest_lab": s.get("dest_lab", {})}})
                continue
            if not msg.get("method"):
                # Conn log entry (no HTTP method)
                if not msg.get("id.orig_h"): continue
                proto = msg.get("proto","tcp")
                history = msg.get("history","")
                resp_p = msg.get("id.resp_p","")
                # Check if this looks like auth brute force
                if resp_p in [22, 3389, 5900, 445, 139]:
                    phase = "auth"
                    sig = f"SSH/RDP brute attempt port {resp_p}"
                elif isinstance(resp_p, int) and resp_p in REVSHELL_PORTS:
                    phase = "shell"
                    sig = f"Reverse shell callback port {resp_p}"
                else:
                    phase = "scan"
                    sig = f"{proto.upper()} port {resp_p}"
                if history:
                    sig += f" [{history}]"
                src_ip = s.get("src_ip","") or msg.get("id.orig_h","")
                dest_ip = s.get("dest_ip","") or msg.get("id.resp_h","")
                track_event(debug, s.get("src_lab"), s.get("dest_lab"), phase, sig, src_ip, dest_ip, s.get("@timestamp",""))
                hits.append({"_id": fid, "_source": {
                    "@timestamp": s.get("@timestamp",""),
                    "src_ip": src_ip, "dest_ip": dest_ip,
                    "dest_port": s.get("dest_port","") or str(resp_p),
                    "alert": {"signature": sig, "category": phase},
                    "src_lab": s.get("src_lab", {}), "dest_lab": s.get("dest_lab", {}),
                }})
                continue
            phase, sig = classify_zeek_http(msg)
            src_ip = s.get("src_ip","") or msg.get("id.orig_h","")
            dest_ip = s.get("dest_ip","") or msg.get("id.resp_h","")
            track_event(debug, s.get("src_lab"), s.get("dest_lab"), phase, sig, src_ip, dest_ip, s.get("@timestamp",""))
            hits.append({"_id": fid, "_source": {
                "@timestamp": s.get("@timestamp",""),
                "src_ip": src_ip, "dest_ip": dest_ip,
                "dest_port": s.get("dest_port","") or msg.get("id.resp_p",""),
                "alert": {"signature": sig, "category": phase},
                "src_lab": s.get("src_lab", {}), "dest_lab": s.get("dest_lab", {}),
            }})

    # ─── Source 3: IDS Detections (Suricata high-value alerts) ───
    r = es_search(suri_index, {
        "size": 30, "sort": [{"@timestamp": "desc"}],
        "_source": ["@timestamp","src_ip","dest_ip","dest_port","alert","src_lab","dest_lab"],
        "query": {"bool": {"must": [
            {"range": {"@timestamp": {"gte": "now-30m"}}},
            {"term": {"event_type": "alert"}},
            {"range": {"alert.severity": {"lte": 2}}}
        ]}}
    })
    debug["poller"]["query_ms"].append(r.get("_query_ms", 0))
    if r.get("_error"):
        debug["poller"]["errors"].append(f"detections: {r['_error']}")
    sigma_hits = r.get("hits",{}).get("hits",[])
    debug["poller"]["sigma_raw"] = len(sigma_hits)
    for h in sigma_hits:
        s = h["_source"]
        fid = "det_" + h["_id"]
        if fid in seen:
            debug["poller"]["deduped"] += 1
            continue
        seen.add(fid)
        alert = s.get("alert", {})
        phase, sig = classify_suricata(alert)
        src_ip = s.get("src_ip", "")
        dst_ip = s.get("dest_ip", "")
        track_event(debug, s.get("src_lab"), s.get("dest_lab"), phase, f"[DETECTION] {sig}", src_ip, dst_ip, s.get("@timestamp",""))
        hits.append({"_id": fid, "_source": {
            "@timestamp": s.get("@timestamp",""),
            "src_ip": src_ip, "dest_ip": dst_ip, "dest_port": s.get("dest_port", ""),
            "alert": {"signature": f"[DETECTION] {sig}", "category": phase},
            "src_lab": s.get("src_lab", {}), "dest_lab": s.get("dest_lab", {}),
        }})

    # ─── Sort and cap with fair-share per student ───
    # Ensure every active student gets at least 1 event in the feed
    # so all active stations show arcs on the map, even when one dominates volume

    # Group ALL hits by source student, filtering out infrastructure noise
    by_student = {}  # {student_name: [hits]}
    no_student = []  # hits without a student source (but still relevant)
    noise_count = 0
    for h in hits:
        src_ip = h["_source"].get("src_ip","")
        dest_ip = h["_source"].get("dest_ip","")
        # Skip infrastructure noise (SOC-to-SOC, infra-to-infra)
        if is_noise(src_ip, dest_ip):
            noise_count += 1
            continue
        src_name = resolve_name(src_ip, h["_source"].get("src_lab"))
        if src_name and src_name.startswith("kali-"):
            by_student.setdefault(src_name, []).append(h)
        else:
            no_student.append(h)
    debug["poller"]["noise_filtered"] = noise_count

    # Phase 1: Guarantee 1 newest event per student (up to 25 slots reserved)
    student_guaranteed = []
    student_overflow = []
    for student_name in sorted(by_student.keys()):
        student_events = sorted(by_student[student_name], key=lambda h: h["_source"].get("@timestamp",""), reverse=True)
        if student_events:
            student_guaranteed.append(student_events[0])
            student_overflow.extend(student_events[1:])

    # Phase 2: Fill remaining 75+ slots by timestamp from overflow + non-student
    overflow_pool = sorted(student_overflow + no_student, key=lambda h: h["_source"].get("@timestamp",""), reverse=True)
    max_events = CFG.get("poller", {}).get("max_events_per_poll", 100)
    remaining_slots = max_events - len(student_guaranteed)
    final_hits = student_guaranteed + overflow_pool[:max(0, remaining_slots)]

    hits = sorted(final_hits, key=lambda h: h["_source"].get("@timestamp",""), reverse=True)[:max_events]
    debug["poller"]["final_events"] = len(hits)

    # ─── Write events.json ───
    out = {"events":{"hits":{"hits":hits,"total":{"value":len(hits)}}},"ts":now}
    try:
        with open(OUT+".tmp","w") as f: json.dump(out, f)
        os.rename(OUT+".tmp", OUT)
    except: pass

    # ─── Build and write debug.json ───
    # Serialize students (convert sets to lists)
    students_serializable = {}
    for k, v in all_students.items():
        students_serializable[k] = {"events": v["events"], "targets": sorted(v["targets"]), "phases": v["phases"]}

    # Auto-detect gaps
    gaps = []
    if debug["poller"]["suricata_raw"] == 0:
        gaps.append("Suricata: 0 events in last 30m - check elastic-agent or Suricata service")
    if debug["poller"]["zeek_raw"] == 0:
        gaps.append("Zeek: 0 HTTP events - no web traffic or Zeek logging issue")
    for errmsg in debug["poller"]["errors"]:
        gaps.append(f"Query error: {errmsg}")

    # Session info
    session_age = time.time() - session_start
    session_hours = round(session_age / 3600, 1)
    session_remaining = max(0, round((SESSION_DURATION - session_age) / 3600, 1))

    debug_out = {
        "ts": now,
        "cycle": cycle_count,
        "poller": debug["poller"],
        "phases": debug["phases"],
        "phases_cumulative": {k: v for k, v in cumulative.items()},
        "students": students_serializable,
        "targets": all_targets,
        "enrichment": debug["enrichment"],
        "recent_events": recent_events[-20:],
        "gaps": gaps,
        "session": {
            "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(session_start)),
            "age_hours": session_hours,
            "auto_reset_in_hours": session_remaining,
            "clear_endpoint": "GET /clear (triggers session reset via HTTP server)",
        },
    }
    try:
        with open(DEBUG_OUT+".tmp","w") as f: json.dump(debug_out, f, indent=1)
        os.rename(DEBUG_OUT+".tmp", DEBUG_OUT)
    except: pass

# ─── Main loop ───
if __name__ == "__main__":
    print(f"Attack Map Poller starting (poll every {POLL_INTERVAL}s, session decay {SESSION_DURATION//3600}h)")
    print(f"Config: {CONFIG_PATH}")
    print(f"ES: {ES}")
    print(f"Output: {OUT}")
    while True:
        try:
            check_session()  # Auto-decay + manual clear check
            poll()
        except Exception as e:
            with open("/tmp/poller.log","a") as f:
                f.write(f"{time.strftime('%H:%M:%S')} ERROR: {e}\n")
        time.sleep(POLL_INTERVAL)
