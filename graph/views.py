import re
import json
import ssl
import subprocess
import urllib.request as urllib_req
import urllib.error
import pandas as pd
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

def extract_ip(value):
    if not isinstance(value, str):
        return None
    m = IP_RE.search(value)
    return m.group(1) if m else None

def classify_ip(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return "external"
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return "external"
    if a == 10:
        return "internal"
    if a == 172 and 16 <= b <= 31:
        return "internal"
    if a == 192 and b == 168:
        return "internal"
    if a == 127:
        return "loopback"
    return "external"

def parse_csv(file_obj):
    try:
        df = pd.read_csv(file_obj, low_memory=False, encoding="utf-8-sig")
    except Exception as e:
        return {"error": f"Could not parse CSV: {e}"}

    df.columns = [c.strip() for c in df.columns]
    col_lower = {c.lower(): c for c in df.columns}

    src_col = next(
        (col_lower[k] for k in col_lower
         if "source" in k and "port" not in k and "country" not in k
         and "zone" not in k and "user" not in k),
        None,
    )
    dst_col = next(
        (col_lower[k] for k in col_lower
         if "destination" in k and "port" not in k and "country" not in k
         and "zone" not in k and "user" not in k
         and "domain" not in k and "machine" not in k),
        None,
    )

    if not src_col or not dst_col:
        return {"error": f"Could not detect source/destination columns. Found: {list(df.columns[:20])}"}

    action_col = col_lower.get("action")
    proto_col  = col_lower.get("protocol")
    port_col   = next((col_lower[k] for k in col_lower if "destination port" in k), None)
    app_col    = col_lower.get("application name")
    domain_col = next((col_lower[k] for k in col_lower if "destination" in k and "domain" in k), None)

    col_list = list(df.columns)
    edges = {}
    raw_rows = []
    for _, row in df.iterrows():
        src_ip = extract_ip(str(row.get(src_col, "")))
        dst_ip = extract_ip(str(row.get(dst_col, "")))
        if not src_ip or not dst_ip or src_ip == dst_ip:
            continue

        key = (src_ip, dst_ip)
        if key not in edges:
            edges[key] = {"source": src_ip, "target": dst_ip, "count": 0,
                          "actions": set(), "protocols": set(), "ports": set(), "apps": set(), "domains": set()}
        e = edges[key]
        e["count"] += 1
        if action_col and pd.notna(row.get(action_col)):
            e["actions"].add(str(row[action_col]))
        if proto_col and pd.notna(row.get(proto_col)):
            e["protocols"].add(str(row[proto_col]))
        if port_col and pd.notna(row.get(port_col)):
            e["ports"].add(str(int(float(row[port_col]))) if str(row[port_col]).replace(".","").isdigit() else str(row[port_col]))
        if app_col and pd.notna(row.get(app_col)):
            e["apps"].add(str(row[app_col]))
        if domain_col and pd.notna(row.get(domain_col)) and str(row[domain_col]).strip():
            e["domains"].add(str(row[domain_col]).strip())

        raw_rows.append(["" if pd.isna(row[c]) else str(row[c]) for c in col_list])

    if not edges:
        return {"error": "No valid source/destination IP pairs found."}

    all_ips = set()
    for src, dst in edges:
        all_ips.add(src)
        all_ips.add(dst)

    nodes = [{"id": ip, "type": classify_ip(ip)} for ip in sorted(all_ips)]
    links = [
        {"source": src, "target": dst, "count": m["count"],
         "actions": list(m["actions"]), "protocols": list(m["protocols"]),
         "ports": list(m["ports"]), "apps": list(m["apps"]), "domains": list(m["domains"])}
        for (src, dst), m in edges.items()
    ]

    return {
        "nodes": nodes,
        "links": links,
        "stats": {
            "total_rows": len(df),
            "unique_ips": len(nodes),
            "unique_connections": len(links),
            "src_col": src_col,
            "dst_col": dst_col,
        },
        "columns": col_list,
        "rows": raw_rows,
    }

# ── Checkpoint Management API ─────────────────────────────────────────────────

def _cp_ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def _cp_request(server, endpoint, payload, sid=None, timeout=15):
    """POST to a Checkpoint Management API endpoint, ignoring self-signed certs."""
    server = server.strip().rstrip("/")
    if not server.startswith("http"):
        server = f"https://{server}"
    url = f"{server}/web_api/{endpoint}"
    headers = {"Content-Type": "application/json"}
    if sid:
        headers["X-chkp-sid"] = sid
    req = urllib_req.Request(
        url,
        data=json.dumps(payload).encode(),
        headers=headers,
        method="POST",
    )
    with urllib_req.urlopen(req, context=_cp_ssl_ctx(), timeout=timeout) as resp:
        return json.loads(resp.read())

def _process_cp_logs(logs):
    """Convert a list of Checkpoint log dicts into the same graph payload as parse_csv."""
    all_fields = []
    seen_fields = set()
    for log in logs:
        for k in log.keys():
            if k not in seen_fields:
                all_fields.append(k)
                seen_fields.add(k)

    edges = {}
    raw_rows = []
    for log in logs:
        src_ip = extract_ip(str(log.get("src", "")))
        dst_ip = extract_ip(str(log.get("dst", "")))
        if not src_ip or not dst_ip or src_ip == dst_ip:
            continue
        key = (src_ip, dst_ip)
        if key not in edges:
            edges[key] = {"source": src_ip, "target": dst_ip, "count": 0,
                          "actions": set(), "protocols": set(), "ports": set(), "apps": set(), "domains": set()}
        e = edges[key]
        e["count"] += 1
        action = str(log.get("action", ""))
        if action:
            e["actions"].add(action)
        proto = str(log.get("proto", "") or log.get("protocol", ""))
        if proto and proto != "None":
            e["protocols"].add(proto)
        port = str(log.get("service", "") or log.get("dest_port", ""))
        if port and port != "None":
            e["ports"].add(port)
        app = str(log.get("app_id", "") or log.get("matched_id", "") or log.get("product", ""))
        if app and app != "None":
            e["apps"].add(app)
        domain = str(log.get("destination_domain_name", "") or log.get("dst_dns", "") or log.get("dst_name", ""))
        if domain and domain != "None":
            e["domains"].add(domain)
        raw_rows.append([str(log.get(f, "")) for f in all_fields])

    if not edges:
        return {"error": "No valid source/destination IP pairs found in logs."}

    all_ips = set()
    for src, dst in edges:
        all_ips.add(src); all_ips.add(dst)

    return {
        "nodes":  [{"id": ip, "type": classify_ip(ip)} for ip in sorted(all_ips)],
        "links":  [{"source": src, "target": dst, "count": m["count"],
                    "actions": list(m["actions"]), "protocols": list(m["protocols"]),
                    "ports": list(m["ports"]), "apps": list(m["apps"]), "domains": list(m["domains"])}
                   for (src, dst), m in edges.items()],
        "stats":  {"total_rows": len(logs), "unique_ips": len(all_ips),
                   "unique_connections": len(edges), "src_col": "src", "dst_col": "dst"},
        "columns": all_fields,
        "rows":    raw_rows,
    }

@csrf_exempt
@require_POST
def checkpoint_connect(request):
    try:
        body = json.loads(request.body)
        server  = body.get("server", "").strip()
        api_key = body.get("api_key", "").strip()
    except Exception:
        return JsonResponse({"error": "Invalid request."}, status=400)
    if not server or not api_key:
        return JsonResponse({"error": "Server and API key are required."}, status=400)
    try:
        result = _cp_request(server, "login", {"api-key": api_key})
        sid = result.get("sid")
        if not sid:
            return JsonResponse({"error": result.get("message", "Login failed — no session ID returned.")}, status=401)
        return JsonResponse({"sid": sid, "api-server-version": result.get("api-server-version", "")})
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("message", str(e))
        except Exception:
            msg = str(e)
        return JsonResponse({"error": f"HTTP {e.code}: {msg}"}, status=502)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=502)

CHUNK_SIZE = 100

@csrf_exempt
@require_POST
def checkpoint_query(request):
    try:
        body       = json.loads(request.body)
        server     = body.get("server", "").strip()
        sid        = body.get("sid", "").strip()
        time_frame = body.get("time_frame", "last-7-days")
        start_time = body.get("start_time", "")
        end_time   = body.get("end_time", "")
        max_logs   = max(1, int(body.get("max_logs", 100)))
    except Exception:
        return JsonResponse({"error": "Invalid request."}, status=400)

    if time_frame == "custom" and (not start_time or not end_time):
        return JsonResponse({"error": "Start and end time required for custom range."}, status=400)

    # First request — new-query
    first_query = {"time-frame": time_frame, "max-logs-per-request": min(max_logs, CHUNK_SIZE)}
    if time_frame == "custom":
        first_query["start-time"] = start_time
        first_query["end-time"]   = end_time

    try:
        result = _cp_request(server, "v1.7/show-logs", {"new-query": first_query}, sid=sid, timeout=30)
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("message", str(e))
        except Exception:
            msg = str(e)
        return JsonResponse({"error": f"HTTP {e.code}: {msg}"}, status=502)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=502)

    all_logs = result.get("logs") or result.get("log", [])
    if not all_logs:
        return JsonResponse({"error": f"No logs returned. Server response: {json.dumps(result)[:300]}"}, status=404)

    query_id = result.get("query-id", result.get("request-id", ""))

    # CP API tracks cursor server-side; each call with query-id returns the next batch
    fetched = len(all_logs)
    while fetched < max_logs and query_id:
        try:
            result = _cp_request(
                server, "v1.7/show-logs",
                {"query-id": query_id},
                sid=sid, timeout=30,
            )
        except Exception:
            break
        page_logs = result.get("logs") or result.get("log", [])
        if not page_logs:
            break
        all_logs.extend(page_logs)
        fetched = len(all_logs)

    processed = _process_cp_logs(all_logs)
    if "error" in processed:
        return JsonResponse(processed, status=400)
    processed["_cp_fetched"] = len(all_logs)
    return JsonResponse(processed)

@csrf_exempt
@require_POST
def checkpoint_logout(request):
    try:
        body   = json.loads(request.body)
        server = body.get("server", "").strip()
        sid    = body.get("sid", "").strip()
    except Exception:
        return JsonResponse({"error": "Invalid request."}, status=400)
    try:
        _cp_request(server, "logout", {}, sid=sid, timeout=5)
    except Exception:
        pass
    return JsonResponse({"message": "Logged out."})

_geo_cache = {}

@csrf_exempt
@require_POST
def geoip(request):
    try:
        body = json.loads(request.body)
        ips = body.get("ips", [])
    except Exception:
        return JsonResponse({"error": "Invalid request."}, status=400)

    result = {}
    for ip in ips:
        parts = ip.split(".")
        if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            continue
        if ip in _geo_cache:
            result[ip] = _geo_cache[ip]
            continue
        try:
            url = f"http://ip-api.com/json/{ip}?fields=country"
            with urllib_req.urlopen(url, timeout=3) as resp:
                data = json.loads(resp.read())
                country = data.get("country", "")
        except Exception:
            country = ""
        _geo_cache[ip] = country
        result[ip] = country

    return JsonResponse(result)

def index(request):
    return render(request, "graph/index.html")

import os
from django.http import HttpResponse

def deploy_key(request):
    """Temporary endpoint — remove after adding key to GitHub."""
    pub_key_path = os.path.expanduser("~/.ssh/netgraph_deploy_key.pub")
    try:
        with open(pub_key_path) as f:
            key = f.read().strip()
    except FileNotFoundError:
        return HttpResponse("Key not found.", status=404)
    return HttpResponse(
        f"<pre style='font-family:monospace;padding:20px;'>{key}</pre>"
        "<p style='font-family:sans-serif;padding:0 20px;color:#888;'>"
        "Add this as a Deploy Key on GitHub: "
        "<a href='https://github.com/joeaudet/chkp-net-graph/settings/keys/new'>github.com/joeaudet/chkp-net-graph/settings/keys/new</a>"
        "<br>Remove this endpoint from urls.py and views.py once done.</p>",
        content_type="text/html",
    )

@csrf_exempt
@require_POST
def nslookup_ip(request):
    ip = request.POST.get("ip", "").strip()
    parts = ip.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return JsonResponse({"error": "Invalid IP address."}, status=400)
    try:
        result = subprocess.run(
            ["nslookup", ip],
            capture_output=True, text=True, timeout=5
        )
        output = (result.stdout + result.stderr).strip()
    except FileNotFoundError:
        return JsonResponse({"error": "nslookup not found on this system."}, status=500)
    except subprocess.TimeoutExpired:
        return JsonResponse({"error": "nslookup timed out."}, status=504)
    return JsonResponse({"output": output})

@csrf_exempt
@require_POST
def upload_csv(request):
    f = request.FILES.get("csv_file")
    if not f:
        return JsonResponse({"error": "No file provided."}, status=400)
    if not f.name.lower().endswith(".csv"):
        return JsonResponse({"error": "Only .csv files are supported."}, status=400)
    result = parse_csv(f)
    if "error" in result:
        return JsonResponse(result, status=400)
    return JsonResponse(result)
