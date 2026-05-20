"""
NetBot Flask Server — app.py
Run: python app.py
Then open: http://localhost:5000
"""

from flask import Flask, Response, render_template, request, stream_with_context
import subprocess
import platform
import socket
import urllib.request
import urllib.error
import re
import json
import ollama

app = Flask(__name__)

# ──────────────────────────────────────────────
# Networking Tools
# ──────────────────────────────────────────────

def get_ping_flag():
    return '-n' if platform.system().lower() == 'windows' else '-c'

def clean_target(target: str) -> str:
    target = re.sub(r'^https?://', '', target)
    target = target.split('/')[0]
    return target

def run_ping(target: str, count: int = 4) -> dict:
    target = clean_target(target)
    flag = get_ping_flag()
    try:
        result = subprocess.run(
            ['ping', flag, str(count), target],
            capture_output=True, text=True, timeout=15
        )
        output = result.stdout + result.stderr
        diagnosis = _diagnose_ping(output, target)
        if target == "8.8.8.8" and any(
            any(tag in d for tag in ("LOSS", "UNREACHABLE", "TIMEOUT", "NO_INTERNET"))
            for d in diagnosis
        ):
            diagnosis.insert(0, "NO_INTERNET_CONFIRMED: Ping to 8.8.8.8 failed. User has no internet connection.")
        return {"tool": "PING", "target": target, "raw": output, "diagnosis": diagnosis}
    except subprocess.TimeoutExpired:
        diag = ["TIMEOUT: ping timed out."]
        if target == "8.8.8.8":
            diag.insert(0, "NO_INTERNET_CONFIRMED: Ping to 8.8.8.8 timed out.")
        return {"tool": "PING", "target": target, "raw": "", "diagnosis": diag}
    except Exception as e:
        return {"tool": "PING", "target": target, "raw": "", "diagnosis": [f"ERROR: {e}"]}

def _diagnose_ping(output: str, target: str) -> list:
    issues = []
    o = output.lower()
    if any(x in o for x in ["transmit failed", "general failure", "network is unreachable"]):
        return ["NO_INTERNET: Device appears disconnected at the local interface level."]
    if any(x in o for x in ["could not find host", "name or service not known", "cannot resolve"]):
        issues.append(f"NXDOMAIN: '{target}' could not be resolved.")
    if any(x in o for x in ["destination host unreachable", "host unreachable"]):
        issues.append("UNREACHABLE: Destination is unreachable.")
    if re.search(r'100%\s*(packet\s*)?loss', o) or re.search(r'lost\s*=\s*\d+\s*\(100%\)', o):
        issues.append("FULL_LOSS: 100% packet loss detected.")
    else:
        loss_match = re.search(r'(\d+)%\s*(packet\s*)?loss', o)
        if loss_match and int(loss_match.group(1)) > 0:
            issues.append(f"PARTIAL_LOSS: {loss_match.group(1)}% packet loss.")
    latency_match = re.search(r'(?:avg|average)[^\d]*(\d+\.?\d*)\s*ms', o) or \
                    re.search(r'min/avg/max[^\d]*[\d.]+/([\d.]+)/[\d.]+', o)
    if latency_match:
        avg_ms = float(latency_match.group(1))
        if avg_ms > 200:
            issues.append(f"HIGH_LATENCY: Average latency is {avg_ms:.1f}ms.")
    if not issues:
        issues.append("OK: All packets received. Host is reachable.")
    return issues

def run_nslookup(target: str) -> dict:
    target = clean_target(target)
    try:
        result = subprocess.run(['nslookup', target], capture_output=True, text=True, timeout=10)
        diagnosis = _diagnose_nslookup(result.stdout + result.stderr, target)
        return {"tool": "NSLOOKUP", "target": target, "raw": result.stdout, "diagnosis": diagnosis}
    except Exception as e:
        return {"tool": "NSLOOKUP", "target": target, "raw": "", "diagnosis": [f"ERROR: {e}"]}

def _diagnose_nslookup(output: str, target: str) -> list:
    o = output.lower()
    if any(x in o for x in ["can't find", "nxdomain", "non-existent", "name or service not known"]):
        return [f"NXDOMAIN: '{target}' does not exist in DNS."]
    elif "timed out" in o or "no servers could be reached" in o:
        return ["DNS_TIMEOUT: DNS server not responding."]
    ip_match = re.search(r'address[:\s]+([\d.]+)', o)
    if ip_match and ip_match.group(1) not in ['127.0.0.1', '0.0.0.0']:
        return [f"OK: '{target}' resolved to {ip_match.group(1)}."]
    return [f"OK: DNS lookup completed for '{target}'."]

def run_traceroute(target: str) -> dict:
    target = clean_target(target)
    cmd = ['tracert', '-h', '20', target] if platform.system().lower() == 'windows' else ['traceroute', '-m', '20', target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        diagnosis = _diagnose_traceroute(result.stdout + result.stderr, target)
        return {"tool": "TRACEROUTE", "target": target, "raw": result.stdout, "diagnosis": diagnosis}
    except subprocess.TimeoutExpired:
        return {"tool": "TRACEROUTE", "target": target, "raw": "", "diagnosis": ["TIMEOUT: Traceroute timed out."]}
    except Exception as e:
        return {"tool": "TRACEROUTE", "target": target, "raw": "", "diagnosis": [f"ERROR: {e}"]}

def _diagnose_traceroute(output: str, target: str) -> list:
    o = output.lower()
    if "unable to resolve" in o or "name or service not known" in o:
        return ["NXDOMAIN: Traceroute failed — domain does not exist."]
    lines = output.strip().splitlines()
    star_hops = sum(1 for l in lines if re.match(r'\s*\d+\s+\*\s+\*\s+\*', l))
    total_hops = sum(1 for l in lines if re.match(r'\s*\d+', l))
    issues = []
    if total_hops > 0 and star_hops == total_hops:
        issues.append("BLOCKED: All hops returned *. ICMP likely blocked.")
    elif star_hops > 0:
        issues.append(f"INFO: {star_hops} hop(s) did not respond (*).")
    if target.lower() in o or re.search(r'\d+\s+[\d.]+\s+ms', output):
        issues.append(f"REACHED: Route to {target} was traced.")
    else:
        issues.append(f"NOT_REACHED: Trace did not complete to {target}.")
    return issues

def run_port_scan(target: str, port: int) -> dict:
    target = clean_target(target)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((target, port))
        sock.close()
        if result == 0:
            diag = f"OPEN: Port {port} on {target} is open."
        elif result in [111, 61, 10061]:
            diag = f"REFUSED: Port {port} connection refused."
        else:
            diag = f"CLOSED/FILTERED: Port {port} not responding (error {result})."
        return {"tool": "PORTSCAN", "target": f"{target}:{port}", "raw": f"code: {result}", "diagnosis": [diag]}
    except OSError as e:
        if e.errno in [10051, 101]:
            return {"tool": "PORTSCAN", "target": target, "raw": str(e), "diagnosis": ["NO_INTERNET: Network completely unreachable."]}
        return {"tool": "PORTSCAN", "target": target, "raw": str(e), "diagnosis": [f"DNS_FAIL or OS Error: {e}"]}

def run_http_check(url: str) -> dict:
    if not url.startswith("http"):
        url = "https://" + url
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetBot/2.3"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return {"tool": "HTTPCHECK", "target": url, "raw": f"HTTP {resp.getcode()}", "diagnosis": [f"HTTP_OK: {url} returned HTTP {resp.getcode()}."]}
    except urllib.error.HTTPError as e:
        return {"tool": "HTTPCHECK", "target": url, "raw": str(e), "diagnosis": [f"HTTP_{e.code}: Server responded with an error."]}
    except urllib.error.URLError as e:
        reason = str(e.reason).lower()
        if "timed out" in reason or "timeout" in reason:
            diag = "SERVER_TIMEOUT: Connection timed out. Server likely offline."
        elif "getaddrinfo failed" in reason or "name or service not known" in reason:
            diag = "DNS_FAIL: DNS resolution failed. Domain may not exist OR no internet."
        elif "unreachable" in reason:
            diag = "ROUTE_UNREACHABLE: No route to this host."
        elif "refused" in reason:
            diag = "CONN_REFUSED: Connection refused."
        elif "ssl" in reason:
            diag = "SSL_ERROR: SSL/TLS certificate issue."
        else:
            diag = f"URL_ERROR: Failed to connect — {e.reason}"
        return {"tool": "HTTPCHECK", "target": url, "raw": str(e), "diagnosis": [diag]}

def run_ifconfig() -> dict:
    cmd = ['ipconfig'] if platform.system().lower() == 'windows' else ['ip', 'addr']
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        ips = [ip for ip in re.findall(r'(?:inet\s+|IPv4.*?:\s*)([\d.]+)', result.stdout) if ip != '127.0.0.1']
        if not ips:
            return {"tool": "IFCONFIG", "target": "localhost", "raw": result.stdout, "diagnosis": ["NO_IP: No IPv4 address found. Not connected to a network."]}
        apipa = [ip for ip in ips if ip.startswith("169.254.")]
        real = [ip for ip in ips if not ip.startswith("169.254.")]
        if apipa and not real:
            return {"tool": "IFCONFIG", "target": "localhost", "raw": result.stdout, "diagnosis": [f"APIPA: IP {apipa[0]} is self-assigned. DHCP failed."]}
        return {"tool": "IFCONFIG", "target": "localhost", "raw": result.stdout, "diagnosis": [f"OK: Local IPs: {', '.join(real)}."]}
    except Exception as e:
        return {"tool": "IFCONFIG", "target": "localhost", "raw": "", "diagnosis": [f"ERROR: {e}"]}

# ──────────────────────────────────────────────
# Tool Registry & Dispatcher
# ──────────────────────────────────────────────

TOOL_REGISTRY = {
    "PING": run_ping, "NSLOOKUP": run_nslookup, "TRACEROUTE": run_traceroute,
    "PORTSCAN": run_port_scan, "HTTPCHECK": run_http_check, "IFCONFIG": run_ifconfig,
}

def dispatch_tool(tool_call: str) -> dict | None:
    parts = tool_call.strip().split()
    if not parts: return None
    tool = parts[0].upper()
    if tool == "PING" and len(parts) >= 2: return run_ping(parts[1])
    elif tool == "NSLOOKUP" and len(parts) >= 2: return run_nslookup(parts[1])
    elif tool == "TRACEROUTE" and len(parts) >= 2: return run_traceroute(parts[1])
    elif tool == "PORTSCAN" and len(parts) >= 3:
        try: return run_port_scan(parts[1], int(parts[2]))
        except ValueError: return None
    elif tool == "HTTPCHECK" and len(parts) >= 2: return run_http_check(parts[1])
    elif tool == "IFCONFIG": return run_ifconfig()
    return None

# ──────────────────────────────────────────────
# System Prompt
# ──────────────────────────────────────────────

SYSTEM_PROMPT = """
You are NetBot, an expert Network Diagnostic Assistant.

You have access to these tools. To call one, output ONLY the tool call on its own line:
  PING <hostname>
  NSLOOKUP <hostname>
  TRACEROUTE <hostname>
  PORTSCAN <hostname> <port>
  HTTPCHECK <url>
  IFCONFIG

CRITICAL INSTRUCTION: When you call a tool, you MUST STOP WRITING immediately.
Do NOT hallucinate or guess the result.
Do NOT write a summary until I return the tool's raw output to you.

DIAGNOSTIC WORKFLOW:
  1. If user reports "can't reach a website" → HTTPCHECK first.
  2. If user reports "internet not working" → IFCONFIG first.

CORNER CASE RULES:
  - If a tool returns 'NO_INTERNET', 'NO_IP', 'ROUTE_UNREACHABLE', or 'DNS_FAIL',
    you MUST verify global connectivity by running 'PING 8.8.8.8' before anything else.
    - If PING 8.8.8.8 SUCCEEDS (OK result) → internet is working. You may now run NSLOOKUP.
    - If PING 8.8.8.8 returns 'NO_INTERNET_CONFIRMED', 'FULL_LOSS', 'UNREACHABLE', or
      'TIMEOUT' → STOP ALL FURTHER TESTING IMMEDIATELY. User has NO INTERNET.
      Do NOT run NSLOOKUP, TRACEROUTE, HTTPCHECK, or PORTSCAN on any domain.
      Report the internet outage as the final diagnosis.
  - If a tool returns 'SERVER_TIMEOUT', the target server is down. Do not blame the user's internet.
  - If a tool returns 'NXDOMAIN', STOP testing that domain. Inform user it does not exist.

After REAL tool results are given to you, summarize:
  - What the test found (plain English)
  - What the likely root cause is
  - What the user should do to fix it (specific, actionable steps)
"""

# ──────────────────────────────────────────────
# SSE Streaming Generator
# ──────────────────────────────────────────────

def sse_event(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"

def run_netbot_stream(user_input: str, history: list):
    """Generator that yields SSE events as NetBot runs diagnostics."""
    history.append({'role': 'user', 'content': user_input})
    calls_made = 0

    def call_llm(extra=None):
        msgs = [{'role': 'system', 'content': SYSTEM_PROMPT}] + history
        if extra:
            msgs.append({'role': 'user', 'content': extra})
        resp = ollama.chat(model='llama3', messages=msgs)
        return resp['message']['content']

    while calls_made < 6:
        reply = call_llm()

        tool_call_line = None
        matched_tool = None

        for line in reply.strip().splitlines():
            line = line.replace("`", "").strip()
            clean_line = line.upper()
            match = next((t for t in TOOL_REGISTRY if clean_line.startswith(t)), None)
            if not match and ":" in line:
                after_colon = line.split(":", 1)[-1].strip()
                match = next((t for t in TOOL_REGISTRY if after_colon.upper().startswith(t)), None)
                if match:
                    line = after_colon
            if match:
                tool_call_line = line
                matched_tool = match
                break

        if matched_tool:
            history.append({'role': 'assistant', 'content': tool_call_line})
            # Emit tool start event
            yield sse_event("tool_start", {"tool": matched_tool, "call": tool_call_line})

            result = dispatch_tool(tool_call_line)
            calls_made += 1

            if result:
                # Emit tool result event
                yield sse_event("tool_result", {
                    "tool": result["tool"],
                    "target": result["target"],
                    "diagnosis": result["diagnosis"]
                })
                diag_text = "\n".join(f"  • {d}" for d in result["diagnosis"])
                
                # FIX: Truncate the raw output severely to prevent overloading the LLM context window
                feedback = (
                    f"[TOOL RESULT: {result['tool']}]\n"
                    f"Diagnosis:\n{diag_text}\n"
                    f"Raw Output Snippet:\n{result['raw'][:100]}"
                )
                history.append({
                    'role': 'user',
                    'content': f"Here are the real tool results:\n\n{feedback}\n\nBased on this, call another tool if needed, or provide your final diagnosis."
                })
            else:
                history.append({'role': 'user', 'content': "Invalid tool formatting. Try again or provide analysis."})
        else:
            # FIX: Catch LLM outputting empty strings because it thinks it already summarized
            if not reply or not reply.strip():
                reply = "Based on the diagnostic tools, your system is completely disconnected from the internet. Please check your WiFi or router."

            # Final text response — stream character by character
            history.append({'role': 'assistant', 'content': reply})
            yield sse_event("stream_start", {})
            for char in reply:
                yield sse_event("token", {"char": char})
            yield sse_event("stream_end", {})
            return

    # Max tools hit
    final = call_llm("Max tools reached. Provide final diagnosis based on the real tool results above.")
    if not final or not final.strip():
        final = "Diagnostics complete. Based on the tools, the network is unreachable."
    
    history.append({'role': 'assistant', 'content': final})
    yield sse_event("stream_start", {})
    for char in final:
        yield sse_event("token", {"char": char})
    yield sse_event("stream_end", {})

# ──────────────────────────────────────────────
# Flask Routes
# ──────────────────────────────────────────────

# In-memory session history (single user, local use)
_history = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/chat', methods=['POST'])
def chat():
    global _history
    data = request.get_json()
    user_input = data.get('message', '').strip()
    if not user_input:
        return Response("data: {}\n\n", mimetype='text/event-stream')

    # FIX: Keep history short! Retain only the last 6 messages to prevent LLM hallucination
    if len(_history) > 6:
        _history = _history[-6:]

    def generate():
        yield from run_netbot_stream(user_input, _history)
        yield sse_event("done", {})

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        }
    )

@app.route('/reset', methods=['POST'])
def reset():
    global _history
    _history = []
    return {'status': 'ok'}

if __name__ == '__main__':
    print("╔══════════════════════════════════════════╗")
    print("║   NetBot Web UI — http://localhost:5000   ║")
    print("╚══════════════════════════════════════════╝")
    app.run(debug=False, port=5000)