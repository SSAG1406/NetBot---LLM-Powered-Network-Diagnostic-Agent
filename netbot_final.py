"""
NetBot Enhanced — Intelligent Network Diagnostic Agent
------------------------------------------------------
Tools available:
  PING        – Reachability & latency check
  NSLOOKUP    – DNS resolution
  TRACEROUTE  – Hop-by-hop path tracing
  PORTSCAN    – Check if a specific port is open (TCP)
  HTTPCHECK   – HTTP/HTTPS status code check
  IFCONFIG    – Show local network interfaces & IP info
"""

import subprocess
import platform
import socket
import urllib.request
import urllib.error
import re
import ollama  # pip install ollama

# ──────────────────────────────────────────────
# PART 1 — Networking Tools
# ──────────────────────────────────────────────

def get_ping_flag():
    """Return OS-appropriate count flag for ping."""
    return '-n' if platform.system().lower() == 'windows' else '-c'

def clean_target(target: str) -> str:
    """Strips http/https and paths so tools like PING/NSLOOKUP don't fail on URLs."""
    target = re.sub(r'^https?://', '', target)
    target = target.split('/')[0]
    return target

def run_ping(target: str, count: int = 4) -> dict:
    target = clean_target(target)
    print(f"\n[TOOL] ⚙️  PING {target} ({count} packets)...")
    flag = get_ping_flag()
    try:
        result = subprocess.run(
            ['ping', flag, str(count), target],
            capture_output=True, text=True, timeout=15
        )
        output = result.stdout + result.stderr
        diagnosis = _diagnose_ping(output, target)

        # FIX: Tag 8.8.8.8 failures explicitly so LLM can reason about it
        if target == "8.8.8.8" and any(
            any(tag in d for tag in ("LOSS", "UNREACHABLE", "TIMEOUT", "NO_INTERNET"))
            for d in diagnosis
        ):
            diagnosis.insert(0, "NO_INTERNET_CONFIRMED: Ping to 8.8.8.8 failed. User has no internet connection.")

        return {"tool": "PING", "target": target, "raw": output, "diagnosis": diagnosis}
    except subprocess.TimeoutExpired:
        diag = ["TIMEOUT: ping command timed out — host may be unreachable or blocking ICMP."]
        if target == "8.8.8.8":
            diag.insert(0, "NO_INTERNET_CONFIRMED: Ping to 8.8.8.8 timed out. User has no internet connection.")
        return {"tool": "PING", "target": target, "raw": "", "diagnosis": diag}
    except Exception as e:
        return {"tool": "PING", "target": target, "raw": "", "diagnosis": [f"ERROR: {e}"]}

def _diagnose_ping(output: str, target: str) -> list:
    issues = []
    o = output.lower()

    if any(x in o for x in ["transmit failed", "general failure", "network is unreachable"]):
        return ["NO_INTERNET: Your device appears to be disconnected from the network. Pings failed at the local interface level."]

    if any(x in o for x in ["could not find host", "name or service not known", "cannot resolve"]):
        issues.append(f"NXDOMAIN: '{target}' could not be resolved. The domain may not exist.")

    if any(x in o for x in ["destination host unreachable", "host unreachable"]):
        issues.append("UNREACHABLE: Destination is unreachable. The host may be offline or a routing issue exists.")

    if re.search(r'100%\s*(packet\s*)?loss', o) or re.search(r'lost\s*=\s*\d+\s*\(100%\)', o):
        issues.append("FULL_LOSS: 100% packet loss detected. Target is not responding to ICMP.")
    else:
        loss_match = re.search(r'(\d+)%\s*(packet\s*)?loss', o)
        if loss_match and int(loss_match.group(1)) > 0:
            issues.append(f"PARTIAL_LOSS: {loss_match.group(1)}% packet loss. Network is unstable.")

    latency_match = re.search(r'(?:avg|average)[^\d]*(\d+\.?\d*)\s*ms', o) or \
                    re.search(r'min/avg/max[^\d]*[\d.]+/([\d.]+)/[\d.]+', o)
    if latency_match:
        avg_ms = float(latency_match.group(1))
        if avg_ms > 200:
            issues.append(f"HIGH_LATENCY: Average latency is {avg_ms:.1f}ms. Possible congestion.")

    if not issues:
        issues.append("OK: All packets received with normal latency. Host is reachable.")

    return issues

def run_nslookup(target: str) -> dict:
    target = clean_target(target)
    print(f"\n[TOOL] ⚙️  NSLOOKUP {target}...")
    try:
        result = subprocess.run(['nslookup', target], capture_output=True, text=True, timeout=10)
        diagnosis = _diagnose_nslookup(result.stdout + result.stderr, target)
        return {"tool": "NSLOOKUP", "target": target, "raw": result.stdout, "diagnosis": diagnosis}
    except Exception as e:
        return {"tool": "NSLOOKUP", "target": target, "raw": "", "diagnosis": [f"ERROR: {e}"]}

def _diagnose_nslookup(output: str, target: str) -> list:
    o = output.lower()
    if any(x in o for x in ["can't find", "nxdomain", "non-existent", "name or service not known"]):
        return [f"NXDOMAIN: '{target}' does not exist in DNS. It is likely a mistyped or dead website."]
    elif "timed out" in o or "no servers could be reached" in o:
        return ["DNS_TIMEOUT: Your configured DNS server is not responding. You may have no internet connection."]

    ip_match = re.search(r'address[:\s]+([\d.]+)', o)
    if ip_match and ip_match.group(1) not in ['127.0.0.1', '0.0.0.0']:
        return [f"OK: '{target}' resolved to {ip_match.group(1)}."]
    return [f"OK: DNS lookup completed for '{target}'."]

def run_traceroute(target: str) -> dict:
    target = clean_target(target)
    print(f"\n[TOOL] ⚙️  TRACEROUTE {target}...")
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
        return ["NXDOMAIN: Traceroute failed because the domain does not exist."]

    lines = output.strip().splitlines()
    star_hops = sum(1 for l in lines if re.match(r'\s*\d+\s+\*\s+\*\s+\*', l))
    total_hops = sum(1 for l in lines if re.match(r'\s*\d+', l))

    issues = []
    if total_hops > 0 and star_hops == total_hops:
        issues.append("BLOCKED: All hops returned *. ICMP is likely blocked by a local firewall.")
    elif star_hops > 0:
        issues.append(f"INFO: {star_hops} hop(s) did not respond (*).")

    if target.lower() in o or re.search(r'\d+\s+[\d.]+\s+ms', output):
        issues.append(f"REACHED: Route to {target} was traced.")
    else:
        issues.append(f"NOT_REACHED: Trace did not complete to {target}.")
    return issues

def run_port_scan(target: str, port: int) -> dict:
    target = clean_target(target)
    print(f"\n[TOOL] ⚙️  PORTSCAN {target}:{port}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((target, port))
        sock.close()

        if result == 0:
            diag = f"OPEN: Port {port} on {target} is open."
        elif result in [111, 61, 10061]:
            diag = f"REFUSED: Port {port} refused the connection. Service is down or local firewall is blocking it."
        else:
            diag = f"CLOSED/FILTERED: Port {port} is not responding (error {result})."
        return {"tool": "PORTSCAN", "target": f"{target}:{port}", "raw": f"code: {result}", "diagnosis": [diag]}

    except OSError as e:
        if e.errno in [10051, 101]:
            return {"tool": "PORTSCAN", "target": target, "raw": str(e), "diagnosis": ["NO_INTERNET: The network is completely unreachable."]}
        return {"tool": "PORTSCAN", "target": target, "raw": str(e), "diagnosis": [f"DNS_FAIL or OS Error: {e}"]}

def run_http_check(url: str) -> dict:
    if not url.startswith("http"):
        url = "https://" + url
    print(f"\n[TOOL] ⚙️  HTTPCHECK {url}...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "NetBot/2.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return {"tool": "HTTPCHECK", "target": url, "raw": f"HTTP {resp.getcode()}", "diagnosis": [f"HTTP_OK: {url} returned HTTP {resp.getcode()}."]}

    except urllib.error.HTTPError as e:
        diag = f"HTTP_{e.code}: Server responded with an error."
        return {"tool": "HTTPCHECK", "target": url, "raw": str(e), "diagnosis": [diag]}

    except urllib.error.URLError as e:
        reason = str(e.reason).lower()
        if "timed out" in reason or "timeout" in reason or "10060" in reason:
            diag = "SERVER_TIMEOUT: The connection timed out. The server is likely offline, overloaded, or dropping requests."
        elif "getaddrinfo failed" in reason or "name or service not known" in reason:
            diag = "DNS_FAIL: DNS resolution failed. The domain either does not exist, OR you have no internet connection."
        elif "unreachable network" in reason or "network is unreachable" in reason:
            diag = "ROUTE_UNREACHABLE: No route to this specific host."
        elif "refused" in reason or "10061" in reason:
            diag = "CONN_REFUSED: Connection refused. The server is up but actively rejecting connections."
        elif "ssl" in reason:
            diag = "SSL_ERROR: SSL/TLS certificate issue detected."
        else:
            diag = f"URL_ERROR: Failed to connect — {e.reason}"
        return {"tool": "HTTPCHECK", "target": url, "raw": str(e), "diagnosis": [diag]}

def run_ifconfig() -> dict:
    print(f"\n[TOOL] ⚙️  IFCONFIG (local interfaces)...")
    cmd = ['ipconfig'] if platform.system().lower() == 'windows' else ['ip', 'addr']
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        ips = [ip for ip in re.findall(r'(?:inet\s+|IPv4.*?:\s*)([\d.]+)', result.stdout) if ip != '127.0.0.1']

        if not ips:
            return {"tool": "IFCONFIG", "target": "localhost", "raw": result.stdout, "diagnosis": ["NO_IP: No IPv4 address found. You are not connected to a network."]}

        apipa = [ip for ip in ips if ip.startswith("169.254.")]
        real = [ip for ip in ips if not ip.startswith("169.254.")]

        if apipa and not real:
            return {"tool": "IFCONFIG", "target": "localhost", "raw": result.stdout, "diagnosis": [f"APIPA: IP {apipa[0]} is self-assigned. DHCP failed. Check router."]}
        return {"tool": "IFCONFIG", "target": "localhost", "raw": result.stdout, "diagnosis": [f"OK: Local IPs: {', '.join(real)}."]}
    except Exception as e:
        return {"tool": "IFCONFIG", "target": "localhost", "raw": "", "diagnosis": [f"ERROR: {e}"]}

# ──────────────────────────────────────────────
# PART 2 — Tool Dispatcher & Agent
# ──────────────────────────────────────────────

TOOL_REGISTRY = {
    "PING":       run_ping,
    "NSLOOKUP":   run_nslookup,
    "TRACEROUTE": run_traceroute,
    "PORTSCAN":   run_port_scan,
    "HTTPCHECK":  run_http_check,
    "IFCONFIG":   run_ifconfig,
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
# PART 3 — System Prompt (FIXED)
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
    - If PING 8.8.8.8 SUCCEEDS (OK result) → the internet is working. The issue is with the
      specific website or its DNS. You may now run NSLOOKUP on the target domain.
    - If PING 8.8.8.8 returns 'NO_INTERNET_CONFIRMED', 'FULL_LOSS', 'UNREACHABLE', or 
      'TIMEOUT' → STOP ALL FURTHER TESTING IMMEDIATELY. The user has NO INTERNET.
      Do NOT run NSLOOKUP, TRACEROUTE, HTTPCHECK, or PORTSCAN on any domain.
      Report the internet outage to the user as the final diagnosis.

  - If a tool returns 'SERVER_TIMEOUT', inform the user the target server is down or 
    dropping packets. Do not blame the user's internet connection.

  - If a tool returns 'NXDOMAIN', STOP testing that specific domain.
    Do NOT run TRACEROUTE or PORTSCAN on it. Inform the user the domain does not exist.

After REAL tool results are given to you, summarize:
  - What the test found (plain English)
  - What the likely root cause is
  - What the user should do to fix it (specific, actionable steps)
"""

# ──────────────────────────────────────────────
# PART 4 — NetBot Agent Class
# ──────────────────────────────────────────────

class NetBot:
    def __init__(self, model: str = 'llama3'):
        self.model = model
        self.history = []

    def _call_llm(self, extra_user_msg: str | None = None) -> str:
        messages = [{'role': 'system', 'content': SYSTEM_PROMPT}] + self.history
        if extra_user_msg:
            messages.append({'role': 'user', 'content': extra_user_msg})
        response = ollama.chat(model=self.model, messages=messages)
        return response['message']['content']

    def chat(self, user_input: str) -> str:
        self.history.append({'role': 'user', 'content': user_input})
        calls_made = 0

        while calls_made < 6:
            reply = self._call_llm()

            tool_call_line = None
            matched_tool = None

            for line in reply.strip().splitlines():
                # Clean up markdown backticks if the model wraps calls in them
                line = line.replace("`", "").strip()
                clean_line = line.upper()

                # Check 1: Line starts directly with a tool name
                match = next((t for t in TOOL_REGISTRY if clean_line.startswith(t)), None)

                # Check 2: Tool name is hidden after a conversational colon
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
                self.history.append({'role': 'assistant', 'content': tool_call_line})
                result = dispatch_tool(tool_call_line)
                calls_made += 1

                if result:
                    diag_text = "\n".join(f"  • {d}" for d in result["diagnosis"])
                    feedback = (
                        f"[TOOL RESULT: {result['tool']}]\n"
                        f"Diagnosis:\n{diag_text}\n"
                        f"Raw Output Snippet:\n{result['raw'][:300]}"
                    )
                    self.history.append({
                        'role': 'user',
                        'content': (
                            f"Here are the real tool results:\n\n{feedback}\n\n"
                            f"Based on this, call another tool if needed, or provide your final diagnosis."
                        )
                    })
                else:
                    self.history.append({
                        'role': 'user',
                        'content': "Invalid tool formatting. Try again or provide analysis."
                    })
            else:
                self.history.append({'role': 'assistant', 'content': reply})
                return reply

        final = self._call_llm("Max tools reached. Provide final diagnosis based on the real tool results above.")
        self.history.append({'role': 'assistant', 'content': final})
        return final

# ──────────────────────────────────────────────
# PART 5 — CLI Runner
# ──────────────────────────────────────────────

if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════╗")
    print("║          NetBot v2.3 — Network Diagnostic AI     ║")
    print("╚══════════════════════════════════════════════════╝")
    model_name = input("Enter Ollama model name (default: llama3): ").strip() or 'llama3'
    bot = NetBot(model=model_name)
    print(f"\n[NetBot] Ready! Ask me about any network issue.\n")

    while True:
        try:
            user_text = input("You: ").strip()
            if not user_text:
                continue
            if user_text.lower() in ['exit', 'quit', 'q']:
                print("[NetBot] Goodbye!")
                break

            print(f"NetBot:\n{bot.chat(user_text)}\n")
            print("─" * 60)
        except KeyboardInterrupt:
            print("\n[NetBot] Session ended.")
            break
        except Exception as e:
            print(f"[ERROR] {e}")