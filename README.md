# NetBot — LLM-Powered Network Diagnostic Agent

A production-ready agentic AI system that translates natural language 
network queries into autonomous multi-step diagnostic workflows using 
a local LLM (Llama 3 via Ollama), a ReAct-style tool dispatcher, and 
real OS-level network command execution.

**Stack:** Python · Flask · Ollama (Llama 3) · ReAct reasoning · 
Server-Sent Events · REST API  
**Interfaces:** Web UI (real-time streaming) + CLI  
**Tools dispatched:** PING · NSLOOKUP · TRACEROUTE · PORTSCAN · 
HTTPCHECK · IFCONFIG



## 🚀 Key Features

* **LLM-Driven Diagnostics:** Uses Llama3 (via Ollama) to parse user issues, trigger tools, and analyze results.
* **Autonomous Tool Dispatcher:** Built-in Python functions to run and parse real system commands:
  * `PING` (Reachability, latency, packet loss)
  * `NSLOOKUP` (DNS resolution)
  * `TRACEROUTE` (Hop-by-hop path tracing)
  * `PORTSCAN` (TCP port connectivity)
  * `HTTPCHECK` (HTTP/HTTPS status codes and SSL errors)
  * `IFCONFIG` (Local network interfaces and IP allocation)
* **Dual Interfaces:**
  * **Web UI (`app.py`):** A Flask-based server utilizing Server-Sent Events (SSE) for real-time streaming of the agent's thought process and tool execution.
  * **CLI Mode (`netbot_final.py` / `netcla.py`):** A lightweight terminal interface for quick, command-line diagnostics.
* **Context-Aware Reasoning:** The agent follows strict diagnostic workflows (e.g., verifying global internet connectivity via `8.8.8.8` before diagnosing specific domain failures) to prevent hallucinated conclusions.

## 🛠️ Tech Stack

* **Backend:** Python, Flask
* **AI/LLM:** Ollama (default: `llama3`)
* **Networking:** Native OS sub-processes (`ping`, `nslookup`, `tracert`/`traceroute`), Python `socket`, `urllib`
* **Frontend:** HTML/JS with Server-Sent Events (SSE) for the web interface

## ⚙️ Getting Started

### Prerequisites
1. Install [Python 3.8+](https://www.python.org/downloads/)
2. Install [Ollama](https://ollama.com/) and pull the Llama3 model:
   ```bash
   ollama run llama3

### Installations

# Clone the repository
git clone https://github.com/SSAG1406/NetBot---LLM-Powered-Network-Diagnostic-Agent.git

# Navigate into the project directory
cd NetBot---LLM-Powered-Network-Diagnostic-Agent

# Install the required Python dependencies
pip install Flask ollama

### Usage
python app.py

### To run the CLI Agent
python netbot_final.py


