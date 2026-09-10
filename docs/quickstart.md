# Quickstart Guide: MCP Sentinel Mesh

## 1. Prerequisites
- Python 3.11+
- Node.js 20+ & npm
- Git

---

## 2. Installation
Clone the repository and install dependencies:
```bash
git clone https://github.com/vijaymahes9080/MCP-Sentinel-Mesh.git
cd MCP-Sentinel-Mesh

# Install Python requirements
pip install -r requirements.txt

# Install frontend dependencies
cd frontend && npm install && cd ..
```

---

## 3. Run Static Security Scan (CLI)
Scan an MCP manifest:
```bash
# Markdown output in terminal
python sentinel.py scan mcp-samples/manifests/vulnerable_mcp.json --format markdown

# Export OASIS SARIF v2.1.0 for GitHub Security tab
python sentinel.py scan mcp-samples/manifests/vulnerable_mcp.json --format sarif --output scan.sarif

# Scan an exported n8n workflow
python sentinel.py scan n8n-samples/vulnerable_crm_sync.json --format markdown
```

---

## 4. Launch Runtime Policy Proxy
Start the ASGI proxy server on port 8000:
```bash
uvicorn proxy.server:app --reload --port 8000
```
Verify proxy health:
```bash
curl http://localhost:8000/health
```

---

## 5. Launch React Security Dashboard
In another terminal:
```bash
cd frontend
npm run dev
```
Open `http://localhost:5173` in your browser.

---

## 6. Run Adversarial Benchmarks
Execute the 80-case adversarial evaluation suite:
```bash
python tests/evaluation/run_benchmarks.py
```
View output in `evaluation.md` and charts in `docs/benchmark_charts.png`.
