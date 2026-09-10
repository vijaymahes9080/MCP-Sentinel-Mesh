#!/usr/bin/env python3
"""
MCP Sentinel Mesh - Local Setup & Healthcheck Script
"""

import sys
import subprocess
import os

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def run_cmd(cmd, cwd=None):
    print(f"--> Running: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    res = subprocess.run(cmd, cwd=cwd, shell=isinstance(cmd, str))
    if res.returncode != 0:
        print(f"[!] Command failed with exit code {res.returncode}")
        sys.exit(res.returncode)


def main():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    print("=" * 60)
    print("[*] Bootstrapping MCP Sentinel Mesh Local Environment")
    print("=" * 60)

    # 1. Install python dependencies
    print("\n[Step 1/4] Checking Python dependencies...")
    run_cmd([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"], cwd=root_dir)

    # 2. Run automated tests
    print("\n[Step 2/4] Running automated test suite...")
    run_cmd([sys.executable, "-m", "pytest", "tests/"], cwd=root_dir)

    # 3. Run benchmarks
    print("\n[Step 3/4] Running empirical evaluation benchmarks...")
    run_cmd([sys.executable, "tests/evaluation/run_benchmarks.py"], cwd=root_dir)

    # 4. Build frontend
    frontend_dir = os.path.join(root_dir, "frontend")
    print("\n[Step 4/4] Building React frontend...")
    run_cmd("npm run build", cwd=frontend_dir)

    print("\n" + "=" * 60)
    print("[SUCCESS] Local Setup Complete!")
    print("To start the Sentinel Proxy:")
    print("  uvicorn proxy.server:app --reload --port 8000")
    print("To start the React Dashboard:")
    print("  cd frontend && npm run dev")
    print("=" * 60)


if __name__ == "__main__":
    main()
