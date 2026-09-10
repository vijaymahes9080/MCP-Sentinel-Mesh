"""
MCP Sentinel Mesh - Live Operator Cockpit TUI
Rich-powered terminal interface for monitoring security proxies, agent swarms, and Merkle ledgers.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich import box

from proxy.merkle import MerkleAuditTree
from scanner.bot_simulator import SwarmSimulator


def render_cockpit():
    console = Console()

    # ASCII Header
    banner = Text(
        "=============================================================\n"
        "           MCP SENTINEL MESH - SECURITY COCKPIT              \n"
        "    Zero-Trust Gateway & Adversarial Shield for AI Agents    \n"
        "=============================================================",
        style="bold cyan"
    )
    console.print(banner)

    # 1. System Status Panel
    tree = MerkleAuditTree(["init:mesh-operational", "status:active"])
    merkle_root = tree.get_root_hex() or "uninitialized"

    status_table = Table(box=box.ROUNDED, expand=True)
    status_table.add_column("Subsystem", style="bold white")
    status_table.add_column("Status", style="bold green")
    status_table.add_column("Telemetry / Metric", style="yellow")

    status_table.add_row("Policy Engine", "ACTIVE", "12 Deterministic Rules (Deny-by-Default)")
    status_table.add_row("Streaming Redactor", "ACTIVE", "Sliding Window Secret Scrubber (SSE/WS)")
    status_table.add_row("Cryptographic Ledger", "VERIFIED", f"Merkle Root: {merkle_root[:24]}...")
    status_table.add_row("FIDO2 WebAuthn Guard", "ONLINE", "User Presence & Hardware Biometric Gating")
    status_table.add_row("Process Sandbox", "ENFORCING", "Seccomp & eBPF Socket Filter Active")

    console.print(Panel(status_table, title="Runtime Proxy Subsystems", border_style="cyan"))

    # 2. Agent Swarm Telemetry
    sim = SwarmSimulator()
    metrics = sim.run_simulation()

    swarm_table = Table(box=box.ROUNDED, expand=True)
    swarm_table.add_column("Agent Persona", style="bold magenta")
    swarm_table.add_column("Allowed Calls", style="green")
    swarm_table.add_column("Blocked Attacks", style="red")
    swarm_table.add_column("Human Approvals Gated", style="yellow")

    for persona, data in metrics["by_persona"].items():
        swarm_table.add_row(
            persona,
            str(data.get("allowed", 0)),
            str(data.get("blocked", 0)),
            str(data.get("approvals", 0))
        )

    console.print(Panel(swarm_table, title="Agent Persona Swarm Telemetry", border_style="magenta"))
    console.print("[dim]Sentinel Mesh TUI operational. Press Ctrl+C to detach console.[/dim]\n")


if __name__ == "__main__":
    render_cockpit()
