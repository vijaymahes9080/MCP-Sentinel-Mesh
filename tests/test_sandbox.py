"""
Unit Tests for Process Sandbox & Seccomp Generator
"""

import pytest
from backend.schemas.contracts import ToolDefinition, ToolPermission, PermissionScope, DataClassification
from scanner.sandbox import SandboxProfileGenerator


def test_sandbox_generates_restrictive_seccomp_profile():
    # Read-only tool requires neither write nor network
    readonly_tool = ToolDefinition(
        name="read_report",
        description="Reads financial report",
        parameters_schema={"type": "object"},
        permissions=[
            ToolPermission(
                scope=PermissionScope.READ,
                resource_patterns=["reports/*"],
                data_classification=DataClassification.INTERNAL,
                is_destructive=False
            )
        ]
    )

    profile = SandboxProfileGenerator.generate_seccomp_profile([readonly_tool])

    assert profile["defaultAction"] == "SCMP_ACT_ALLOW"
    blocked_syscalls = profile["syscalls"][0]["names"]

    # Base dangerous syscalls must be blocked
    assert "ptrace" in blocked_syscalls
    assert "bpf" in blocked_syscalls
    assert "reboot" in blocked_syscalls

    # Since WRITE scope is missing, write syscalls should be in blocked list
    assert "write" in blocked_syscalls
    assert "unlink" in blocked_syscalls

    # Since NETWORK scope is missing, network syscalls should be in blocked list
    assert "connect" in blocked_syscalls
    assert "socket" in blocked_syscalls

    # eBPF rules check
    ebpf = SandboxProfileGenerator.generate_ebpf_network_rules([readonly_tool])
    assert ebpf["policy"] == "block_and_alert"
    assert "169.254.0.0/16" in ebpf["blocked_subnets"]
