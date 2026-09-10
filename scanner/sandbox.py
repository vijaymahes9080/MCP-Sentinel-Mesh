"""
MCP Sentinel Mesh - Process Sandboxing & Seccomp Profile Generator
Generates least-privilege Linux Seccomp JSON profiles and eBPF syscall monitoring rules for MCP servers.
"""

from typing import Dict, List, Any
import json
from backend.schemas.contracts import ToolDefinition, PermissionScope


class SandboxProfileGenerator:
    """
    Synthesizes production Seccomp security profiles and eBPF socket monitoring filters
    based on declared tool permission scopes.
    """

    BASE_DISALLOWED_SYSCALLS = [
        "ptrace",
        "bpf",
        "sys_chroot",
        "reboot",
        "kexec_load",
        "init_module",
        "finit_module",
        "delete_module",
        "mount",
        "umount2",
        "pivot_root",
        "swapon",
        "swapoff"
    ]

    WRITE_SYSCALLS = [
        "write",
        "writev",
        "pwrite64",
        "pwritev",
        "unlink",
        "unlinkat",
        "rmdir",
        "rename",
        "renameat",
        "renameat2"
    ]

    NETWORK_SYSCALLS = [
        "socket",
        "connect",
        "bind",
        "listen",
        "accept",
        "accept4",
        "sendto",
        "sendmsg"
    ]

    @classmethod
    def generate_seccomp_profile(cls, tools: List[ToolDefinition]) -> Dict[str, Any]:
        """
        Generates a hardened Docker / OCI compliant Seccomp profile tailored
        strictly to the scopes required by the toolset.
        """
        all_scopes = set()
        for t in tools:
            if hasattr(t, "permissions"):
                for p in t.permissions:
                    all_scopes.add(p.scope if hasattr(p, "scope") else p)
            if hasattr(t, "required_scopes"):
                for s in t.required_scopes:
                    all_scopes.add(s)

        blocked_syscalls = list(cls.BASE_DISALLOWED_SYSCALLS)

        # If no write permission is required, block filesystem write syscalls
        if PermissionScope.WRITE not in all_scopes and PermissionScope.ADMIN not in all_scopes:
            blocked_syscalls.extend(cls.WRITE_SYSCALLS)

        # If no network permission is required, block raw network sockets
        if PermissionScope.NETWORK not in all_scopes and PermissionScope.ADMIN not in all_scopes:
            blocked_syscalls.extend(cls.NETWORK_SYSCALLS)

        profile = {
            "defaultAction": "SCMP_ACT_ALLOW",
            "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
            "syscalls": [
                {
                    "names": sorted(list(set(blocked_syscalls))),
                    "action": "SCMP_ACT_ERRNO",
                    "args": [],
                    "comment": "Restricted by MCP Sentinel Mesh Sandbox Policy"
                }
            ]
        }
        return profile

    @classmethod
    def generate_ebpf_network_rules(cls, tools: List[ToolDefinition]) -> Dict[str, Any]:
        """Generates eBPF tracepoint socket connection filters."""
        all_scopes = set()
        for t in tools:
            if hasattr(t, "permissions"):
                for p in t.permissions:
                    all_scopes.add(p.scope if hasattr(p, "scope") else p)
            if hasattr(t, "required_scopes"):
                for s in t.required_scopes:
                    all_scopes.add(s)

        needs_network = PermissionScope.NETWORK in all_scopes or PermissionScope.ADMIN in all_scopes
        return {
            "version": "sentinel.mesh/ebpf/v1",
            "tracepoint": "sock:inet_sock_set_state",
            "policy": "allow" if needs_network else "block_and_alert",
            "enforce_destination_ip_filter": True,
            "blocked_subnets": ["169.254.0.0/16", "127.0.0.0/8"]
        }
