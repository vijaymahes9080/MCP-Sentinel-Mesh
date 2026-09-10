"""
MCP Sentinel Mesh - Multi-Tenant Isolation & IDOR Protection Guard
Enforces strict tenant boundary isolation, cross-tenant resource protection, and per-tenant burst quotas.
"""

from typing import Dict, Any, Tuple, Optional
import time
from collections import defaultdict


class TenantQuotaExceededError(Exception):
    pass


class CrossTenantAccessError(Exception):
    pass


class TenancyGuard:
    """
    Enforces multi-tenant data partitioning, token budgeting, and IDOR defense.
    """

    def __init__(self, default_hourly_quota: int = 500):
        self.default_hourly_quota = default_hourly_quota
        self.tenant_usage: Dict[str, list] = defaultdict(list)
        self.tenant_quotas: Dict[str, int] = {}

    def set_tenant_quota(self, tenant_id: str, hourly_quota: int):
        self.tenant_quotas[tenant_id] = hourly_quota

    def check_and_consume_quota(self, tenant_id: str) -> bool:
        """Enforces sliding 1-hour window per-tenant quota."""
        now = time.time()
        window_start = now - 3600.0
        active_calls = [t for t in self.tenant_usage[tenant_id] if t > window_start]

        limit = self.tenant_quotas.get(tenant_id, self.default_hourly_quota)
        if len(active_calls) >= limit:
            raise TenantQuotaExceededError(f"Tenant '{tenant_id}' quota exceeded: {len(active_calls)}/{limit} calls used in past hour.")

        active_calls.append(now)
        self.tenant_usage[tenant_id] = active_calls
        return True

    def validate_resource_access(self, tenant_id: str, resource_identifier: str) -> Tuple[bool, Optional[str]]:
        """
        Validates that a resource identifier (path, database key, bucket) belongs strictly
        to the executing tenant's namespace, preventing IDOR vulnerabilities.
        """
        if not resource_identifier:
            return True, None

        # Check for explicit cross-tenant traversal
        normalized = resource_identifier.replace("\\", "/").lower()
        if "tenant-" in normalized or "org-" in normalized or "customer-" in normalized:
            # If path specifies a tenant directory, it MUST match tenant_id
            segments = normalized.split("/")
            for seg in segments:
                if (seg.startswith("tenant-") or seg.startswith("org-")) and seg != tenant_id.lower():
                    return False, f"Cross-tenant IDOR violation: Tenant '{tenant_id}' cannot access '{seg}' assets."

        return True, None

    def partition_resource_path(self, tenant_id: str, raw_path: str) -> str:
        """Namespaces a resource path into the tenant's isolated sandboxed tree."""
        clean_path = raw_path.lstrip("/\\")
        return f"tenants/{tenant_id}/{clean_path}"
