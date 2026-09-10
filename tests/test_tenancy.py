"""
Unit Tests for TenancyGuard Multi-Tenant Security
"""

import pytest
from proxy.tenancy import TenancyGuard, TenantQuotaExceededError


def test_tenancy_guard_idor_prevention():
    guard = TenancyGuard(default_hourly_quota=10)

    # Allowed: Accessing own tenant directory
    valid, err = guard.validate_resource_access("tenant-alpha", "tenants/tenant-alpha/reports/q3.csv")
    assert valid is True
    assert err is None

    # Blocked: Attempting cross-tenant IDOR access to tenant-beta
    valid, err = guard.validate_resource_access("tenant-alpha", "tenants/tenant-beta/secrets.json")
    assert valid is False
    assert "Cross-tenant IDOR violation" in err

    # Namespacing path
    partitioned = guard.partition_resource_path("tenant-gamma", "data/analysis.parquet")
    assert partitioned == "tenants/tenant-gamma/data/analysis.parquet"


def test_tenancy_guard_quota_throttling():
    guard = TenancyGuard(default_hourly_quota=3)

    # Consume 3 calls within quota
    for _ in range(3):
        assert guard.check_and_consume_quota("tenant-acme") is True

    # 4th call should trigger quota exceeded error
    with pytest.raises(TenantQuotaExceededError) as exc_info:
        guard.check_and_consume_quota("tenant-acme")

    assert "quota exceeded" in str(exc_info.value)
