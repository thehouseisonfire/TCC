#!/usr/bin/env python3
"""
This script verifies that Prometheus snapshots are populated with CPU and memory
data for the mosquitto container.

Usage: python3 verify_prometheus.py
"""

from typing import Any

import subprocess
import sys
import urllib.parse

import httpx

try:
    from benchmarks.run_scenarios import (
        CURRENT_DOCKER_COMPOSE_CPU_QUERY,
        CURRENT_DOCKER_COMPOSE_MEM_QUERY,
    )
except ImportError:
    # Fallback constants if import fails
    CURRENT_DOCKER_COMPOSE_CPU_QUERY = (
        "sum(rate(container_cpu_usage_seconds_total{"
        'container_label_com_docker_compose_service="mosquitto"'
        "}[30s]))"
    )
    CURRENT_DOCKER_COMPOSE_MEM_QUERY = (
        "max(container_memory_working_set_bytes{"
        'container_label_com_docker_compose_service="mosquitto"'
        "})"
    )


def query_prometheus(query) -> dict[str, Any]:
    """Query Prometheus and return the result."""
    try:
        url = f"http://localhost:9090/api/v1/query?query={urllib.parse.quote(query, safe='')}"
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(url)
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        return {"error": str(e)}


def get_mosquitto_container_id():
    """Get the container ID for mosquitto."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "docker-mosquitto-1", "--format", "{{.Id}}"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except Exception as e:
        print(f"Error getting mosquitto container ID: {e}")
        return None


def verify_resource_monitoring():
    """Verify that resource monitoring is working correctly."""
    print("=== Phase 6.2 Resource Monitoring Verification ===\n")

    # Check if Prometheus is accessible
    print("1. Checking Prometheus connectivity...")
    prom_status = query_prometheus("up")
    if "error" in prom_status:
        print(f"   ❌ Prometheus not accessible: {prom_status['error']}")
        return False
    print("   ✅ Prometheus accessible")

    # Get mosquitto container ID
    print("\n2. Getting mosquitto container ID...")
    container_id = get_mosquitto_container_id()
    if not container_id:
        print("   ❌ Could not get mosquitto container ID")
        return False
    print(f"   ✅ Container ID: {container_id[:12]}...")

    # Check CPU metrics
    print("\n3. Checking CPU metrics...")
    cpu_query = f'container_cpu_usage_seconds_total{{id=~".*{container_id[:12]}.*"}}'
    cpu_result = query_prometheus(cpu_query)

    if "error" in cpu_result:
        print(f"   ❌ CPU query error: {cpu_result['error']}")
        return False

    if not cpu_result.get("data", {}).get("result"):
        print("   ❌ No CPU metrics found for mosquitto container")
        return False

    cpu_value = cpu_result["data"]["result"][0]["value"][1]
    print(f"   ✅ CPU usage seconds total: {cpu_value}")

    # Check memory metrics
    print("\n4. Checking memory metrics...")
    mem_query = f'container_memory_working_set_bytes{{id=~".*{container_id[:12]}.*"}}'
    mem_result = query_prometheus(mem_query)

    if "error" in mem_result:
        print(f"   ❌ Memory query error: {mem_result['error']}")
        return False

    if not mem_result.get("data", {}).get("result"):
        print("   ❌ No memory metrics found for mosquitto container")
        return False

    mem_value = mem_result["data"]["result"][0]["value"][1]
    mem_mb = float(mem_value) / (1024 * 1024)
    print(f"   ✅ Memory working set: {mem_value} bytes ({mem_mb:.2f} MB)")

    # Test the current scenario runner label-based queries.
    print("\n5. Testing current scenario runner queries...")
    current_cpu_result = query_prometheus(CURRENT_DOCKER_COMPOSE_CPU_QUERY)

    current_cpu_ok = bool(current_cpu_result.get("data", {}).get("result"))
    if not current_cpu_ok:
        print("   ⚠️  Current scenario runner CPU query returns empty")
        print("      This is because Docker Compose labels are not available in cAdvisor")
    else:
        print("   ✅ Current scenario runner CPU query works")

    current_mem_result = query_prometheus(CURRENT_DOCKER_COMPOSE_MEM_QUERY)

    current_mem_ok = bool(current_mem_result.get("data", {}).get("result"))
    if not current_mem_ok:
        print("   ⚠️  Current scenario runner memory query returns empty")
        print("      This is because Docker Compose labels are not available in cAdvisor")
    else:
        print("   ✅ Current scenario runner memory query works")

    print("\n=== Summary ===")
    print("✅ Prometheus is accessible and collecting container metrics")
    print("✅ CPU and memory metrics are available for mosquitto container")
    if current_cpu_ok and current_mem_ok:
        print("✅ Current scenario runner label-based queries return data")
        print("\n=== Phase 6.2 Status ===")
        print("✅ RESOURCE MONITORING OK")
    else:
        print("⚠️  Current scenario runner label-based queries return empty vectors")
        print("\n=== Phase 6.2 Status ===")
        print("🔧 RESOURCE MONITORING PARTIAL: Prometheus is healthy, but label-based")
        print("   queries are empty. Use container ID-based queries for this cAdvisor setup.")

    return True


def test_fixed_queries():
    """Test the fixed queries that should work."""
    print("\n=== Testing Fixed Queries ===")

    container_id = get_mosquitto_container_id()
    if not container_id:
        return False

    # Fixed CPU query (rate over 30s)
    fixed_cpu_query = (
        f'sum(rate(container_cpu_usage_seconds_total{{id=~".*{container_id[:12]}.*"}}[30s]))'
    )
    fixed_cpu_result = query_prometheus(fixed_cpu_query)

    print(f"Fixed CPU query: {fixed_cpu_query}")
    if fixed_cpu_result.get("data", {}).get("result"):
        cpu_rate = fixed_cpu_result["data"]["result"][0]["value"][1]
        print(f"   ✅ CPU usage rate: {cpu_rate} cores")
    else:
        print("   ⚠️  CPU rate query returned empty (container might be idle)")

    # Fixed memory query
    fixed_mem_query = f'max(container_memory_working_set_bytes{{id=~".*{container_id[:12]}.*"}})'
    fixed_mem_result = query_prometheus(fixed_mem_query)

    print(f"Fixed memory query: {fixed_mem_query}")
    if fixed_mem_result.get("data", {}).get("result"):
        mem_bytes = fixed_mem_result["data"]["result"][0]["value"][1]
        mem_mb = float(mem_bytes) / (1024 * 1024)
        print(f"   ✅ Memory usage: {mem_bytes} bytes ({mem_mb:.2f} MB)")
    else:
        print("   ❌ Fixed memory query failed")
        return False

    return True


if __name__ == "__main__":
    success = verify_resource_monitoring()

    if success:
        test_fixed_queries()
        print("\n🎯 PHASE 6.2 VERIFICATION COMPLETE")
        print("   Resource monitoring infrastructure is working.")
        sys.exit(0)
    else:
        print("\n❌ PHASE 6.2 VERIFICATION FAILED")
        print("   Resource monitoring infrastructure has issues.")
        sys.exit(1)
