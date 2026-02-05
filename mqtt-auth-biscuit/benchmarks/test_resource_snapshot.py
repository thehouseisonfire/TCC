#!/usr/bin/env python3
"""
Test the fixed resource snapshot function directly
"""

import json
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from benchmarks.run_scenarios import _resource_snapshot


def test_error_scenarios():
    """Test error scenarios for resource snapshot function."""
    print("=== Testing Error Scenarios ===")

    # Test with invalid Prometheus URL
    print("1. Testing with invalid Prometheus URL...")
    try:
        _resource_snapshot("http://localhost:9999", None, False)
        print("   ❌ Should have failed with invalid URL")
    except Exception as e:
        print(f"   ✅ Correctly failed with: {type(e).__name__}: {e}")

    # Test with unreachable Prometheus
    print("2. Testing with unreachable Prometheus...")
    try:
        _resource_snapshot("http://nonexistent-host:9090", None, False)
        print("   ❌ Should have failed with unreachable host")
    except Exception as e:
        print(f"   ✅ Correctly failed with: {type(e).__name__}: {e}")

    # Test with TLS verification failure
    print("3. Testing with TLS verification (should fail for HTTP)...")
    try:
        _resource_snapshot("https://localhost:9090", None, False)
        # This might fail due to TLS or connection issues
        print("   ⚠️  TLS test completed (behavior depends on Prometheus TLS setup)")
    except Exception as e:
        print(f"   ✅ Correctly failed with TLS issue: {type(e).__name__}: {e}")


def test_resource_snapshot():
    """Test the resource snapshot function directly."""
    print("Testing _resource_snapshot function...")

    # Test with default instant query
    print("Testing with instant CPU query...")
    result = _resource_snapshot("http://localhost:9090", None, False)

    print("Result:")
    print(json.dumps(result, indent=2))

    # Check if we got data
    if result.get("prometheus", {}).get("cpu", {}).get("data", {}).get("result"):
        print("✅ CPU data found")
    else:
        print("❌ No CPU data")

    if result.get("prometheus", {}).get("memory", {}).get("data", {}).get("result"):
        print("✅ Memory data found")
    else:
        print("❌ No memory data")

    # Test with rate query
    print("\nTesting with rate CPU query...")
    result_rate = _resource_snapshot("http://localhost:9090", None, False, cpu_query_type="rate")

    if result_rate.get("prometheus", {}).get("cpu", {}).get("data", {}).get("result"):
        print("✅ CPU rate data found")
    else:
        print("⚠️  CPU rate data empty (container might be idle)")


if __name__ == "__main__":
    test_error_scenarios()
    print("\n" + "=" * 50 + "\n")
    test_resource_snapshot()
