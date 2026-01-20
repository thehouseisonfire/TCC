#!/usr/bin/env python3
"""
Debug script to test the exact queries used by run_scenarios.py
"""

import argparse
import subprocess
import time
import urllib.parse
import urllib.request
import json

def get_mosquitto_container_id():
    """Get the container ID for mosquitto."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "docker-mosquitto-1", "--format", "{{.Id}}"],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()[:12]  # Use first 12 chars for regex matching
    except Exception as e:
        print(f"Error getting mosquitto container ID: {e}")
        return None

def query_prometheus_debug(query):
    """Query Prometheus with debug output and timing."""
    try:
        url = f"http://localhost:9090/api/v1/query?query={urllib.parse.quote(query, safe='')}"
        print(f"Query: {query}")
        print(f"URL: {url}")
        
        start_time = time.time()
        with urllib.request.urlopen(url, timeout=5) as resp:
            result = json.loads(resp.read().decode("utf-8"))
        end_time = time.time()
        
        query_time = (end_time - start_time) * 1000  # Convert to milliseconds
        print(f"Query time: {query_time:.2f}ms")
        
        return result
    except Exception as e:
        print(f"Query failed: {e}")
        return {"error": str(e)}

def test_queries(query_types=["instant", "rate"]):
    container_id = get_mosquitto_container_id()
    print(f"Container ID: {container_id}")
    
    if not container_id:
        print("❌ Could not get container ID, exiting")
        return
    
    for query_type in query_types:
        print(f"\n=== {query_type.upper()} Query Tests ===")
        
        # Test memory query (instant)
        mem_query = f'container_memory_working_set_bytes{{id=~".*{container_id}.*"}}'
        print(f"Memory Query: {mem_query}")
        result = query_prometheus_debug(mem_query)
        print(f"Result: {json.dumps(result, indent=2)}")
        
        # Test CPU query based on type
        if query_type == "rate":
            cpu_query = f'sum(rate(container_cpu_usage_seconds_total{{id=~".*{container_id}.*"}}[30s]))'
        else:  # instant
            cpu_query = f'container_cpu_usage_seconds_total{{id=~".*{container_id}.*"}}'
        
        print(f"\nCPU Query ({query_type}): {cpu_query}")
        result = query_prometheus_debug(cpu_query)
        print(f"Result: {json.dumps(result, indent=2)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Debug Prometheus queries for Mosquitto monitoring")
    parser.add_argument(
        "--query-types", 
        nargs="+", 
        choices=["instant", "rate"], 
        default=["instant", "rate"],
        help="Types of CPU queries to test (default: both instant and rate)"
    )
    
    args = parser.parse_args()
    test_queries(args.query_types)
