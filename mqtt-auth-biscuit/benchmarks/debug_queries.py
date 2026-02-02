#!/usr/bin/env python3
"""
Debug script to test the exact queries used by run_scenarios.py
"""

import json
import subprocess
import time

import httpx
import typer

from logging_utils import get_logger, setup_logging


logger = get_logger(__name__)
app = typer.Typer(add_completion=False)


def get_mosquitto_container_id():
    """Get the container ID for mosquitto."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "docker-mosquitto-1", "--format", "{{.Id}}"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()[:12]  # Use first 12 chars for regex matching
    except Exception as e:
        logger.error("Error getting mosquitto container ID: %s", e)
        return None


def query_prometheus_debug(query):
    """Query Prometheus with debug output and timing."""
    try:
        start_time = time.time()
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(
                "http://localhost:9090/api/v1/query", params={"query": query}
            )
            resp.raise_for_status()
            result = resp.json()
        end_time = time.time()

        query_time = (end_time - start_time) * 1000  # Convert to milliseconds
        logger.info("Query: %s", query)
        logger.info("Query time: %.2fms", query_time)

        return result
    except Exception as e:
        logger.error("Query failed: %s", e)
        return {"error": str(e)}


def test_queries(query_types=["instant", "rate"]):
    container_id = get_mosquitto_container_id()
    logger.info("Container ID: %s", container_id)

    if not container_id:
        logger.error("Could not get container ID, exiting")
        return

    for query_type in query_types:
        logger.info("=== %s Query Tests ===", query_type.upper())

        # Test memory query (instant)
        mem_query = f'container_memory_working_set_bytes{{id=~".*{container_id}.*"}}'
        logger.info("Memory Query: %s", mem_query)
        result = query_prometheus_debug(mem_query)
        logger.info("Result: %s", json.dumps(result, indent=2))

        # Test CPU query based on type
        if query_type == "rate":
            cpu_query = f'sum(rate(container_cpu_usage_seconds_total{{id=~".*{container_id}.*"}}[30s]))'
        else:  # instant
            cpu_query = f'container_cpu_usage_seconds_total{{id=~".*{container_id}.*"}}'

        logger.info("CPU Query (%s): %s", query_type, cpu_query)
        result = query_prometheus_debug(cpu_query)
        logger.info("Result: %s", json.dumps(result, indent=2))


@app.command()
def main(
    query_types: list[str] = typer.Option(
        ["instant", "rate"],
        "--query-types",
        help="Types of CPU queries to test (default: both instant and rate)",
    ),
    log_level: str = typer.Option("INFO", "--log-level"),
):
    setup_logging(log_level)
    test_queries(query_types)


if __name__ == "__main__":
    app()
