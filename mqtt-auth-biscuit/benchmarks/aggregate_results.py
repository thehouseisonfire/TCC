import json
import os
from datetime import UTC, datetime
from typing import Any

import numpy as np
import pandas as pd
import typer

from benchmarks.logging_utils import get_logger, setup_logging

logger = get_logger(__name__)
app = typer.Typer(add_completion=False)

METRIC_FIELDS = [
    "min_ms",
    "p50_ms",
    "p95_ms",
    "p99_ms",
    "max_ms",
    "mean_ms",
    "median_ms",
]


def _safe_float(val):
    try:
        return float(val)
    except TypeError, ValueError:
        return None


def _aggregate_values(values):
    clean = [v for v in values if v is not None]
    if not clean:
        return {"avg": None, "min": None, "max": None}
    arr = np.array(clean, dtype=float)
    return {
        "avg": float(np.mean(arr)),
        "min": float(np.min(arr)),
        "max": float(np.max(arr)),
    }


def _percentile(values, p):
    if not values:
        return None
    return float(np.percentile(values, p * 100))


def _aggregate_latency_values(values):
    clean = [v for v in values if v is not None]
    if not clean:
        return {field: None for field in METRIC_FIELDS}
    arr = np.array(clean, dtype=float)
    return {
        "min_ms": float(np.min(arr)),
        "p50_ms": _percentile(arr, 0.5),
        "p95_ms": _percentile(arr, 0.95),
        "p99_ms": _percentile(arr, 0.99),
        "max_ms": float(np.max(arr)),
        "mean_ms": float(np.mean(arr)),
        "median_ms": float(np.median(arr)),
    }


def _aggregate_metric(runs, metric_name):
    values_by_field: dict[str, list[float | None]] = {field: [] for field in METRIC_FIELDS}
    counts = []
    for run in runs:
        metric = run.get("loadgen", {}).get(metric_name)
        if not isinstance(metric, dict):
            continue
        count = _safe_float(metric.get("count"))
        if count is not None:
            counts.append(count)
        for field in METRIC_FIELDS:
            values_by_field[field].append(_safe_float(metric.get(field)))

    out = {
        "count_total": int(sum(counts)) if counts else 0,
    }
    for field, values in values_by_field.items():
        out[field] = _aggregate_values(values)
    return out


def _aggregate_scalar(runs, key, source="loadgen"):
    values = []
    for run in runs:
        payload = run.get(source, {})
        if not isinstance(payload, dict):
            continue
        values.append(_safe_float(payload.get(key)))
    return _aggregate_values(values)


def _aggregate_errors(runs):
    errors = []
    for run in runs:
        payload = run.get("loadgen", {})
        if not isinstance(payload, dict):
            continue
        errors.extend(payload.get("errors", []))
    uniq = []
    for err in errors:
        if err not in uniq:
            uniq.append(err)
    return {
        "total": len(errors),
        "unique": uniq[:10],
    }


def _extract_prom_value(snap, metric):
    try:
        results = snap["prometheus"][metric]["data"]["result"]
        if not results:
            return None
        return _safe_float(results[0]["value"][1])
    except KeyError, IndexError, TypeError:
        return None


def _aggregate_resources(runs):
    cpu_vals = []
    mem_vals = []
    for run in runs:
        snap = run.get("resources")
        if not isinstance(snap, dict):
            continue
        cpu_vals.append(_extract_prom_value(snap, "cpu"))
        mem_vals.append(_extract_prom_value(snap, "memory"))
    return {
        "cpu": _aggregate_values(cpu_vals),
        "memory": _aggregate_values(mem_vals),
    }


def _aggregate_mqtt5(runs):
    connect_vals = []
    reauth_vals = []
    for run in runs:
        payload = run.get("loadgen", {})
        if not isinstance(payload, dict):
            continue
        if "connect_ms" in payload:
            connect_vals.append(_safe_float(payload.get("connect_ms")))
            reauth_vals.append(_safe_float(payload.get("reauth_ms")))
    if not connect_vals and not reauth_vals:
        return None
    return {
        "connect": _aggregate_latency_values(connect_vals),
        "reauth": _aggregate_latency_values(reauth_vals),
    }


def _load_scenario(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return data


def _build_summary(input_dir):
    scenario_summaries = []
    for entry in sorted(os.listdir(input_dir)):
        if not entry.endswith(".json"):
            continue
        if entry in {"summary.json"}:
            continue
        path = os.path.join(input_dir, entry)
        if not os.path.isfile(path):
            continue
        data = _load_scenario(path)
        runs = data.get("runs", [])
        scenario_id = data.get("scenario") or os.path.splitext(entry)[0]
        mqtt5 = _aggregate_mqtt5(runs)

        summary = {
            "scenario": scenario_id,
            "file": entry,
            "runs": len(runs),
            "token_len": data.get("token_len"),
            "tls": data.get("tls"),
            "parity": data.get("parity"),
            "loadgen": {
                "throughput_mps": _aggregate_scalar(runs, "throughput_mps"),
                "publish_throughput_mps": _aggregate_scalar(runs, "publish_throughput_mps"),
                "receive_throughput_mps": _aggregate_scalar(runs, "receive_throughput_mps"),
                "connect": _aggregate_metric(runs, "connect"),
                "publish": _aggregate_metric(runs, "publish"),
                # Issue 17: Per-QoS metrics aggregation
                "publish_qos_0": _aggregate_metric(runs, "publish_qos_0"),
                "publish_qos_1": _aggregate_metric(runs, "publish_qos_1"),
                "publish_qos_2": _aggregate_metric(runs, "publish_qos_2"),
                "token_refresh": _aggregate_metric(runs, "token_refresh"),
                "token_refresh_len": _aggregate_metric(runs, "token_refresh_len"),
                "delegation": _aggregate_metric(runs, "delegation"),
                "delegation_len": _aggregate_metric(runs, "delegation_len"),
                "attenuation": _aggregate_metric(runs, "attenuation"),
                "attenuation_len": _aggregate_metric(runs, "attenuation_len"),
            },
            "mqtt5_auth": mqtt5,
            "resources": _aggregate_resources(runs),
            "errors": _aggregate_errors(runs),
        }
        scenario_summaries.append(summary)

    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "input_dir": input_dir,
        "scenario_count": len(scenario_summaries),
        "scenarios": scenario_summaries,
    }


def _write_csv(summary, path):
    rows: list[dict[str, Any]] = []
    for scenario in summary.get("scenarios", []):
        loadgen = scenario.get("loadgen", {})
        connect = loadgen.get("connect", {})
        publish = loadgen.get("publish", {})
        refresh = loadgen.get("token_refresh", {})
        delegation = loadgen.get("delegation", {})
        delegation_len = loadgen.get("delegation_len", {})
        attenuation = loadgen.get("attenuation", {})
        attenuation_len = loadgen.get("attenuation_len", {})
        mqtt5 = scenario.get("mqtt5_auth") or {}
        resources = scenario.get("resources", {})
        token_metadata = scenario.get("token_metadata") or {}
        rows.append(
            {
                "scenario": scenario.get("scenario"),
                "runs": scenario.get("runs"),
                "token_len": scenario.get("token_len"),
                "jwt_grants_schema_version": token_metadata.get("jwt_grants_schema_version"),
                "jwt_default_grants_enabled": token_metadata.get("jwt_default_grants_enabled"),
                "jwt_denies_schema_version": token_metadata.get("jwt_denies_schema_version"),
                "tls_enabled": (scenario.get("tls") or {}).get("enabled"),
                "throughput_avg": (loadgen.get("throughput_mps") or {}).get("avg"),
                "publish_throughput_avg": (loadgen.get("publish_throughput_mps") or {}).get("avg"),
                "receive_throughput_avg": (loadgen.get("receive_throughput_mps") or {}).get("avg"),
                "connect_p50_avg": (connect.get("p50_ms") or {}).get("avg"),
                "connect_p95_avg": (connect.get("p95_ms") or {}).get("avg"),
                "connect_p99_avg": (connect.get("p99_ms") or {}).get("avg"),
                "publish_p50_avg": (publish.get("p50_ms") or {}).get("avg"),
                "publish_p95_avg": (publish.get("p95_ms") or {}).get("avg"),
                "publish_p99_avg": (publish.get("p99_ms") or {}).get("avg"),
                # Issue 17: Per-QoS columns
                "publish_qos_0_p50_avg": (loadgen.get("publish_qos_0") or {})
                .get("p50_ms", {})
                .get("avg"),
                "publish_qos_0_count": (loadgen.get("publish_qos_0") or {}).get("count_total"),
                "publish_qos_1_p50_avg": (loadgen.get("publish_qos_1") or {})
                .get("p50_ms", {})
                .get("avg"),
                "publish_qos_1_count": (loadgen.get("publish_qos_1") or {}).get("count_total"),
                "publish_qos_2_p50_avg": (loadgen.get("publish_qos_2") or {})
                .get("p50_ms", {})
                .get("avg"),
                "publish_qos_2_count": (loadgen.get("publish_qos_2") or {}).get("count_total"),
                "token_refresh_p50_avg": (refresh.get("p50_ms") or {}).get("avg"),
                "token_refresh_count_total": refresh.get("count_total"),
                "delegation_p50_avg": (delegation.get("p50_ms") or {}).get("avg"),
                "delegation_count_total": delegation.get("count_total"),
                "delegation_len_p50_avg": (delegation_len.get("p50_ms") or {}).get("avg"),
                "attenuation_p50_avg": (attenuation.get("p50_ms") or {}).get("avg"),
                "attenuation_count_total": attenuation.get("count_total"),
                "attenuation_len_p50_avg": (attenuation_len.get("p50_ms") or {}).get("avg"),
                "errors_total": (scenario.get("errors") or {}).get("total"),
                "cpu_avg": (resources.get("cpu") or {}).get("avg"),
                "memory_avg": (resources.get("memory") or {}).get("avg"),
                "mqtt5_connect_p50": (mqtt5.get("connect") or {}).get("p50_ms"),
                "mqtt5_connect_p95": (mqtt5.get("connect") or {}).get("p95_ms"),
                "mqtt5_connect_p99": (mqtt5.get("connect") or {}).get("p99_ms"),
                "mqtt5_connect_mean": (mqtt5.get("connect") or {}).get("mean_ms"),
                "mqtt5_connect_median": (mqtt5.get("connect") or {}).get("median_ms"),
                "mqtt5_connect_min": (mqtt5.get("connect") or {}).get("min_ms"),
                "mqtt5_connect_max": (mqtt5.get("connect") or {}).get("max_ms"),
                "mqtt5_reauth_p50": (mqtt5.get("reauth") or {}).get("p50_ms"),
                "mqtt5_reauth_p95": (mqtt5.get("reauth") or {}).get("p95_ms"),
                "mqtt5_reauth_p99": (mqtt5.get("reauth") or {}).get("p99_ms"),
                "mqtt5_reauth_mean": (mqtt5.get("reauth") or {}).get("mean_ms"),
                "mqtt5_reauth_median": (mqtt5.get("reauth") or {}).get("median_ms"),
                "mqtt5_reauth_min": (mqtt5.get("reauth") or {}).get("min_ms"),
                "mqtt5_reauth_max": (mqtt5.get("reauth") or {}).get("max_ms"),
            }
        )
    df = pd.DataFrame(rows)
    df.to_csv(path, index=False)


@app.command()
def main(
    input: str = "benchmarks/results",
    out_json: str = "summary.json",
    out_csv: str = "summary.csv",
    no_csv: bool = False,
    log_level: str = typer.Option("INFO", "--log-level"),
):
    setup_logging(log_level)
    input_dir = os.path.abspath(input)
    summary = _build_summary(input_dir)

    out_json_path = out_json
    if not os.path.isabs(out_json_path):
        out_json_path = os.path.join(input_dir, out_json_path)
    with open(out_json_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    if not no_csv:
        out_csv_path = out_csv
        if not os.path.isabs(out_csv_path):
            out_csv_path = os.path.join(input_dir, out_csv_path)
        _write_csv(summary, out_csv_path)
    logger.info("Summary written to %s", out_json_path)


if __name__ == "__main__":
    app()
