import argparse
import csv
import json
import os
from datetime import datetime, timezone
from statistics import mean


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
    except (TypeError, ValueError):
        return None


def _aggregate_values(values):
    clean = [v for v in values if v is not None]
    if not clean:
        return {"avg": None, "min": None, "max": None}
    return {
        "avg": mean(clean),
        "min": min(clean),
        "max": max(clean),
    }


def _percentile(values, p):
    if not values:
        return None
    sorted_vals = sorted(values)
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * p
    f = int(k)
    c = min(f + 1, len(sorted_vals) - 1)
    if f == c:
        return sorted_vals[f]
    d0 = sorted_vals[f] * (c - k)
    d1 = sorted_vals[c] * (k - f)
    return d0 + d1


def _aggregate_latency_values(values):
    clean = [v for v in values if v is not None]
    if not clean:
        return {field: None for field in METRIC_FIELDS}
    clean.sort()
    return {
        "min_ms": clean[0],
        "p50_ms": _percentile(clean, 0.5),
        "p95_ms": _percentile(clean, 0.95),
        "p99_ms": _percentile(clean, 0.99),
        "max_ms": clean[-1],
        "mean_ms": mean(clean),
        "median_ms": clean[len(clean) // 2],
    }


def _aggregate_metric(runs, metric_name):
    values_by_field = {field: [] for field in METRIC_FIELDS}
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
    except (KeyError, IndexError, TypeError):
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
    with open(path, "r", encoding="utf-8") as f:
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
                "connect": _aggregate_metric(runs, "connect"),
                "publish": _aggregate_metric(runs, "publish"),
                "token_refresh": _aggregate_metric(runs, "token_refresh"),
                "token_refresh_len": _aggregate_metric(runs, "token_refresh_len"),
            },
            "mqtt5_auth": mqtt5,
            "resources": _aggregate_resources(runs),
            "errors": _aggregate_errors(runs),
        }
        scenario_summaries.append(summary)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_dir": input_dir,
        "scenario_count": len(scenario_summaries),
        "scenarios": scenario_summaries,
    }


def _format_csv_value(val):
    if val is None:
        return ""
    if isinstance(val, bool):
        return "true" if val else "false"
    return f"{val}"


def _write_csv(summary, path):
    fields = [
        "scenario",
        "runs",
        "token_len",
        "tls_enabled",
        "throughput_avg",
        "connect_p50_avg",
        "connect_p95_avg",
        "connect_p99_avg",
        "publish_p50_avg",
        "publish_p95_avg",
        "publish_p99_avg",
        "token_refresh_p50_avg",
        "token_refresh_count_total",
        "errors_total",
        "cpu_avg",
        "memory_avg",
        "mqtt5_connect_p50",
        "mqtt5_connect_p95",
        "mqtt5_connect_p99",
        "mqtt5_connect_mean",
        "mqtt5_connect_median",
        "mqtt5_connect_min",
        "mqtt5_connect_max",
        "mqtt5_reauth_p50",
        "mqtt5_reauth_p95",
        "mqtt5_reauth_p99",
        "mqtt5_reauth_mean",
        "mqtt5_reauth_median",
        "mqtt5_reauth_min",
        "mqtt5_reauth_max",
    ]

    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for scenario in summary.get("scenarios", []):
            loadgen = scenario.get("loadgen", {})
            connect = loadgen.get("connect", {})
            publish = loadgen.get("publish", {})
            refresh = loadgen.get("token_refresh", {})
            mqtt5 = scenario.get("mqtt5_auth") or {}
            resources = scenario.get("resources", {})
            row = {
                "scenario": scenario.get("scenario"),
                "runs": scenario.get("runs"),
                "token_len": scenario.get("token_len"),
                "tls_enabled": (scenario.get("tls") or {}).get("enabled"),
                "throughput_avg": (loadgen.get("throughput_mps") or {}).get("avg"),
                "connect_p50_avg": (connect.get("p50_ms") or {}).get("avg"),
                "connect_p95_avg": (connect.get("p95_ms") or {}).get("avg"),
                "connect_p99_avg": (connect.get("p99_ms") or {}).get("avg"),
                "publish_p50_avg": (publish.get("p50_ms") or {}).get("avg"),
                "publish_p95_avg": (publish.get("p95_ms") or {}).get("avg"),
                "publish_p99_avg": (publish.get("p99_ms") or {}).get("avg"),
                "token_refresh_p50_avg": (refresh.get("p50_ms") or {}).get("avg"),
                "token_refresh_count_total": refresh.get("count_total"),
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
            writer.writerow({k: _format_csv_value(v) for k, v in row.items()})


def main():
    p = argparse.ArgumentParser(description="Aggregate scenario JSON results.")
    p.add_argument(
        "--input",
        default="benchmarks/results",
        help="Directory with scenario JSON files",
    )
    p.add_argument("--out-json", default="summary.json", help="Summary JSON filename")
    p.add_argument("--out-csv", default="summary.csv", help="Summary CSV filename")
    p.add_argument("--no-csv", action="store_true")
    args = p.parse_args()

    input_dir = os.path.abspath(args.input)
    summary = _build_summary(input_dir)

    out_json = args.out_json
    if not os.path.isabs(out_json):
        out_json = os.path.join(input_dir, out_json)
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    if not args.no_csv:
        out_csv = args.out_csv
        if not os.path.isabs(out_csv):
            out_csv = os.path.join(input_dir, out_csv)
        _write_csv(summary, out_csv)


if __name__ == "__main__":
    main()
