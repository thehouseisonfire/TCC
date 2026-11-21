from __future__ import annotations

import math
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from benchmarks import run_scenarios as rs


def _mock_prometheus(
    monkeypatch: pytest.MonkeyPatch,
    responder: Callable[[httpx.Request, int], httpx.Response],
) -> list[httpx.Request]:
    real_client = httpx.Client
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return responder(request, len(requests))

    def client_factory(*, verify: bool | str, timeout: float) -> httpx.Client:
        return real_client(
            transport=httpx.MockTransport(handler),
            verify=verify,
            timeout=timeout,
        )

    monkeypatch.setattr(rs.httpx, "Client", client_factory)
    return requests


def _matrix(series: list[tuple[str, list[list[Any]]]]) -> dict[str, Any]:
    return {
        "status": "success",
        "data": {
            "resultType": "matrix",
            "result": [
                {"metric": {"series": label}, "values": samples} for label, samples in series
            ],
        },
    }


def _sample_times(start: float, end: float) -> list[float]:
    count = math.floor((end - start) / rs.PROM_RANGE_QUERY_STEP_SECONDS + 1e-9)
    return [start + index * rs.PROM_RANGE_QUERY_STEP_SECONDS for index in range(count + 1)]


def test_short_range_is_one_request_and_preserves_response(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = _matrix([("cpu", [[10.0, "1"], [10.25, "1"]])])
    requests = _mock_prometheus(
        monkeypatch,
        lambda _request, _number: httpx.Response(200, json=expected),
    )

    result = rs._prom_range_query("http://prometheus", "sum(cpu)", 10.0, 10.25, None, False)

    assert result == expected
    assert len(requests) == 1
    assert requests[0].url.params["step"] == "0.25"


def test_internal_chunk_boundary_and_just_above_use_expected_request_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests = _mock_prometheus(
        monkeypatch,
        lambda request, _number: httpx.Response(
            200,
            json=_matrix(
                [
                    (
                        "one",
                        [
                            [ts, "7"]
                            for ts in _sample_times(
                                float(request.url.params["start"]),
                                float(request.url.params["end"]),
                            )
                        ],
                    )
                ]
            ),
        ),
    )

    rs._prom_range_query("http://prometheus", "sum(cpu)", 1000.0, 3500.0, None, False)
    assert len(requests) == 1

    requests.clear()
    result = rs._prom_range_query("http://prometheus", "sum(cpu)", 1000.0, 3500.25, None, False)
    assert len(requests) == 2
    assert [
        (float(request.url.params["start"]), float(request.url.params["end"]))
        for request in requests
    ] == [(1000.0, 3500.0), (3500.25, 3500.25)]
    assert result["data"]["result"][0]["values"] == [
        [ts, "7"] for ts in _sample_times(1000.0, 3500.25)
    ]


def test_failed_5018_5_second_interval_is_chunked_on_original_quarter_second_grid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    start = 1_793_509_322.8347855
    end = start + 5018.5
    requests = _mock_prometheus(
        monkeypatch,
        lambda request, _number: httpx.Response(
            200,
            json=_matrix(
                [
                    (
                        "cpu",
                        [
                            [ts, "2"]
                            for ts in _sample_times(
                                float(request.url.params["start"]),
                                float(request.url.params["end"]),
                            )
                        ],
                    )
                ]
            ),
        ),
    )

    result = rs._prom_range_query("http://prometheus", "sum(cpu)", start, end, None, False)

    assert len(requests) == 3
    bounds = [
        (float(request.url.params["start"]), float(request.url.params["end"]))
        for request in requests
    ]
    assert bounds[0][0] == start
    assert bounds[-1][1] == end
    assert bounds == [
        (start, start + 2500.0),
        (start + 2500.25, start + 5000.25),
        (start + 5000.5, end),
    ]
    for chunk_start, chunk_end in bounds:
        assert (chunk_end - chunk_start) / 0.25 <= rs.PROM_RANGE_QUERY_MAX_INTERVALS
    assert all(request.url.params["step"] == "0.25" for request in requests)

    samples = result["data"]["result"][0]["values"]
    expected_times = _sample_times(start, end)
    assert [sample[0] for sample in samples] == expected_times
    assert len(samples) == 20_075
    assert len({sample[0] for sample in samples}) == len(samples)
    assert all(sample[1] == "2" for sample in samples)


def test_awkward_start_uses_integer_indices_for_non_overlapping_ranges() -> None:
    start = 1_793_509_322.8347855
    end = start + 5018.5

    bounds = rs._prom_range_query_chunk_bounds(start, end)

    assert bounds == [
        (start, start + 10_000 * 0.25),
        (start + 10_001 * 0.25, start + 20_001 * 0.25),
        (start + 20_002 * 0.25, end),
    ]
    assert all((chunk_end - chunk_start) / 0.25 <= 10_000 for chunk_start, chunk_end in bounds)
    assert bounds[0][0] == start
    assert bounds[-1][1] == end
    assert all(
        right[0] == left[0] + (math.floor((left[1] - left[0]) / 0.25) + 1) * 0.25
        for left, right in zip(bounds, bounds[1:], strict=False)
    )


def test_chunk_stitching_uses_series_labels_and_preserves_gaps_and_repeated_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    start = 1000.0
    end = 6100.0

    def responder(request: httpx.Request, chunk_number: int) -> httpx.Response:
        chunk_start = float(request.url.params["start"])
        chunk_end = float(request.url.params["end"])
        times = _sample_times(chunk_start, chunk_end)
        samples_a = [[ts, "4"] for ts in times]
        samples_b = [[ts, "9"] for ts in times]
        if chunk_number == 1:
            series = [("A", samples_a), ("B", samples_b)]
        elif chunk_number == 2:
            # Response order changes; B is absent in this chunk.
            series = [("A", samples_a)]
        else:
            series = [("B", samples_b), ("A", samples_a)]
        return httpx.Response(200, json=_matrix(series))

    requests = _mock_prometheus(monkeypatch, responder)
    result = rs._prom_range_query("http://prometheus", "metric", start, end, None, False)

    assert len(requests) == 3
    by_label = {series["metric"]["series"]: series["values"] for series in result["data"]["result"]}
    all_times = _sample_times(start, end)
    assert [sample[0] for sample in by_label["A"]] == all_times
    assert [sample[1] for sample in by_label["A"]] == ["4"] * len(all_times)
    # The missing middle-chunk series stays missing there; no values are filled in.
    expected_b_times = _sample_times(start, start + 2500.0) + _sample_times(start + 5000.5, end)
    assert [sample[0] for sample in by_label["B"]] == expected_b_times


@pytest.mark.parametrize("new_value", ["4", "99"])
def test_unexpected_duplicate_timestamp_fails_closed_with_diagnostics(
    monkeypatch: pytest.MonkeyPatch, new_value: str
) -> None:
    duplicate_time = 3500.0

    def responder(_request: httpx.Request, chunk_number: int) -> httpx.Response:
        value = "4" if chunk_number == 1 else new_value
        return httpx.Response(200, json=_matrix([("cpu", [[duplicate_time, value]])]))

    requests = _mock_prometheus(monkeypatch, responder)

    with pytest.raises(RuntimeError) as error:
        rs._prom_range_query("http://prometheus", "sum(cpu)", 1000.0, 3500.25, None, False)

    message = str(error.value)
    assert "unexpected duplicate timestamp" in message
    assert "query='sum(cpu)'" in message
    assert "series=(('series', 'cpu'),)" in message
    assert "timestamp=3500.0" in message
    assert "previous_value='4'" in message
    assert f"new_value='{new_value}'" in message
    assert "previous_chunk=1/2" in message
    assert "chunk=2/2" in message
    assert "chunk_ranges=" in message
    assert len(requests) == 2


def test_failed_chunk_is_fatal_and_surfaces_prometheus_error_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def responder(_request: httpx.Request, chunk_number: int) -> httpx.Response:
        if chunk_number == 2:
            return httpx.Response(
                400,
                json={"status": "error", "error": "fixture query rejected"},
            )
        return httpx.Response(200, json=_matrix([("cpu", [])]))

    requests = _mock_prometheus(monkeypatch, responder)

    with pytest.raises(RuntimeError, match="chunk 2/2.*HTTP 400.*fixture query rejected"):
        rs._prom_range_query("http://prometheus", "sum(cpu)", 0.0, 2500.25, None, False)

    assert len(requests) == 2


def test_long_resource_interval_calculates_metrics_from_chunked_prometheus_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started_at = 100.0
    finished_at = 5127.0
    observed_at = 5127.25
    monkeypatch.setattr(rs, "_compose_service_container_id", lambda *_args, **_kwargs: "cid")
    monkeypatch.setattr(rs.time, "time", lambda: observed_at)
    monkeypatch.setattr(
        rs,
        "_wait_for_prometheus_samples_after",
        lambda *_args, **_kwargs: {"cpu": observed_at, "memory": observed_at},
    )

    def responder(request: httpx.Request, _chunk_number: int) -> httpx.Response:
        chunk_start = float(request.url.params["start"])
        chunk_end = float(request.url.params["end"])
        query = request.url.params["query"]
        series: list[list[Any]] = []
        for evaluation_time in _sample_times(chunk_start, chunk_end):
            scrape_time = float(math.floor(evaluation_time))
            if "timestamp(" in query:
                value = scrape_time
            elif "container_cpu_usage_seconds_total" in query:
                value = scrape_time - 98.0
            else:
                value = 1000.0 + scrape_time % 10
            series.append([evaluation_time, str(value)])
        return httpx.Response(200, json=_matrix([("mosquitto", series)]))

    requests = _mock_prometheus(monkeypatch, responder)
    resource = rs._resource_interval(
        "http://prometheus",
        None,
        False,
        workload_started_at=started_at,
        workload_finished_at=finished_at,
    )
    rs._validate_resource_interval(resource, scenario_id="METRICS-ONLY", run_index=0)

    assert resource["available"] is True
    assert resource["workload_interval"] == {
        "started_at": started_at,
        "finished_at": finished_at,
    }
    assert resource["cpu_usage_seconds"] == 5027.0
    assert resource["memory_working_set_bytes"]["samples"] > 5000
    assert len(requests) == 12  # Four resource expressions, three bounded chunks each.
    for request in requests:
        params = request.url.params
        assert params["step"] == "0.25"
        assert float(params["end"]) - float(params["start"]) <= 2500.0
    assert min(float(request.url.params["start"]) for request in requests) == started_at - 2.0
    assert max(float(request.url.params["end"]) for request in requests) == observed_at
