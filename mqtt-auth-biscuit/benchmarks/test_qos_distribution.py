#!/usr/bin/env python3
"""Tests for QoS distribution parsing in loadgen."""

from __future__ import annotations

import math
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from benchmarks.loadgen import _parse_qos_distribution


def _assert_raises_value_error(value: str) -> None:
    try:
        _parse_qos_distribution(value)
    except ValueError:
        return
    raise AssertionError(f"Expected ValueError for input: {value}")


def test_empty_inputs() -> None:
    assert _parse_qos_distribution("") is None
    assert _parse_qos_distribution("   ") is None


def test_invalid_entries() -> None:
    _assert_raises_value_error("0")
    _assert_raises_value_error(":1")
    _assert_raises_value_error("0:")
    _assert_raises_value_error("3:1")
    _assert_raises_value_error("1:-1")
    _assert_raises_value_error("0:0")


def test_valid_distribution() -> None:
    result = _parse_qos_distribution("0:2,1:1")
    assert result is not None
    weights = {qos: weight for qos, weight in result}
    assert math.isclose(sum(weights.values()), 1.0, rel_tol=1e-9)
    assert math.isclose(weights[0], 2 / 3, rel_tol=1e-9)
    assert math.isclose(weights[1], 1 / 3, rel_tol=1e-9)


def run_tests() -> None:
    test_empty_inputs()
    test_invalid_entries()
    test_valid_distribution()
    print("✅ QoS distribution tests passed")


if __name__ == "__main__":
    run_tests()
