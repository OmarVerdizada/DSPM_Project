"""Source and pure-function contracts for the cross-phase Track S polish pass."""

from __future__ import annotations

import inspect

from scripts import inventory_benchmark


def test_inventory_benchmark_corpus_and_percentile_are_deterministic() -> None:
    first = inventory_benchmark._row(0)
    second = inventory_benchmark._row(1)
    assert first[0] == "bench-a"
    assert second[0] == "bench-b"
    assert "sentroneedle" in first[-1]
    assert inventory_benchmark._percentile([1, 2, 3, 4, 5], 0.95) == 5


def test_inventory_benchmark_is_guarded_and_cleans_up() -> None:
    source = inspect.getsource(inventory_benchmark.main)
    assert "DSPM_INVENTORY_BENCHMARK_ALLOW_WRITE" in source
    assert "name must contain test or bench" in source
    assert "DROP TABLE IF EXISTS" in source
    assert "finally:" in source
    assert "5_000_000" in source
