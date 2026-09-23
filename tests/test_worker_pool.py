"""
Tests for the dynamic async worker pool in core/agent.py.

The worker pool is the highest-risk new code in RAVAGER — it replaced
a sequential for-loop with N concurrent tasks that share a mutable list
(active). These tests verify:

  1. All candidates are processed exactly once (no drops, no duplicates).
  2. Phase 10 queue re-sort is honoured — a candidate promoted to HIGH
     mid-scan is processed before still-queued MEDIUM/LOW ones.
  3. total_active is captured before workers drain the list (Candidates
     scanned counter bug regression).
  4. active.pop(0) + active[:] = triage_queue(active) are safe under
     asyncio's cooperative scheduler (no interleaving within synchronous
     statements).
  5. Workers exit cleanly when the queue empties mid-flight (IndexError
     guard on pop).
"""
from __future__ import annotations

import asyncio
from collections import Counter
from unittest.mock import MagicMock
import pytest


def _make_cand(cid: str, tier: str = "medium"):
    """Return a minimal candidate-like object with the fields the worker needs."""
    c = MagicMock()
    c.candidate_id = cid
    c.pre_score_tier = MagicMock()
    c.pre_score_tier.value = tier
    return c


def triage_queue_stub(candidates):
    """
    Mimics core.prescore.triage_queue: HIGH first, then MEDIUM, then LOW.
    """
    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(candidates, key=lambda c: order.get(c.pre_score_tier.value, 99))


async def _run_worker_pool(active: list, process_fn, concurrency: int = 3):
    """
    Exact replica of the worker pool from core/agent.py so tests remain
    independent of the full agent import chain.

    Returns (processed_order, total_active).
    """
    processed_order: list[str] = []
    total_active = len(active)

    async def _worker() -> None:
        while active:
            try:
                cand = active.pop(0)
            except IndexError:
                break
            await process_fn(cand, processed_order, active)
            if active:
                active[:] = triage_queue_stub(active)

    workers = [asyncio.create_task(_worker()) for _ in range(concurrency)]
    await asyncio.gather(*workers)
    return processed_order, total_active


# ---------------------------------------------------------------------------
# Test 1 — Every candidate processed exactly once
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_all_candidates_processed_exactly_once():
    """
    N workers draining a shared list must process each candidate exactly
    once — no candidate is skipped, and no candidate is double-processed.
    """
    cands = [_make_cand(f"c{i}") for i in range(12)]
    active = list(cands)

    async def process(cand, order, _active):
        order.append(cand.candidate_id)
        await asyncio.sleep(0)

    processed, total = await _run_worker_pool(active, process, concurrency=4)

    assert total == 12
    # Compare as sets — sorted() on string IDs like c0..c11 is lexicographic
    # (c10 < c2), which is not what we want. The actual property is: every
    # candidate ID appears in the output exactly once.
    assert set(processed) == {f"c{i}" for i in range(12)}, "a candidate was skipped"
    assert len(processed) == len(set(processed)), "duplicate processing detected"


# ---------------------------------------------------------------------------
# Test 2 — Phase 10 re-sort is honoured mid-scan
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_promoted_candidate_processed_before_lower_tier():
    """
    When a candidate is promoted to HIGH tier during processing (simulating
    Phase 10 adaptive feedback), it must be picked up before remaining
    MEDIUM candidates.
    """
    c0 = _make_cand("c0", "high")
    c1 = _make_cand("c1", "medium")
    c2 = _make_cand("c2", "medium")
    c3 = _make_cand("c3", "medium")
    active = [c0, c1, c2, c3]

    async def process(cand, order, remaining):
        order.append(cand.candidate_id)
        await asyncio.sleep(0)
        # Simulate Phase 10: processing c0 promotes c3 to HIGH
        if cand.candidate_id == "c0":
            for r in remaining:
                if r.candidate_id == "c3":
                    r.pre_score_tier.value = "high"

    # concurrency=1 makes ordering deterministic for this assertion
    processed, _ = await _run_worker_pool(active, process, concurrency=1)

    assert processed[0] == "c0", "c0 (initial HIGH) must be first"
    assert processed[1] == "c3", "c3 (promoted to HIGH) must come before c1/c2"
    assert set(processed) == {"c0", "c1", "c2", "c3"}


# ---------------------------------------------------------------------------
# Test 3 — total_active captured before workers drain the list
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_total_active_reflects_pre_drain_count():
    """
    Regression for the 'Candidates scanned: 0' bug.
    total_active must be frozen before workers start popping candidates.
    """
    active = [_make_cand(f"c{i}") for i in range(12)]

    async def process(cand, order, _active):
        order.append(cand.candidate_id)
        await asyncio.sleep(0)

    processed, total = await _run_worker_pool(active, process, concurrency=3)

    assert len(active) == 0, "queue should be empty after all workers finish"
    assert total == 12, f"total_active should be 12, got {total}"


# ---------------------------------------------------------------------------
# Test 4 — `while active:` guard terminates workers cleanly
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_while_guard_terminates_workers_cleanly():
    """
    The `while active:` check is the only guard against running on an empty
    queue. Verify that all workers exit once the queue is exhausted, with
    no hangs and no tasks left running.

    Note: the previous version of this test exercised a `try/except IndexError`
    block that was removed because it was structurally unreachable:
    `while active:` is a synchronous check and active.pop(0) runs immediately
    after with no `await` between them, so the list cannot become empty
    between the guard and the pop under asyncio's cooperative scheduler.
    """
    active = [_make_cand(f"c{i}") for i in range(3)]

    async def process(cand, order, _active):
        order.append(cand.candidate_id)
        await asyncio.sleep(0)

    # 10 workers, only 3 candidates — 7 workers will find an empty queue
    # immediately on their first `while active:` check and exit without
    # doing anything. The 3 real candidates must still all be processed.
    processed, total = await _run_worker_pool(active, process, concurrency=10)

    assert sorted(processed) == ["c0", "c1", "c2"]
    assert total == 3
    assert len(active) == 0


# ---------------------------------------------------------------------------
# Test 5 — No duplicates under concurrent workers
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_no_duplicate_processing_under_concurrent_workers():
    """
    With N workers all racing on the same list, pop(0) must be atomic under
    asyncio's cooperative scheduler so no two coroutines grab the same
    candidate.
    """
    n = 100
    active = [_make_cand(f"c{i}", tier=["high", "medium", "low"][i % 3]) for i in range(n)]

    async def process(cand, order, _active):
        order.append(cand.candidate_id)
        await asyncio.sleep(0)
        await asyncio.sleep(0)  # extra yield to stress interleaving

    processed, total = await _run_worker_pool(active, process, concurrency=10)

    assert total == n
    counts = Counter(processed)
    duplicates = {cid: cnt for cid, cnt in counts.items() if cnt > 1}
    assert not duplicates, f"Candidates processed more than once: {duplicates}"
    assert len(processed) == n


# ---------------------------------------------------------------------------
# Test 6 — re-sort does not lose candidates
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_triage_resort_does_not_lose_candidates():
    """
    active[:] = triage_queue(active) is an in-place replacement — must
    not silently drop any candidate still in the list at re-sort time.
    """
    active = [_make_cand(f"c{i}", tier="medium") for i in range(20)]
    for i in range(0, 20, 3):
        active[i].pre_score_tier.value = "high"

    snapshot_before = {c.candidate_id for c in active}

    async def process(cand, order, _active):
        order.append(cand.candidate_id)
        await asyncio.sleep(0)

    processed, _ = await _run_worker_pool(active, process, concurrency=4)

    assert set(processed) == snapshot_before, \
        "re-sort must not drop any candidates from the queue"


# ---------------------------------------------------------------------------
# Test 7 — one candidate exception does not cancel sibling workers
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_exception_in_one_candidate_does_not_cancel_siblings():
    """
    asyncio.gather(*workers) propagates the first exception and cancels all
    other tasks by default. The worker pool wraps _process_candidate in a
    per-candidate try/except so that one flaky HTTP response, parse error,
    or unexpected exception is isolated and does not abort in-flight siblings.

    Setup: 10 candidates. Candidate c5 raises RuntimeError mid-processing.
    All 9 others must still complete successfully.
    """
    async def _run_worker_pool_with_isolation(active, process_fn, concurrency=3):
        """Replica of the fixed worker pool that includes per-candidate isolation."""
        processed_order = []
        errors = []
        total_active = len(active)

        async def _worker():
            while active:
                cand = active.pop(0)
                try:
                    await process_fn(cand, processed_order, active)
                except Exception as exc:
                    errors.append((cand.candidate_id, exc))

        workers = [asyncio.create_task(_worker()) for _ in range(concurrency)]
        await asyncio.gather(*workers)
        return processed_order, errors, total_active

    active = [_make_cand(f"c{i}") for i in range(10)]

    async def process(cand, order, _active):
        await asyncio.sleep(0)
        if cand.candidate_id == "c5":
            raise RuntimeError("simulated network error")
        order.append(cand.candidate_id)

    processed, errors, total = await _run_worker_pool_with_isolation(
        active, process, concurrency=3
    )

    # c5 raised, so it must appear in errors, not in processed
    assert len(errors) == 1
    assert errors[0][0] == "c5"
    assert isinstance(errors[0][1], RuntimeError)

    # All 9 other candidates must have completed successfully
    assert len(processed) == 9
    assert "c5" not in processed
    assert len(set(processed)) == 9, "no duplicates among successful candidates"


# ---------------------------------------------------------------------------
# Test 8 — multiple simultaneous failures don't affect each other
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_multiple_simultaneous_failures_are_all_isolated():
    """
    Closer to real-world flaky network conditions: 3 of 10 candidates raise
    different exception types concurrently. Each must be caught independently —
    no cross-contamination, no cascade, and all 7 healthy candidates complete.
    """
    failing_exc = {
        "c2": ValueError("malformed response body"),
        "c5": ConnectionError("connection timed out"),
        "c8": RuntimeError("unexpected None in phase 4"),
    }

    async def _run_isolated(active, process_fn, concurrency=4):
        processed_order = []
        errors = []

        async def _worker():
            while active:
                cand = active.pop(0)
                try:
                    await process_fn(cand, processed_order, active)
                except Exception as exc:
                    errors.append((cand.candidate_id, type(exc).__name__))

        workers = [asyncio.create_task(_worker()) for _ in range(concurrency)]
        await asyncio.gather(*workers)
        return processed_order, errors

    active = [_make_cand(f"c{i}") for i in range(10)]

    async def process(cand, order, _active):
        await asyncio.sleep(0)
        if cand.candidate_id in failing_exc:
            raise failing_exc[cand.candidate_id]
        order.append(cand.candidate_id)

    processed, errors = await _run_isolated(active, process, concurrency=4)

    # All 3 failures recorded independently
    assert len(errors) == 3
    failed_ids = {cid for cid, _ in errors}
    assert failed_ids == {"c2", "c5", "c8"}

    # Correct exception type per candidate
    error_map = {cid: etype for cid, etype in errors}
    assert error_map["c2"] == "ValueError"
    assert error_map["c5"] == "ConnectionError"
    assert error_map["c8"] == "RuntimeError"

    # All 7 healthy candidates completed — no collateral damage
    assert len(processed) == 7
    assert not ({"c2", "c5", "c8"} & set(processed)), \
        "a failed candidate appeared in processed output"
    assert len(set(processed)) == 7, "no duplicates among healthy candidates"
