"""Approval mechanism: replay, expiry, races, tampering, traversal."""
import asyncio
import json
import time

import pytest

from mcp_chaos.guard.approvals import FileApprover, decide, list_pending


async def _wait_pending(root, n=1, timeout=5):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        p = list_pending(root)
        if len(p) >= n:
            return p
        await asyncio.sleep(0.02)
    raise AssertionError("request never appeared")


async def test_approval_is_single_use_and_cannot_be_replayed(tmp_path):
    ap = FileApprover(tmp_path, timeout=5, poll=0.02)
    t = asyncio.create_task(ap.request("bash_exec", {"command": "rm -rf a"}, "r", "why"))
    [req] = await _wait_pending(tmp_path)
    assert decide(tmp_path, req["id"], "approve")
    assert await t is True
    assert not list((tmp_path / "decided").glob("*")) and not list_pending(tmp_path)
    # the SAME call again needs a fresh approval; the old decision file is gone and the old id is dead
    assert decide(tmp_path, req["id"], "approve") is False
    t2 = asyncio.create_task(FileApprover(tmp_path, timeout=0.3, poll=0.02).request("bash_exec", {"command": "rm -rf a"}, "r", "why"))
    assert await t2 is False


async def test_a_decision_planted_in_advance_cannot_pre_approve_a_future_request(tmp_path):
    """Ids are unguessable and decisions are bound to the exact call, so pre-writing approvals achieves nothing."""
    (tmp_path / "decided").mkdir()
    for guess in ("00000000-0000000000000000", "ffffffff-ffffffffffffffff"):
        (tmp_path / "decided" / f"{guess}.json").write_text(json.dumps({"decision": "approve", "bound_to": "x"}))
    ap = FileApprover(tmp_path, timeout=0.4, poll=0.02)
    assert await ap.request("bash_exec", {"command": "rm -rf a"}, "r", "why") is False


async def test_expired_requests_cannot_be_approved_and_are_cleaned_up(tmp_path):
    ap = FileApprover(tmp_path, timeout=0.3, poll=0.02)
    t = asyncio.create_task(ap.request("bash_exec", {"command": "rm -rf a"}, "r", "why"))
    [req] = await _wait_pending(tmp_path)
    assert await t is False  # timed out
    assert decide(tmp_path, req["id"], "approve") is False
    assert list_pending(tmp_path) == []


def test_stale_request_from_a_crashed_guard_is_expired(tmp_path):
    (tmp_path / "pending").mkdir()
    (tmp_path / "pending" / "00000000-0000000000000000.json").write_text(json.dumps(
        {"id": "00000000-0000000000000000", "tool": "t", "arguments": {}, "rule": "r", "reason": "", "requested_at": 0, "expires_at": time.time() - 5,
         "bound_to": "x"}))
    assert list_pending(tmp_path) == []
    assert decide(tmp_path, "00000000-0000000000000000", "approve") is False
    assert not (tmp_path / "decided" / "00000000-0000000000000000.json").exists()


async def test_concurrent_requests_each_get_only_their_own_decision(tmp_path):
    n = 24
    approvers = [FileApprover(tmp_path, timeout=10, poll=0.02) for _ in range(n)]
    tasks = [asyncio.create_task(a.request("bash_exec", {"command": f"rm -rf d{i}"}, "r", "why")) for i, a in enumerate(approvers)]
    pend = await _wait_pending(tmp_path, n)
    by_cmd = {p["arguments"]["command"]: p["id"] for p in pend}
    for i in range(n):
        decide(tmp_path, by_cmd[f"rm -rf d{i}"], "approve" if i % 2 == 0 else "deny")
    results = await asyncio.gather(*tasks)
    assert results == [i % 2 == 0 for i in range(n)]
    assert list_pending(tmp_path) == []


async def test_identical_concurrent_requests_are_approved_independently(tmp_path):
    aps = [FileApprover(tmp_path, timeout=5, poll=0.02) for _ in range(2)]
    ts = [asyncio.create_task(a.request("bash_exec", {"command": "rm -rf same"}, "r", "why")) for a in aps]
    a, b = await _wait_pending(tmp_path, 2)
    assert a["id"] != b["id"]
    decide(tmp_path, a["id"], "approve")
    decide(tmp_path, b["id"], "deny")
    assert sorted(await asyncio.gather(*ts)) == [False, True]


async def test_tampered_pending_file_cannot_launder_an_approval(tmp_path):
    ap = FileApprover(tmp_path, timeout=3, poll=0.02)
    t = asyncio.create_task(ap.request("bash_exec", {"command": "rm -rf a"}, "r", "why"))
    [req] = await _wait_pending(tmp_path)
    f = tmp_path / "pending" / f"{req['id']}.json"
    forged = dict(req, bound_to="0" * 64)  # attacker rewrites the binding, then approves
    f.write_text(json.dumps(forged))
    decide(tmp_path, req["id"], "approve")
    assert await t is False  # the guard compares against the digest it computed itself, not the file


async def test_garbage_decision_file_is_a_denial_not_a_crash(tmp_path):
    ap = FileApprover(tmp_path, timeout=3, poll=0.02)
    t = asyncio.create_task(ap.request("bash_exec", {"command": "rm -rf a"}, "r", "why"))
    [req] = await _wait_pending(tmp_path)
    (tmp_path / "decided" / f"{req['id']}.json").write_text("{not json")
    assert await t is False


@pytest.mark.parametrize("rid", ["../x", "..\\x", "a/b", "/etc/passwd", "..", ".", "a\x00b"])
def test_decide_rejects_path_traversal_ids(rid, tmp_path):
    with pytest.raises(ValueError):
        decide(tmp_path, rid, "approve")


async def test_ids_are_unguessable_and_unique(tmp_path):
    ap = FileApprover(tmp_path, timeout=10, poll=0.02)
    ts = [asyncio.create_task(ap.request("t", {"a": 1}, "r", "w")) for _ in range(30)]
    pend = await _wait_pending(tmp_path, 30)
    ids = {p["id"] for p in pend}
    assert len(ids) == 30 and all(len(i.split("-")[1]) == 16 for i in ids)
    for i in ids:
        decide(tmp_path, i, "deny")
    assert await asyncio.gather(*ts) == [False] * 30
