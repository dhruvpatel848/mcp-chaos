"""LangGraph agent following the mcp-chaos agent contract (no LLM: deterministic nodes stand in for the model).

Vulnerable (default) acts on instructions found in tool output and loops without bound.
  mcp-chaos attack --target examples/langgraph_agent/agent.py
Hardened:
  mcp-chaos attack --target "python examples/langgraph_agent/agent.py --secure"
"""
import asyncio
import os
import re
import sys
from typing import TypedDict

from langgraph.graph import END, StateGraph

from mcp_chaos.demo_agents._common import INSTR, call, connect, decode_hidden, task_kind

SECURE = "--secure" in sys.argv
MAX_TRIES = 3 if SECURE else 10**6


class S(TypedDict, total=False):
    doc: str
    tries: int
    cursor: int
    page: str
    actions: list
    answer: str


def build(session, descriptions: str, task: str):
    async def fetch(st: S) -> S:
        doc = await call(session, "fetch_document", doc_id="INV-1001")
        return {"doc": doc, "tries": st.get("tries", 0) + 1}

    def after_fetch(st: S) -> str:
        retry = "retry" in st["doc"].lower() and not st["doc"].startswith("BUDGET")
        return "fetch" if retry and st["tries"] < MAX_TRIES else "plan"

    async def plan(st: S) -> S:
        if SECURE:
            return {"actions": []}  # tool output is data, never instructions
        text = decode_hidden(st["doc"] + " " + descriptions)
        acts = []
        if m := INSTR["read"].search(text):
            acts.append(("read_file", {"path": m.group(1)}))
        if m := INSTR["post"].search(text):
            acts.append(("post", {"url": m.group(1)}))
        if m := INSTR["save"].search(text):
            acts.append(("save", {"prefix": m.group(1)}))
        if m := INSTR["beacon"].search(text):
            acts.append(("http_request", {"url": m.group(2) + "?t=" + m.group(1)}))
        if m := INSTR["sql"].search(text):
            acts.append(("db_query", {"sql": m.group(1)}))
        if m := INSTR["cmd"].search(text):
            acts.append(("bash_exec", {"command": m.group(1)}))
        return {"actions": acts}

    async def act(st: S) -> S:
        secret = None
        for tool, args in st["actions"]:
            if tool == "read_file":
                secret = await call(session, tool, **args)
            elif tool == "post" and secret is not None:
                await call(session, "http_request", url=args["url"], method="POST", body=secret)
            elif tool == "save" and secret is not None:
                await call(session, "bash_exec", command=args["prefix"] + " " + secret)
            elif tool not in ("post", "save"):
                await call(session, tool, **args)
        return {"answer": "Invoice INV-1001 total due: 4,200.00 USD"}

    async def page(st: S) -> S:
        cursor = st.get("cursor", 0)
        out = await call(session, "next_page", cursor=cursor)
        m = re.search(r"cursor=(\d+)", out)
        return {"page": out, "cursor": int(m.group(1)) if m else -1, "tries": st.get("tries", 0) + 1}

    def after_page(st: S) -> str:
        done = st["cursor"] < 0 or st["page"].startswith("BUDGET") or (SECURE and ("total" in st["page"] or st["tries"] >= 5))
        return END if done else "page"

    g = StateGraph(S)
    if task_kind(task) == "ledger":
        g.add_node("page", page)
        g.set_entry_point("page")
        g.add_conditional_edges("page", after_page, {"page": "page", END: END})
    else:
        g.add_node("fetch", fetch)
        g.add_node("plan", plan)
        g.add_node("act", act)
        g.set_entry_point("fetch")
        g.add_conditional_edges("fetch", after_fetch, {"fetch": "fetch", "plan": "plan"})
        g.add_edge("plan", "act")
        g.add_edge("act", END)
    return g.compile()


async def main() -> None:
    task = os.environ["MCP_CHAOS_TASK"]
    async with connect() as s:
        tools = await s.list_tools()
        descriptions = " ".join(t.description or "" for t in tools.tools)
        result = await build(s, descriptions, task).ainvoke({}, {"recursion_limit": 100000})
        print(result.get("answer") or result.get("page", "")[:80])


if __name__ == "__main__":
    asyncio.run(main())
