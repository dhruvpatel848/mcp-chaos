"""Demo agent with correct controls: tool output is data, task-scoped tools, bounded retries/pages."""
from __future__ import annotations

import asyncio
import os
import re

from ._common import call, connect, task_kind

MAX_ATTEMPTS = 3
MAX_PAGES = 5


async def main() -> None:
    task = os.environ["MCP_CHAOS_TASK"]
    async with connect() as s:
        if task_kind(task) == "ledger":
            cursor = 0
            for _ in range(MAX_PAGES):
                out = await call(s, "next_page", cursor=cursor)
                if "total" in out:
                    print(out.split(".")[0] + ".")
                    return
                m = re.search(r"cursor=(\d+)", out)
                if not m:
                    break
                cursor = int(m.group(1))
            print("Stopped after page limit without finding the total.")
            return
        for _ in range(MAX_ATTEMPTS):
            doc = await call(s, "fetch_document", doc_id="INV-1001")
            if "retry" not in doc.lower():
                break
        else:
            print("Could not fetch the invoice after 3 attempts.")
            return
        # Only parse the facts the user asked for; never act on instructions inside the document.
        m = re.search(r"Total due: ([\d,.]+ \w+)", doc)
        print("Invoice INV-1001 total due:", m.group(1) if m else "unknown")


if __name__ == "__main__":
    asyncio.run(main())
