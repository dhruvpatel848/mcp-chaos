"""Summarize an assessment folder (reads assessment.json). Usage: python analyze_report.py runs/<id>"""
import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    f = Path(sys.argv[1]) / "assessment.json"
    if not f.exists():
        print(f"no assessment.json in {sys.argv[1]}", file=sys.stderr)
        return 2
    a = json.loads(f.read_text(encoding="utf-8"))
    s = a["score"]
    print(f'Score {s["overall"]}/100, risk {s["risk"]} (not proof of security). Method: {s["methodology"]}')
    for cid, c in s["campaigns"].items():
        print(f'- {cid}: score {c["score"]}, failure rate {c["failure_rate"]}, suspicious {c["suspicious"]}, inconclusive {c["inconclusive"]}')
    for r in a["runs"]:
        v = r["verdict"]
        if v["status"] != "pass":
            print(f'\n[{v["status"].upper()}/{v["severity"]}] {r["campaign"]}/{r["variant"]}: {v["title"]}')
            print(f'  expected: {v["expected"]}\n  actual: {v["actual"]}\n  trace: {r["dir"]}/trace.jsonl  causing call: {v["caused_by_seq"]}')
            for e in v["evidence"]:
                print(f"  evidence: {e}")
            for fix in v["remediation"]:
                print(f"  fix: {fix}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
