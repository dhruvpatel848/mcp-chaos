import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SKILL = ROOT / "skills" / "mcp-chaos"


def test_skill_frontmatter_and_files():
    text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    fm = re.match(r"---\nname: mcp-chaos\ndescription: (.+)\n---\n", text)
    assert fm and len(fm.group(1)) < 1024
    for f in ["attack-campaigns", "security-policies", "integration-guide", "report-interpretation"]:
        assert (SKILL / "references" / f"{f}.md").exists()
    for f in ["run_scan", "analyze_report", "validate_policy"]:
        assert (SKILL / "scripts" / f"{f}.py").exists()


def test_skill_scripts_run_on_a_real_assessment(vuln):
    _, out = vuln
    r = subprocess.run([sys.executable, str(SKILL / "scripts" / "analyze_report.py"), str(out)], capture_output=True, text=True, encoding="utf-8")
    assert r.returncode == 0 and "CRITICAL" in r.stdout.upper() and "not proof" in r.stdout
    r = subprocess.run([sys.executable, str(SKILL / "scripts" / "analyze_report.py"), str(out / "nope")], capture_output=True, text=True)
    assert r.returncode == 2
