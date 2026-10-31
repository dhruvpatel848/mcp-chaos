
import pytest

from mcp_chaos.campaigns.registry import resolve
from mcp_chaos.core.assessment import run_assessment


@pytest.fixture(scope="session")
def vuln(tmp_path_factory):
    out = tmp_path_factory.mktemp("vuln") / "a"
    return run_assessment("demo:vulnerable", resolve("all"), out, timeout=90), out


@pytest.fixture(scope="session")
def secure(tmp_path_factory):
    out = tmp_path_factory.mktemp("secure") / "a"
    return run_assessment("demo:secure", resolve("all"), out, timeout=90), out
