import time

import pytest
from fastapi.testclient import TestClient

from mcp_chaos.dashboard.app import create_app


@pytest.fixture
def client(vuln):
    _, out = vuln
    return TestClient(create_app(out.parent)), out.name


def test_read_api(client):
    c, aid = client
    assert c.get("/api/campaigns").json()
    lst = c.get("/api/assessments").json()
    assert lst[0]["id"] == aid and lst[0]["score"]["overall"] <= 40
    a = c.get(f"/api/assessments/{aid}").json()
    run = a["runs"][0]["dir"].split("/")[-1].split("\\")[-1]
    assert c.get(f"/api/assessments/{aid}/trace/{run}").json()[0]["seq"] == 1
    p = c.get(f"/api/assessments/{aid}/policy").json()
    assert p["review_required"] and p["rules"]


def test_html_embeds_token_and_rejects_traversal_and_foreign_host(client):
    c, aid = client
    html = c.get("/").text
    assert "__TOKEN__" not in html and c.app.state.token in html
    assert c.get("/api/assessments/..%2Fx").status_code in (400, 404)
    assert c.get("/api/campaigns", headers={"host": "evil.example"}).status_code == 403


def test_start_requires_token_and_local_target(client):
    c, _ = client
    body = {"target": "demo:secure", "mode": "data-exfil"}
    assert c.post("/api/assessments", json=body).status_code == 403
    h = {"X-Chaos-Token": c.app.state.token}
    assert c.post("/api/assessments", json={"target": "http://x"}, headers=h).status_code == 400
    r = c.post("/api/assessments", json=body, headers=h)
    assert r.status_code == 200
    for _ in range(90):
        st = c.get(f"/api/assessments/{r.json()['id']}").json()
        if st["state"] != "running" and "runs" in st:
            break
        time.sleep(1)
    assert st["state"] == "done" and all(x["verdict"]["status"] == "pass" for x in st["runs"])
