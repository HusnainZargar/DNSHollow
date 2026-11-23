import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from manager.api.main import create_app


@pytest.fixture
def client(tmp_path):
    app = create_app(str(tmp_path / "d.db"), scheduler=False, admin_key="k", initial_password="Temp-pass-1")
    with TestClient(app) as c:
        yield c


def test_index_page_and_security_headers(client):
    r = client.get("/")
    assert r.status_code == 200 and "DNSHollow" in r.text
    csp = r.headers["content-security-policy"]
    assert "default-src 'self'" in csp and "script-src" not in csp        # no inline/remote scripts
    assert r.headers["x-frame-options"] == "DENY" and r.headers["referrer-policy"] == "no-referrer"
    assert "<script>" not in r.text                                         # no inline scripts


def test_static_files_served(client):
    assert client.get("/static/app.js").status_code == 200
    assert client.get("/static/app.css").status_code == 200
    assert client.get("/static/nope.js").status_code == 404
    assert client.get("/static/..%2f..%2fdb.py").status_code in (400, 404)


def test_docs_can_be_disabled(tmp_path):
    with TestClient(create_app(str(tmp_path / "x.db"), scheduler=False, admin_key="k", docs=False)) as c:
        assert c.get("/docs").status_code == 404 and c.get("/openapi.json").status_code == 404
    with TestClient(create_app(str(tmp_path / "y.db"), scheduler=False, admin_key="k", docs=True)) as c:
        assert c.get("/docs").status_code == 200


JS = Path("manager/dashboard/static/app.js").read_text()


SAFE_CALLS = ("esc", "pill", "sevB", "statusPill", "bar", "spark", "icon", "help", "empty")


def _is_single_safe_call(h):
    h = h.strip()
    m = re.match(r"(\w+)\(", h)
    if not m or (m.group(1) not in SAFE_CALLS and not m.group(1).endswith("H")):   # fooH(...) returns safe HTML
        return False
    depth = 0
    for i, ch in enumerate(h[m.end() - 1:], start=m.end() - 1):      # find the matching ")"
        depth += ch == "("
        depth -= ch == ")"
        if depth == 0:
            return i == len(h) - 1                                      # nothing may follow the call
    return False


def test_js_template_values_are_escaped():
    """Every ${...} placed into HTML must be one escaping helper call, or a variable
    whose name ends in H (= already-safe HTML). Domain names are attacker-controlled."""
    holes = re.findall(r"\$\{([^}]*)\}", JS)
    assert len(holes) > 100                                              # the scan really looked at the templates
    risky = [h for h in holes if not _is_single_safe_call(h) and not re.fullmatch(r"\s*\w+H\s*", h)]
    assert risky == [], risky


def test_js_has_no_dangerous_sinks():
    for bad in ("eval(", "document.write", "new Function", "outerHTML =", "insertAdjacentHTML"):
        assert bad not in JS
    assert "localStorage" not in JS and "sessionStorage" not in JS          # no secrets in browser storage
