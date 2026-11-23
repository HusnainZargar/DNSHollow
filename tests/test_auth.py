import time

import pytest
from fastapi.testclient import TestClient

from manager import cli
from manager.api.main import create_app
from manager.db import Database
from manager.security import check_new_password, hash_password, verify_password

TEMP = "Temp-pass-1"
GOOD = "correct horse battery"


def make(tmp_path, **kw):
    kw.setdefault("initial_password", TEMP)
    return create_app(str(tmp_path / "a.db"), scheduler=False, admin_key="scriptkey", **kw)


@pytest.fixture
def client(tmp_path):
    with TestClient(make(tmp_path)) as c:
        yield c


def login(c, user="admin", pw=TEMP):
    return c.post("/api/v1/session", json={"username": user, "password": pw})


def full_login(c):
    login(c)
    assert c.post("/api/v1/account/password", json={"current_password": TEMP, "new_password": GOOD}).status_code == 200


# ---------- first start ----------
def test_first_start_creates_admin_with_temp_password(tmp_path, capsys):
    app = make(tmp_path)
    out = capsys.readouterr().out
    assert "FIRST LOGIN" in out and "admin" in out
    u = Database(str(tmp_path / "a.db")).get_user_by_name("admin")
    assert u["must_change"] == 1 and verify_password(TEMP, u["pw_hash"])
    assert TEMP not in u["pw_hash"]                                     # stored hashed
    make(tmp_path)                                                       # second start: no new user, no banner
    assert "FIRST LOGIN" not in capsys.readouterr().out
    assert Database(str(tmp_path / "a.db")).count_users() == 1


def test_random_temp_password_goes_to_a_private_file(tmp_path, capsys):
    app = create_app(str(tmp_path / "r.db"), scheduler=False)
    f = tmp_path / "initial-credentials.txt"
    text = f.read_text()
    pw = text.split("temporary password: ")[1].split()[0]
    assert oct(f.stat().st_mode & 0o777) == "0o600" and pw in capsys.readouterr().out
    with TestClient(app) as c:
        assert login(c, pw=pw).json()["must_change"] is True
        assert c.post("/api/v1/account/password", json={"current_password": pw, "new_password": GOOD}).status_code == 200
    assert not f.exists()                                                # deleted after the change


# ---------- login ----------
def test_wrong_password_and_unknown_user_look_the_same(client):
    a = login(client, pw="nope")
    b = login(client, user="ghost", pw="nope")
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


def test_username_is_case_insensitive(client):
    assert login(client, user="ADMIN").status_code == 200


def test_brute_force_is_blocked(client):
    codes = [login(client, pw="bad%d" % i).status_code for i in range(7)]
    assert codes[:5] == [401] * 5 and codes[5:] == [429, 429]
    assert login(client).status_code == 429                              # even the right password waits


def test_cookie_flags(client):
    c = login(client).headers["set-cookie"].lower()
    assert "httponly" in c and "samesite=strict" in c


# ---------- forced password change ----------
def test_temp_login_can_only_change_the_password(client):
    assert login(client).json()["must_change"] is True
    assert client.get("/api/v1/session").json()["must_change"] is True
    r = client.get("/api/v1/alerts")
    assert r.status_code == 403 and r.json()["detail"]["code"] == "password_change_required"
    assert client.get("/api/v1/admin/settings").status_code == 403
    assert client.get("/api/v1/logs/audit").status_code == 403
    assert client.get("/api/v1/stats").status_code == 403


def test_change_password_flow(client):
    login(client)
    bad = client.post("/api/v1/account/password", json={"current_password": "wrong", "new_password": GOOD})
    assert bad.status_code == 400 and bad.json()["detail"]["errors"]
    weak = client.post("/api/v1/account/password", json={"current_password": TEMP, "new_password": "short"})
    assert weak.status_code == 422 and "10 characters" in weak.json()["detail"]["errors"][0]
    ok = client.post("/api/v1/account/password", json={"current_password": TEMP, "new_password": GOOD})
    assert ok.status_code == 200
    assert client.get("/api/v1/alerts").status_code == 200               # unlocked, same browser session
    assert client.get("/api/v1/session").json()["must_change"] is False

    client.delete("/api/v1/session")
    assert login(client, pw=TEMP).status_code == 401                     # old password is dead
    assert login(client, pw=GOOD).json()["must_change"] is False


def test_changing_password_signs_out_other_logins(tmp_path):
    app = make(tmp_path)
    with TestClient(app) as a, TestClient(app) as b:
        login(a); full = a.post("/api/v1/account/password", json={"current_password": TEMP, "new_password": GOOD})
        assert full.status_code == 200
        login(b, pw=GOOD)
        assert b.get("/api/v1/alerts").status_code == 200
        assert a.post("/api/v1/account/password",
                      json={"current_password": GOOD, "new_password": "another long phrase"}).status_code == 200
        assert a.get("/api/v1/alerts").status_code == 200                # the one that changed stays in
        assert b.get("/api/v1/alerts").status_code == 401                # every other login is ended


def test_header_key_works_without_login_for_scripts(client):
    assert client.get("/api/v1/alerts", headers={"X-Admin-Key": "scriptkey"}).status_code == 200
    assert client.get("/api/v1/alerts", headers={"X-Admin-Key": "bad"}).status_code == 401


def test_password_endpoint_needs_login(client):
    assert client.post("/api/v1/account/password",
                       json={"current_password": "x", "new_password": GOOD}).status_code == 401


def test_logout_and_bad_sessions(client):
    full_login(client)
    assert client.delete("/api/v1/session").status_code == 200
    assert client.get("/api/v1/alerts").status_code == 401
    client.cookies.set("dh_session", "forged")
    assert client.get("/api/v1/alerts").status_code == 401


def test_expired_session_rejected(client):
    full_login(client)
    for s in client.app.state.sessions.values():
        s["exp"] = time.time() - 1
    assert client.get("/api/v1/alerts").status_code == 401


# ---------- forgot password ----------
def test_cli_reset_ends_logins_and_forces_change(tmp_path, capsys):
    app = make(tmp_path)
    with TestClient(app) as c:
        full_login(c)
        assert c.get("/api/v1/alerts").status_code == 200
        cli.main(["reset-password", "--db", str(tmp_path / "a.db")])
        out = capsys.readouterr().out
        new_pw = out.split("Password : ")[-1].split()[0]
        assert c.get("/api/v1/alerts").status_code == 401                # old session is gone
        assert login(c, pw=GOOD).status_code == 401                      # old password is gone
        assert login(c, pw=new_pw).json()["must_change"] is True
        assert (tmp_path / "initial-credentials.txt").exists()


def test_cli_rejects_unknown_user(tmp_path):
    make(tmp_path)
    with pytest.raises(SystemExit):
        cli.main(["reset-password", "--username", "ghost", "--db", str(tmp_path / "a.db")])


# ---------- audit trail ----------
def test_logins_and_changes_are_audited(client):
    login(client, pw="bad")
    full_login(client)
    actions = [a["action"] for a in client.get("/api/v1/logs/audit").json()["items"]]
    for a in ("login_failed", "login", "password_changed", "first_user_created"):
        assert a in actions
    assert "bad" not in str([a["detail"] for a in client.get("/api/v1/logs/audit").json()["items"]])  # no passwords in logs


# ---------- password rules ----------
def test_password_policy():
    assert check_new_password(GOOD, "admin", TEMP) == []
    assert check_new_password("short", "admin", TEMP)
    assert check_new_password(TEMP, "admin", TEMP)                         # same as current
    assert check_new_password("my-admin-password-1", "admin", TEMP)        # contains username
    assert check_new_password("dnshollow-rocks-2024", "bob", TEMP)         # too guessable
    assert check_new_password("aaaaaaaaaaaaaaa", "bob", TEMP)              # one repeated character
    assert check_new_password("x" * 200, "bob", TEMP)


def test_hashes_are_salted_and_verifiable():
    a, b = hash_password("same-password"), hash_password("same-password")
    assert a != b and verify_password("same-password", a) and not verify_password("other", a)
    assert not verify_password("x", "garbage")
