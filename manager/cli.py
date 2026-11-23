"""Command line helper for the manager.

  python -m manager.cli reset-password            give 'admin' a new temporary password
  python -m manager.cli reset-password --username bob

Use it when you forgot the password. Run it on the manager machine
(`bash run.sh --reset-password` does it for you). Everybody who is signed in
is signed out, and the next sign-in must choose a new password.
"""
import argparse
import os
import sys

from .api.dashboard_routes import credentials_path
from .db import Database
from .security import hash_password, make_temp_password


def reset_password(db: Database, username: str) -> str:
    pw = make_temp_password()
    user = db.get_user_by_name(username)
    if user is None:
        if username.lower() != "admin" or db.count_users() > 0:
            raise SystemExit("No user named '%s'." % username)
        db.create_user("admin", hash_password(pw), must_change=True)
    else:
        db.set_password(user["id"], hash_password(pw), must_change=True)
    db.audit("system", "password_reset_cli", username)
    f = credentials_path(db.path)
    f.write_text("username: %s\ntemporary password: %s\n"
                 "(this file is deleted when you change the password)\n" % (username, pw))
    f.chmod(0o600)
    return pw


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="manager.cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    rp = sub.add_parser("reset-password", help="set a new temporary password")
    rp.add_argument("--username", default="admin")
    rp.add_argument("--db", default=os.environ.get("DNSHOLLOW_DB", "dnshollow.db"))
    a = ap.parse_args(argv)
    db = Database(a.db)
    pw = reset_password(db, a.username)
    print("\n  New temporary login")
    print("  Username : %s" % a.username)
    print("  Password : %s" % pw)
    print("  You will be asked to choose a new password when you sign in.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
