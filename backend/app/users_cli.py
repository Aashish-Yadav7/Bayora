"""
Create a person account (bootstrap the first EVALUATOR here):
  BAYORA_DB_PATH=bayora.db python3 -m backend.app.users_cli add alice EVALUATOR
Password is read from BAYORA_NEW_PASSWORD or prompted (hidden). Minimum 12 characters.
"""
from __future__ import annotations

import getpass
import os
import sys

from .auth import Role, create_user, ensure_tables
from .database import DatabaseManager


def main(argv: list) -> int:
    if len(argv) != 3 or argv[0] != "add":
        print("usage: python3 -m backend.app.users_cli add <username> <RED_TEAM|BLUE_TEAM|EVALUATOR>")
        return 2
    try:
        role = Role(argv[2].upper())
    except ValueError:
        print("unknown role"); return 2
    password = os.environ.get("BAYORA_NEW_PASSWORD") or getpass.getpass("Password (min 12 chars): ")
    db = DatabaseManager(os.environ.get("BAYORA_DB_PATH", "bayora.db"))
    try:
        ensure_tables(db)
        create_user(db, argv[1], role, password)
    except ValueError as exc:
        print(f"error: {exc}"); return 1
    finally:
        db.close()
    print(f"created {argv[1]} ({role.value})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
