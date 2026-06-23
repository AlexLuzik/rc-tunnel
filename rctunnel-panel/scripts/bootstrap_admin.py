"""Create or reset the admin user.

    python -m scripts.bootstrap_admin <email> <password>

If the user already exists, their password is reset and they are promoted to
admin. Since this is self-hosted with no email/password-reset flow, this script
IS the account-recovery mechanism — run it again to set a new password.
"""

from __future__ import annotations

import sys

from rctunnel_panel.config import get_settings
from rctunnel_panel.db import SessionLocal, init_db
from rctunnel_panel.models import Role, User
from rctunnel_panel.security import hash_password


def main() -> None:
    if len(sys.argv) != 3:
        print("usage: bootstrap_admin <email> <password>", file=sys.stderr)
        raise SystemExit(2)
    email, password = sys.argv[1], sys.argv[2]
    init_db()
    with SessionLocal() as db:
        user = db.query(User).filter(User.email == email).first()
        if user is None:
            db.add(User(email=email, password_hash=hash_password(password), role=Role.admin))
            action = "created"
        else:
            user.password_hash = hash_password(password)
            user.role = Role.admin
            action = "password reset"
        db.commit()
    base = get_settings().public_base_url.rstrip("/")
    print(f"admin {email} {action} — sign in at {base}/login")


if __name__ == "__main__":
    main()
