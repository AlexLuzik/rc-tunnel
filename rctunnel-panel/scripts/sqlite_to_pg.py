"""One-off migration: copy all rows from the SQLite DB into Postgres, preserving ids.

Usage (inside the app image, host networking so 127.0.0.1:5432 is reachable):
  OLD_DB=sqlite:////var/lib/rctunnel-panel/rctunnel-panel.db \
  NEW_DB=postgresql+psycopg://rctunnel:PASS@127.0.0.1:5432/rctunnel \
  python scripts/sqlite_to_pg.py

Idempotent: a table that already has rows in Postgres is skipped.
"""

from __future__ import annotations

import os

from sqlalchemy import create_engine, insert, select, text

from rctunnel_panel.models import Agent, Base, Node, Team, Tunnel, User

OLD = os.environ["OLD_DB"]
NEW = os.environ["NEW_DB"]

old = create_engine(OLD, connect_args={"check_same_thread": False} if OLD.startswith("sqlite") else {})
new = create_engine(NEW)

# create the schema on the target (no-op if it already exists)
Base.metadata.create_all(new)

# FK-safe order: parents before children
ORDER = [Team.__table__, Node.__table__, User.__table__, Agent.__table__, Tunnel.__table__]

with old.connect() as oc, new.begin() as nc:
    for t in ORDER:
        existing = nc.execute(text(f'SELECT COUNT(*) FROM "{t.name}"')).scalar() or 0
        if existing:
            print(f"  {t.name}: target already has {existing} rows — skipping")
            continue
        rows = [dict(r._mapping) for r in oc.execute(select(t))]
        if rows:
            nc.execute(insert(t), rows)
        print(f"  {t.name}: copied {len(rows)} rows")

# reset id sequences so future inserts don't collide with copied ids
with new.begin() as nc:
    for t in ORDER:
        nc.execute(text(
            f"SELECT setval(pg_get_serial_sequence('{t.name}','id'), "
            f"GREATEST((SELECT COALESCE(MAX(id),1) FROM \"{t.name}\"), 1))"
        ))

print("migration complete; sequences reset")
