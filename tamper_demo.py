#!/usr/bin/env python3
"""Simulates an insider editing the audit database, to show the blue team detects it.
Usage: python scripts/tamper_demo.py sqlite:////path/to/bayora.db [seq]
(For the Postgres deployment the app role is physically unable to do this - see db/init/01-roles.sh;
 this demo uses the SQLite dev database where no such privilege separation exists.)"""
import sys
from sqlalchemy import create_engine, text

url = sys.argv[1]
seq = int(sys.argv[2]) if len(sys.argv) > 2 else 10
with create_engine(url).begin() as c:
    row = c.execute(text("SELECT event_type, actor FROM audit_events WHERE seq=:s"), {"s": seq}).first()
    print(f"before: seq={seq} event={row.event_type} actor={row.actor}")
    c.execute(text("UPDATE audit_events SET actor='nobody' WHERE seq=:s"), {"s": seq})
print(f"tampered: seq={seq} actor -> 'nobody'")
