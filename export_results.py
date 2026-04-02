"""Export the latest ACES simulation result to JSON for frontend visualization."""
import sqlite3
import json
import glob
import os
import sys

def export_db(db_path: str) -> dict:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    def q(sql, params=()):
        return [dict(r) for r in conn.execute(sql, params).fetchall()]

    data = {
    "run": q("SELECT * FROM runs")[0] if q("SELECT * FROM runs") else {},
    "agents": q("SELECT * FROM agents"),
    "events": q("SELECT * FROM events ORDER BY created_at"),
    "incidents": q("SELECT * FROM incidents ORDER BY sim_day_detected"),
    "messages": q("""
    SELECT m.*,
    CAST((julianday(m.delivered_at) - julianday(r.started_at)) AS INTEGER) + 1 as sim_day
    FROM messages m, runs r
    ORDER BY m.delivered_at
    """),
    "jobs": q("SELECT * FROM jobs ORDER BY created_day"),
    "agent_memory": q("SELECT * FROM agent_memory ORDER BY sim_day_updated"),
    "metric_snapshots": q("SELECT * FROM metric_snapshots ORDER BY sim_day"),
    "ledger": q("SELECT * FROM ledger ORDER BY sim_day"),
}

    conn.close()
    return data

if __name__ == "__main__":
    # Find latest DB
    if len(sys.argv) > 1:
        db_path = sys.argv[1]
    else:
        files = sorted(glob.glob("results/*.db"), key=os.path.getmtime)
        if not files:
            print("No result files found in results/")
            sys.exit(1)
        db_path = files[-1]

    print(f"Exporting: {db_path}")
    data = export_db(db_path)

    out_path = "results/export.json"
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2, default=str)

    print(f"Exported to: {out_path}")
    print(f"  Agents: {len(data['agents'])}")
    print(f"  Events: {len(data['events'])}")
    print(f"  Messages: {len(data['messages'])}")
    print(f"  Incidents: {len(data['incidents'])}")
    print(f"  Memory entries: {len(data['agent_memory'])}")
