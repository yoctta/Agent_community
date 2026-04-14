#!/usr/bin/env python3
"""Analysis script for ACES research-community runs.

Reads every ``run_*.db`` under the output directory and emits three
artifacts into ``<output>/analysis/``:

1. ``per_day.csv`` — one row per (run_id, condition, seed, sim_day)
   with the full set of MetricSnapshot fields, including the research
   primary outcome ``community_token_balance_excluding_attackers``.
2. ``summary.csv`` — one row per (condition, seed) with final metrics
   and a few derived quantities (mean community balance over the
   second half of the run, number of detected anomalies, etc.).
3. ``condition_means.csv`` — one row per condition with the
   seed-averaged primary outcome, CSRI, JCR, TWR, and
   security_intervention_count.

Optional third-party analysis (mixed-effects models, bootstrap CIs,
FDR correction) is *not* in scope here — this script does the minimum
needed to compare conditions during piloting.  Run:

    python analyze_research_results.py --output results/

Then inspect ``results/analysis/condition_means.csv`` for the
research primary outcome.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aces.database import Database
from aces.models import EventType

log = logging.getLogger("analyze_research_results")


PER_DAY_COLUMNS = [
    "run_id", "condition", "seed", "sim_day",
    "community_token_balance_excluding_attackers",
    "attacker_token_balance",
    "active_impersonation_grants",
    "transfers_today",
    "group_posts_today",
    "secret_reads_today",
    "pwcl", "jcr", "twr", "blast_radius",
    "agents_healthy", "agents_compromised", "agents_quarantined",
    "agents_degraded", "agents_distracted",
    "total_tokens_used", "total_salary_paid",
    "total_penalties", "total_rewards",
    "jobs_completed", "jobs_failed", "jobs_pending",
]

SUMMARY_COLUMNS = [
    "run_id", "condition", "seed", "final_day", "status",
    "community_token_balance_excluding_attackers",
    "attacker_token_balance",
    "csri", "pwcl", "jcr", "twr", "blast_radius",
    "impersonation_success_count", "credential_compromise_count",
    "token_loss_from_impersonation",
    "security_intervention_count",
    "time_to_first_security_isolation",
    "total_anomaly_detections",
    "total_mail_audits",
    "mean_community_balance_last_half",
]


def _discover_runs(output_dir: Path) -> list[Path]:
    runs = sorted(output_dir.glob("run_*.db"))
    return runs


def _analyze_one(db_path: Path) -> tuple[list[dict], dict]:
    """Return (per-day rows, summary row) for a single run DB."""
    db = Database(str(db_path))
    try:
        runs = db.get_runs()
        if not runs:
            return [], {}
        run = runs[0]
        snapshots = db.get_metric_snapshots(run.id)
        per_day_rows: list[dict] = []
        for s in snapshots:
            per_day_rows.append({
                "run_id": run.id,
                "condition": run.condition_name or "",
                "seed": run.seed,
                "sim_day": s.sim_day,
                "community_token_balance_excluding_attackers":
                    s.community_token_balance_excluding_attackers,
                "attacker_token_balance": s.attacker_token_balance,
                "active_impersonation_grants": s.active_impersonation_grants,
                "transfers_today": s.transfers_today,
                "group_posts_today": s.group_posts_today,
                "secret_reads_today": s.secret_reads_today,
                "pwcl": s.pwcl,
                "jcr": s.jcr,
                "twr": s.twr,
                "blast_radius": s.blast_radius,
                "agents_healthy": s.agents_healthy,
                "agents_compromised": s.agents_compromised,
                "agents_quarantined": s.agents_quarantined,
                "agents_degraded": s.agents_degraded,
                "agents_distracted": s.agents_distracted,
                "total_tokens_used": s.total_tokens_used,
                "total_salary_paid": s.total_salary_paid,
                "total_penalties": s.total_penalties,
                "total_rewards": s.total_rewards,
                "jobs_completed": s.jobs_completed,
                "jobs_failed": s.jobs_failed,
                "jobs_pending": s.jobs_pending,
            })

        # Half-window average of the primary outcome so a single
        # collapsed day doesn't dominate.
        balances = [
            s.community_token_balance_excluding_attackers for s in snapshots
        ]
        mid = len(balances) // 2
        half = balances[mid:] or balances
        mean_half = sum(half) / len(half) if half else 0.0

        fm = run.final_metrics or {}
        anomaly_count = db.count_events(EventType.ANOMALY_DETECTED.value)
        audit_count = db.count_events(EventType.MAIL_AUDITED.value)

        summary = {
            "run_id": run.id,
            "condition": run.condition_name or "",
            "seed": run.seed,
            "final_day": run.final_day,
            "status": run.status,
            "community_token_balance_excluding_attackers":
                fm.get("community_token_balance_excluding_attackers", 0.0),
            "attacker_token_balance": fm.get("attacker_token_balance", 0.0),
            "csri": fm.get("csri", 0.0),
            "pwcl": fm.get("pwcl", 0.0),
            "jcr": fm.get("jcr", 0.0),
            "twr": fm.get("twr", 0.0),
            "blast_radius": fm.get("blast_radius", 0.0),
            "impersonation_success_count": fm.get("impersonation_success_count", 0),
            "credential_compromise_count": fm.get("credential_compromise_count", 0),
            "token_loss_from_impersonation": fm.get("token_loss_from_impersonation", 0.0),
            "security_intervention_count": fm.get("security_intervention_count", 0),
            "time_to_first_security_isolation": fm.get("time_to_first_security_isolation", 0.0),
            "total_anomaly_detections": anomaly_count,
            "total_mail_audits": audit_count,
            "mean_community_balance_last_half": mean_half,
        }
        return per_day_rows, summary
    finally:
        db.close()


def _write_csv(path: Path, columns: list[str], rows: list[dict]) -> None:
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({c: row.get(c, "") for c in columns})


def _condition_means(summary_rows: list[dict]) -> list[dict]:
    """Group summary rows by condition and produce seed-averaged
    means for the research primary outcome + a few side metrics."""
    by_cond: dict[str, list[dict]] = defaultdict(list)
    for r in summary_rows:
        by_cond[r["condition"]].append(r)
    out: list[dict] = []
    for cond, rows in sorted(by_cond.items()):
        n = len(rows)

        def mean(key: str) -> float:
            vals = [float(r.get(key, 0.0) or 0.0) for r in rows]
            return sum(vals) / len(vals) if vals else 0.0

        out.append({
            "condition": cond,
            "n_seeds": n,
            "mean_community_balance":
                mean("community_token_balance_excluding_attackers"),
            "mean_attacker_balance": mean("attacker_token_balance"),
            "mean_csri": mean("csri"),
            "mean_pwcl": mean("pwcl"),
            "mean_jcr": mean("jcr"),
            "mean_twr": mean("twr"),
            "mean_blast_radius": mean("blast_radius"),
            "mean_anomaly_detections": mean("total_anomaly_detections"),
            "mean_security_interventions": mean("security_intervention_count"),
            "mean_imp_success": mean("impersonation_success_count"),
        })
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Analyze ACES research-community run outputs.",
    )
    parser.add_argument("--output", "-o", default="results",
                        help="Directory containing run_*.db files")
    parser.add_argument("--analysis-dir", default="",
                        help="Where to write the CSV artifacts "
                             "(default: <output>/analysis/)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    out_dir = Path(args.output).resolve()
    if not out_dir.is_dir():
        log.error("output dir %s not found", out_dir)
        return 2
    analysis_dir = Path(args.analysis_dir) if args.analysis_dir else out_dir / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)

    runs = _discover_runs(out_dir)
    log.info("found %d run DBs under %s", len(runs), out_dir)
    if not runs:
        return 1

    all_per_day: list[dict] = []
    all_summary: list[dict] = []
    for db_path in runs:
        try:
            per_day, summary = _analyze_one(db_path)
        except Exception as e:
            log.warning("skipping %s: %s", db_path.name, e)
            continue
        all_per_day.extend(per_day)
        if summary:
            all_summary.append(summary)

    per_day_path = analysis_dir / "per_day.csv"
    summary_path = analysis_dir / "summary.csv"
    cond_path = analysis_dir / "condition_means.csv"
    _write_csv(per_day_path, PER_DAY_COLUMNS, all_per_day)
    _write_csv(summary_path, SUMMARY_COLUMNS, all_summary)
    cond_rows = _condition_means(all_summary)
    cond_columns = [
        "condition", "n_seeds", "mean_community_balance",
        "mean_attacker_balance", "mean_csri", "mean_pwcl",
        "mean_jcr", "mean_twr", "mean_blast_radius",
        "mean_anomaly_detections", "mean_security_interventions",
        "mean_imp_success",
    ]
    _write_csv(cond_path, cond_columns, cond_rows)

    log.info("wrote %s (%d rows)", per_day_path, len(all_per_day))
    log.info("wrote %s (%d rows)", summary_path, len(all_summary))
    log.info("wrote %s (%d conditions)", cond_path, len(cond_rows))

    # Pretty-print the condition-level table so piloting can be eyeballed.
    if cond_rows:
        header = (f"{'condition':<40} {'N':>3} "
                  f"{'comm_bal':>11} {'atk_bal':>9} "
                  f"{'csri':>6} {'jcr':>6} {'anom':>5}")
        print()
        print(header)
        print("-" * len(header))
        for r in cond_rows:
            print(f"{r['condition']:<40} {r['n_seeds']:>3} "
                  f"{r['mean_community_balance']:>11.0f} "
                  f"{r['mean_attacker_balance']:>9.0f} "
                  f"{r['mean_csri']:>6.3f} {r['mean_jcr']:>6.3f} "
                  f"{r['mean_anomaly_detections']:>5.1f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
