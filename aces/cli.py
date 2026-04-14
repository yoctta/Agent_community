"""Command-line interface for ACES."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from .config import load_config
from .experiment import ExperimentRunner, generate_conditions, run_single


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-5s [%(name)s] %(message)s",
        datefmt="%H:%M:%S",
    )


_CONFIG_DIR = str(Path(__file__).resolve().parent.parent / "config")


def _resolve_paths(args: argparse.Namespace) -> tuple[str, str, str]:
    """Swap in the research config paths when --research is set,
    unless the user explicitly pointed elsewhere."""
    if not getattr(args, "research", False):
        return args.enterprise, args.experiment, args.attacks
    defaults = (
        f"{_CONFIG_DIR}/enterprise.yaml",
        f"{_CONFIG_DIR}/experiment.yaml",
        f"{_CONFIG_DIR}/attacks.yaml",
    )
    research = (
        f"{_CONFIG_DIR}/community_research_enterprise.yaml",
        f"{_CONFIG_DIR}/community_research_experiment.yaml",
        f"{_CONFIG_DIR}/community_research_attacks.yaml",
    )
    picked = [
        r if cur == d else cur
        for cur, d, r in zip(
            (args.enterprise, args.experiment, args.attacks),
            defaults, research, strict=True,
        )
    ]
    return picked[0], picked[1], picked[2]


def _apply_cfg(cfg, args: argparse.Namespace) -> None:
    """Map CLI args onto ACESConfig fields."""
    cfg.output_dir = args.output
    cfg.llm_backend = args.backend
    cfg.llm_model = args.model
    cfg.llm_api_key = args.api_key or ""
    cfg.llm_base_url = args.base_url
    cfg.llm_reasoning_effort = getattr(args, "reasoning_effort", None)
    cfg.llm_concurrency = getattr(args, "concurrency", 16)
    cfg.llm_request_timeout = getattr(args, "request_timeout", 60.0)
    cfg.llm_max_tokens = getattr(args, "max_tokens", 512)
    cfg.llm_temperature = getattr(args, "temperature", 0.2)
    cfg.use_async_engine = bool(getattr(args, "async_engine", False))
    cfg.openclaw_base_url = args.openclaw_url
    cfg.moltbook_url = args.moltbook_url or cfg.moltbook_url
    cfg.moltbook_api_key = args.moltbook_key
    cfg.moltbook_submolt = args.moltbook_submolt


def cmd_run(args: argparse.Namespace) -> None:
    """Run a full experiment."""
    enterprise, experiment, attacks = _resolve_paths(args)
    cfg = load_config(
        enterprise_path=enterprise,
        experiment_path=experiment,
        attack_path=attacks,
    )
    _apply_cfg(cfg, args)

    runner = ExperimentRunner(cfg, args.output)
    runner.run()

    print("\n" + "=" * 90)
    print("EXPERIMENT RESULTS")
    print("=" * 90)
    print(runner.summary_table())
    print(f"\nResults saved to: {args.output}/experiment_summary.json")


def cmd_single(args: argparse.Namespace) -> None:
    """Run a single simulation with baseline defenses."""
    enterprise, experiment, attacks = _resolve_paths(args)
    cfg = load_config(
        enterprise_path=enterprise,
        experiment_path=experiment,
        attack_path=attacks,
    )
    _apply_cfg(cfg, args)

    from .experiment import Condition
    cond = Condition(name="baseline", factor_levels={})
    result = run_single(cfg, cond, args.seed, args.output)

    print(json.dumps(result, indent=2))


def cmd_conditions(args: argparse.Namespace) -> None:
    """List all experimental conditions without running them."""
    cfg = load_config(experiment_path=args.experiment)
    conditions = generate_conditions(cfg.experiment)
    print(f"Design: {cfg.experiment.design}")
    print(f"Factors: {len(cfg.experiment.factors)}")
    print(f"Conditions: {len(conditions)}")
    print(f"Seeds: {cfg.experiment.seeds}")
    print(f"Total runs: {len(conditions) * len(cfg.experiment.seeds)}")
    print()
    for i, c in enumerate(conditions):
        print(f"  [{i+1:3d}] {c.name}")
        for k, v in sorted(c.factor_levels.items()):
            print(f"        {k} = {v}")


def cmd_analyze(args: argparse.Namespace) -> None:
    """Analyze results from a completed experiment."""
    summary_path = Path(args.output) / "experiment_summary.json"
    if not summary_path.exists():
        print(f"No summary found at {summary_path}")
        sys.exit(1)

    with open(summary_path) as f:
        data = json.load(f)

    results = data.get("results", [])
    if not results:
        print("No results found.")
        return

    # Group by condition.
    from collections import defaultdict
    by_cond: dict[str, list[dict]] = defaultdict(list)
    for r in results:
        by_cond[r["condition"]].append(r)

    print(f"Experiment: {data.get('experiment', '?')}")
    print(f"Total runs: {data.get('total_runs', len(results))}")
    print()

    header = (f"{'Condition':<40} {'N':>3} {'PWCL':>8} {'JCR':>6} "
              f"{'TWR':>6} {'BR':>6} {'CSRI':>6}")
    print(header)
    print("-" * len(header))

    for cond_name, runs in sorted(by_cond.items()):
        n = len(runs)
        metrics_lists: dict[str, list[float]] = defaultdict(list)
        for r in runs:
            m = r.get("metrics") or {}
            for key in ("pwcl", "jcr", "twr", "blast_radius", "csri"):
                metrics_lists[key].append(m.get(key, 0.0))

        def mean(vals: list[float]) -> float:
            return sum(vals) / len(vals) if vals else 0.0

        print(
            f"{cond_name:<40} {n:>3} "
            f"{mean(metrics_lists['pwcl']):>8.2f} "
            f"{mean(metrics_lists['jcr']):>6.3f} "
            f"{mean(metrics_lists['twr']):>6.3f} "
            f"{mean(metrics_lists['blast_radius']):>6.3f} "
            f"{mean(metrics_lists['csri']):>6.3f}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="aces",
        description="ACES — Agent Community Enterprise Simulator",
    )
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    sub = parser.add_subparsers(dest="command")

    # Shared config arguments.
    config_dir = _CONFIG_DIR

    def add_config_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--enterprise", default=f"{config_dir}/enterprise.yaml",
                        help="Enterprise config YAML")
        p.add_argument("--experiment", default=f"{config_dir}/experiment.yaml",
                        help="Experiment config YAML")
        p.add_argument("--attacks", default=f"{config_dir}/attacks.yaml",
                        help="Attack config YAML")
        p.add_argument("--research", action="store_true",
                        help="Use the 15-agent research community configs "
                             "(community_research_{enterprise,experiment,attacks}.yaml)")
        p.add_argument("--output", "-o", default="results",
                        help="Output directory")
        p.add_argument("--backend", default="openai",
                        help="Agent runtime: openclaw, anthropic, openai, "
                             "openrouter, together, ollama, or any OpenAI-compatible name")
        p.add_argument("--model", default="", help="LLM model name")
        p.add_argument("--api-key", default="", help="LLM API key")
        p.add_argument("--base-url", default="",
                        help="LLM API base URL (auto-detected for known providers)")
        p.add_argument("--reasoning-effort", default=None,
                        choices=[None, "minimal", "low", "medium", "high"],
                        help="Reasoning budget for GPT-5/codex-spark models")
        p.add_argument("--concurrency", type=int, default=16,
                        help="Max in-flight LLM calls for the async engine")
        p.add_argument("--request-timeout", type=float, default=60.0)
        p.add_argument("--max-tokens", type=int, default=512)
        p.add_argument("--temperature", type=float, default=0.2)
        p.add_argument("--async-engine", action="store_true",
                        help="Use async two-phase tick execution "
                             "(parallelizes within-tick LLM calls)")
        p.add_argument("--openclaw-url", default="http://localhost:18789",
                        help="OpenClaw gateway base URL")
        p.add_argument("--moltbook-url", default="",
                        help="Moltbook API URL (for self-hosted instances)")
        p.add_argument("--moltbook-key", default="", help="Moltbook API key")
        p.add_argument("--moltbook-submolt", default="enterprise",
                        help="Default Moltbook submolt")


    # run: full experiment
    p_run = sub.add_parser("run", help="Run a full experiment")
    add_config_args(p_run)

    # single: one run
    p_single = sub.add_parser("single", help="Run a single simulation")
    add_config_args(p_single)
    p_single.add_argument("--seed", type=int, default=42)

    # conditions: list conditions
    p_cond = sub.add_parser("conditions", help="List experimental conditions")
    p_cond.add_argument("--experiment", default=f"{config_dir}/experiment.yaml")

    # analyze: analyze results
    p_analyze = sub.add_parser("analyze", help="Analyze experiment results")
    p_analyze.add_argument("--output", "-o", default="results")

    args = parser.parse_args()
    setup_logging(args.log_level)

    if args.command == "run":
        cmd_run(args)
    elif args.command == "single":
        cmd_single(args)
    elif args.command == "conditions":
        cmd_conditions(args)
    elif args.command == "analyze":
        cmd_analyze(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
