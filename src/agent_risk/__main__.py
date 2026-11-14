"""Command line: ``python -m agent_risk generate|agentdojo``."""

import argparse
import sys
from dataclasses import asdict
from pathlib import Path

from agent_risk import __version__
from agent_risk.agentdojo import DojoCallRow, RunRow, iter_traces, parse_trace
from agent_risk.gateway import CallFeatures
from agent_risk.synthetic import (
    GENERATOR_VERSION,
    ORACLE_VERSION,
    AuditRow,
    GeneratorConfig,
    LabelRow,
    ScenarioRow,
    generate,
)
from agent_risk.tables import write_manifest, write_rows


def _generate(out: Path, seed: int, n_families: int) -> None:
    cfg = GeneratorConfig(seed=seed, n_families=n_families)
    data = generate(cfg)
    hashes = {
        "scenarios.csv.gz": write_rows(out / "scenarios.csv.gz", data.scenarios, ScenarioRow),
        "calls.csv.gz": write_rows(out / "calls.csv.gz", data.calls, CallFeatures),
        "labels.csv.gz": write_rows(out / "labels.csv.gz", data.labels, LabelRow),
        "audit.csv.gz": write_rows(out / "audit.csv.gz", data.audit, AuditRow),
    }
    config = {k: list(v) if isinstance(v, tuple) else v for k, v in asdict(cfg).items()}
    write_manifest(
        out / "manifest.json",
        {
            "dataset": "agent-risk synthetic",
            "package_version": __version__,
            "generator_version": GENERATOR_VERSION,
            "oracle_version": ORACLE_VERSION,
            "config": config,
            "counts": {
                "families": len(data.scenarios),
                "runs": len({c.run_id for c in data.calls}),
                "calls": len(data.calls),
            },
            "sha256": hashes,
            "rebuild": f"uv run python -m agent_risk generate --out {out} --seed {seed}"
            f" --families {n_families}",
        },
    )


def _agentdojo(runs_dir: Path, out: Path, commit: str) -> None:
    runs: list[RunRow] = []
    calls: list[DojoCallRow] = []
    for path in iter_traces(runs_dir):
        run, run_calls = parse_trace(path, runs_dir)
        runs.append(run)
        calls.extend(run_calls)
    hashes = {
        "runs.csv.gz": write_rows(out / "runs.csv.gz", runs, RunRow),
        "calls.csv.gz": write_rows(out / "calls.csv.gz", calls, DojoCallRow),
    }
    write_manifest(
        out / "manifest.json",
        {
            "dataset": "AgentDojo published traces, derived tables",
            "source": "https://github.com/ethz-spylab/agentdojo",
            "source_commit": commit,
            "license": "MIT, see LICENSE-agentdojo.txt",
            "models": sorted({r.model for r in runs}),
            "counts": {"runs": len(runs), "calls": len(calls)},
            "sha256": hashes,
            "package_version": __version__,
        },
    )


def main(argv: list[str] | None = None) -> int:
    """Entry point; returns the process exit code."""
    parser = argparse.ArgumentParser(prog="agent_risk")
    sub = parser.add_subparsers(dest="command", required=True)
    gen = sub.add_parser("generate", help="generate the synthetic dataset")
    gen.add_argument("--out", type=Path, required=True)
    gen.add_argument("--seed", type=int, default=GeneratorConfig().seed)
    gen.add_argument("--families", type=int, default=GeneratorConfig().n_families)
    dojo = sub.add_parser("agentdojo", help="extract tables from AgentDojo traces")
    dojo.add_argument("--runs", type=Path, required=True)
    dojo.add_argument("--out", type=Path, required=True)
    dojo.add_argument("--commit", required=True)
    args = parser.parse_args(argv)
    if args.command == "generate":
        _generate(args.out, args.seed, args.families)
    else:
        _agentdojo(args.runs, args.out, args.commit)
    return 0


if __name__ == "__main__":
    sys.exit(main())
