#!/usr/bin/env python3
"""
PicoCTF Autonomous Solving Agent

Usage:
    docker-compose up          # solve all unsolved challenges
    docker-compose run ctf-agent --category crypto   # filter by category
    docker-compose run ctf-agent --challenge "Mod 26" # solve specific challenge
    docker-compose run ctf-agent --dry-run             # solve but don't submit
    docker-compose run ctf-agent --workers 4           # solve 4 challenges in parallel
"""

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table

from picoctf_client import PicoCTFClient, Challenge
from solver import solve_in_process

# ── Paths ──
WORKDIR = Path("/app/workdir")
LOGDIR = Path("/app/logs")

console = Console()


def setup_logging(level: str = "INFO"):
    LOGDIR.mkdir(parents=True, exist_ok=True)
    log_file = LOGDIR / f"agent_{datetime.now():%Y%m%d_%H%M%S}.log"

    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(message)s",
        datefmt="%H:%M:%S",
        handlers=[
            RichHandler(console=console, rich_tracebacks=True, show_path=False),
            logging.FileHandler(log_file, encoding="utf-8"),
        ],
    )
    return logging.getLogger(__name__)


def parse_args():
    p = argparse.ArgumentParser(description="PicoCTF Autonomous Solver")
    p.add_argument("--category", "-c", help="Filter by category (comma-separated)")
    p.add_argument("--challenge", help="Solve a specific challenge by name")
    p.add_argument("--max-points", type=int, help="Skip challenges above N points")
    p.add_argument("--dry-run", action="store_true", help="Solve but don't submit flags")
    p.add_argument("--max-attempts", type=int, default=3, help="Max solve attempts per challenge")
    p.add_argument("--list", action="store_true", help="Just list challenges and exit")
    p.add_argument("--unsolved-only", action="store_true", default=True, help="Skip already-solved")
    p.add_argument("--workers", "-w", type=int, default=1, help="Number of parallel solvers (default: 1)")
    return p.parse_args()


def filter_challenges(
    challenges: list[Challenge],
    categories: list[str] | None = None,
    name: str | None = None,
    max_points: int | None = None,
    unsolved_only: bool = True,
) -> list[Challenge]:
    """Apply filters and sort by points (easiest first)."""
    filtered = challenges

    if unsolved_only:
        filtered = [c for c in filtered if not c.solved]

    if categories:
        cats = [c.lower().strip() for c in categories]
        filtered = [c for c in filtered if c.category.lower() in cats]

    if name:
        filtered = [c for c in filtered if name.lower() in c.name.lower()]

    if max_points:
        filtered = [c for c in filtered if c.points <= max_points]

    # Sort: easiest first
    filtered.sort(key=lambda c: (c.points, c.name))
    return filtered


def display_challenges(challenges: list[Challenge]):
    """Print a nice table of challenges."""
    table = Table(title="Challenges", show_lines=True)
    table.add_column("ID", width=6)
    table.add_column("Name", min_width=20)
    table.add_column("Category", width=12)
    table.add_column("Points", width=8, justify="right")
    table.add_column("Solved", width=7, justify="center")

    for c in challenges:
        table.add_row(
            c.id,
            c.name,
            c.category,
            str(c.points),
            "✅" if c.solved else "❌",
        )

    console.print(table)
    console.print(f"\nTotal: {len(challenges)} challenges")


def save_result(challenge: Challenge, flag: str | None, workdir: Path):
    """Save solve result to a JSON log."""
    results_file = LOGDIR / "results.jsonl"
    record = {
        "timestamp": datetime.now().isoformat(),
        "challenge": challenge.name,
        "category": challenge.category,
        "points": challenge.points,
        "flag": flag,
        "solved": flag is not None,
        "workdir": str(workdir),
    }
    with open(results_file, "a") as f:
        f.write(json.dumps(record) + "\n")


def prepare_challenge(client: PicoCTFClient, challenge: Challenge, tag: str) -> tuple[Challenge, Path]:
    """Enrich a challenge and download its files. Returns (challenge, workdir)."""
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in challenge.name)
    challenge_dir = WORKDIR / f"{safe_name}_{challenge.id}"
    challenge_dir.mkdir(parents=True, exist_ok=True)

    console.print(f"{tag} Fetching challenge details...")
    challenge = client.enrich_challenge(challenge)

    if challenge.files:
        console.print(f"{tag} Downloading {len(challenge.files)} file(s)...")
        client.download_challenge_files(challenge, challenge_dir)

    # Save challenge info for the solver subprocess
    (challenge_dir / "challenge.json").write_text(
        json.dumps({
            "name": challenge.name,
            "category": challenge.category,
            "points": challenge.points,
            "description": challenge.description,
            "hints": challenge.hints,
            "connection_info": challenge.connection_info,
            "on_demand": challenge.on_demand,
        }, indent=2)
    )

    return challenge, challenge_dir


def main():
    args = parse_args()
    log_level = os.environ.get("LOG_LEVEL", "INFO")
    log = setup_logging(log_level)

    # ── Config from env + args ──
    username = os.environ.get("PICOCTF_USERNAME")
    password = os.environ.get("PICOCTF_PASSWORD")
    base_url = os.environ.get("PICOCTF_URL", "https://play.picoctf.org")
    model = os.environ.get("MODEL", "claude-opus-4-6")
    max_turns = 30

    dry_run = args.dry_run or os.environ.get("DRY_RUN", "false").lower() == "true"
    max_attempts = args.max_attempts or int(os.environ.get("MAX_ATTEMPTS_PER_CHALLENGE", "3"))
    max_points = args.max_points or (int(os.environ.get("MAX_POINTS", "0")) or None)
    workers = args.workers or int(os.environ.get("WORKERS", "1"))
    categories = None
    if args.category:
        categories = args.category.split(",")
    elif os.environ.get("CATEGORIES"):
        categories = os.environ["CATEGORIES"].split(",")

    if not os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"):
        console.print("[red]ERROR: CLAUDE_CODE_OAUTH_TOKEN not set[/red]")
        console.print("[red]Run 'claude setup-token' to generate one from your subscription[/red]")
        sys.exit(1)
    if not username or not password:
        console.print("[red]ERROR: PICOCTF_USERNAME / PICOCTF_PASSWORD not set[/red]")
        sys.exit(1)

    # ── Login ──
    client = PicoCTFClient(base_url, username, password)
    if not client.login():
        console.print("[red]Failed to log in to picoCTF[/red]")
        sys.exit(1)

    # ── Fetch challenges ──
    console.print("\n[bold]Fetching challenges...[/bold]")
    all_challenges = client.get_challenges()
    if not all_challenges:
        console.print("[yellow]No challenges found. The platform API may have changed.[/yellow]")
        sys.exit(1)

    console.print(f"Found {len(all_challenges)} total challenges")

    # ── Filter ──
    targets = filter_challenges(
        all_challenges,
        categories=categories,
        name=args.challenge,
        max_points=max_points,
        unsolved_only=args.unsolved_only,
    )

    if args.list:
        display_challenges(targets)
        sys.exit(0)

    if not targets:
        console.print("[yellow]No matching unsolved challenges found.[/yellow]")
        display_challenges(all_challenges)
        sys.exit(0)

    console.print(f"\n[bold green]Targeting {len(targets)} challenges with {workers} worker(s)[/bold green]")
    display_challenges(targets)

    # ── Solve ──
    solved_count = 0
    failed_count = 0

    with ProcessPoolExecutor(max_workers=workers) as pool:
        # Submit all challenges to the process pool
        future_to_challenge = {}

        for i, challenge in enumerate(targets, 1):
            tag = f"[{i}/{len(targets)}]"
            console.print(f"\n{'━' * 60}")
            console.print(
                f"[bold cyan]{tag} {challenge.name} "
                f"({challenge.category}, {challenge.points} pts)[/bold cyan]"
            )
            console.print(f"{'━' * 60}")

            # Prepare (enrich + download) in the main process
            challenge, challenge_dir = prepare_challenge(client, challenge, tag)

            # Serialize challenge info for the subprocess
            challenge_json = json.dumps({
                "name": challenge.name,
                "category": challenge.category,
                "points": challenge.points,
                "description": challenge.description,
                "hints": challenge.hints,
                "connection_info": challenge.connection_info,
            })

            # Submit solver to the pool (each gets its own process + event loop)
            future = pool.submit(
                solve_in_process,
                challenge_json,
                str(challenge_dir),
                model,
                max_turns,
            )
            future_to_challenge[future] = (challenge, challenge_dir, tag)

        # Collect results as they complete
        for future in as_completed(future_to_challenge):
            challenge, challenge_dir, tag = future_to_challenge[future]
            try:
                flag = future.result()
            except Exception as e:
                log.error("%s Solver error for '%s': %s", tag, challenge.name, e, exc_info=True)
                flag = None

            # Handle retries
            attempts_left = max_attempts - 1
            while not flag and attempts_left > 0:
                attempts_left -= 1
                console.print(f"[yellow]{tag} Retrying '{challenge.name}' ({max_attempts - attempts_left}/{max_attempts})[/yellow]")
                time.sleep(2)
                challenge_json = json.dumps({
                    "name": challenge.name,
                    "category": challenge.category,
                    "points": challenge.points,
                    "description": challenge.description,
                    "hints": challenge.hints,
                    "connection_info": challenge.connection_info,
                })
                try:
                    flag = pool.submit(
                        solve_in_process,
                        challenge_json,
                        str(challenge_dir),
                        model,
                        max_turns,
                    ).result()
                except Exception as e:
                    log.error("%s Retry error for '%s': %s", tag, challenge.name, e)
                    flag = None

            # Submit flag
            if flag:
                console.print(f"[bold green]{tag} 🏁 FLAG: {flag}[/bold green]")
                if dry_run:
                    console.print(f"[yellow]{tag} (dry run — not submitting)[/yellow]")
                    solved_count += 1
                else:
                    accepted = client.submit_flag(challenge, flag)
                    if accepted:
                        console.print(f"[bold green]{tag} ✅ Accepted![/bold green]")
                        solved_count += 1
                    else:
                        console.print(f"[red]{tag} Flag was rejected by the platform[/red]")
                        failed_count += 1
            else:
                console.print(f"[red]{tag} ❌ Could not solve '{challenge.name}'[/red]")
                failed_count += 1

            save_result(challenge, flag, challenge_dir)

    # ── Summary ──
    console.print(f"\n{'═' * 60}")
    console.print("[bold]FINAL RESULTS[/bold]")
    console.print(f"  Solved:  {solved_count}")
    console.print(f"  Failed:  {failed_count}")
    console.print(f"  Total:   {len(targets)}")
    console.print(f"  Workers: {workers}")
    console.print(f"{'═' * 60}")

    client.close()


if __name__ == "__main__":
    main()
