"""
MCP tool server for the CTF orchestrator agent.

Provides tools to:
- List and inspect picoCTF challenges
- Spawn solver agents (single or parallel)
- Submit flags
- Track progress
"""

import json
import logging
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from claude_agent_sdk import tool, create_sdk_mcp_server

from picoctf_client import PicoCTFClient, Challenge
from solver import solve_in_process

log = logging.getLogger(__name__)

# ── Paths ──
WORKDIR = Path("/app/workdir")
LOGDIR = Path("/app/logs")


def build_ctf_mcp_server(client: PicoCTFClient, model: str, max_turns: int = 30):
    """
    Create an in-process MCP server with tools for the orchestrator.
    The `client` must already be logged in.
    """

    # ──────────────────── picoCTF tools ────────────────────

    @tool(
        "list_challenges",
        "List picoCTF challenges. Returns JSON array with id, name, category, points, solved status. "
        "Use filters to narrow results. Results are sorted by points (easiest first).",
        {"category": str, "max_points": int, "unsolved_only": bool},
    )
    async def list_challenges(args):
        all_challenges = client.get_challenges()
        filtered = all_challenges

        if args.get("unsolved_only", True):
            filtered = [c for c in filtered if not c.solved]

        cat = args.get("category", "")
        if cat:
            filtered = [c for c in filtered if cat.lower() in c.category.lower()]

        max_pts = args.get("max_points", 0)
        if max_pts and max_pts > 0:
            filtered = [c for c in filtered if c.points <= max_pts]

        filtered.sort(key=lambda c: (c.points, c.name))

        result = [
            {
                "id": c.id,
                "name": c.name,
                "category": c.category,
                "points": c.points,
                "solved": c.solved,
                "tags": c.tags,
            }
            for c in filtered
        ]

        summary = f"Found {len(result)} challenges"
        if cat:
            summary += f" in category '{cat}'"
        if max_pts:
            summary += f" with max {max_pts} points"

        return {
            "content": [
                {"type": "text", "text": f"{summary}\n\n{json.dumps(result, indent=2)}"}
            ]
        }

    @tool(
        "get_challenge_details",
        "Get full details for a challenge: description, hints, files, connection info. "
        "Also starts on-demand instances if needed.",
        {"challenge_id": str},
    )
    async def get_challenge_details(args):
        cid = args["challenge_id"]

        # Build a minimal Challenge object to enrich
        all_challenges = client.get_challenges()
        target = None
        for c in all_challenges:
            if c.id == cid:
                target = c
                break

        if not target:
            return {
                "content": [{"type": "text", "text": f"Challenge {cid} not found"}],
                "is_error": True,
            }

        enriched = client.enrich_challenge(target)

        result = {
            "id": enriched.id,
            "name": enriched.name,
            "category": enriched.category,
            "points": enriched.points,
            "description": enriched.description,
            "hints": enriched.hints,
            "files": enriched.files,
            "connection_info": enriched.connection_info,
            "on_demand": enriched.on_demand,
            "solved": enriched.solved,
        }

        return {
            "content": [{"type": "text", "text": json.dumps(result, indent=2)}]
        }

    @tool(
        "submit_flag",
        "Submit a flag for a challenge. Returns whether it was accepted.",
        {"challenge_id": str, "flag": str},
    )
    async def submit_flag(args):
        cid = args["challenge_id"]
        flag = args["flag"]

        # Build minimal Challenge for submission
        ch = Challenge(
            id=cid, name="", category="", points=0, description=""
        )

        accepted = client.submit_flag(ch, flag)
        status = "ACCEPTED" if accepted else "REJECTED"

        # Log the result
        _save_result(ch.name or cid, "", 0, flag if accepted else None)

        return {
            "content": [
                {"type": "text", "text": f"Flag submission for challenge {cid}: {status}"}
            ]
        }

    # ──────────────────── solver tools ────────────────────

    @tool(
        "solve_challenge",
        "Spawn a Claude Code solver agent to attempt a single challenge. "
        "Downloads files, builds a prompt, and runs the solver in a subprocess. "
        "Returns the flag if found, or a failure message. "
        "Use extra_hints to provide additional strategy tips for the solver.",
        {"challenge_id": str, "extra_hints": str},
    )
    async def solve_challenge(args):
        cid = args["challenge_id"]
        extra_hints = args.get("extra_hints", "")

        # Find and enrich the challenge
        all_challenges = client.get_challenges()
        target = None
        for c in all_challenges:
            if c.id == cid:
                target = c
                break

        if not target:
            return {
                "content": [{"type": "text", "text": f"Challenge {cid} not found"}],
                "is_error": True,
            }

        enriched = client.enrich_challenge(target)

        # Prepare workdir
        safe_name = "".join(
            c if c.isalnum() or c in "-_" else "_" for c in enriched.name
        )
        challenge_dir = WORKDIR / f"{safe_name}_{enriched.id}"
        challenge_dir.mkdir(parents=True, exist_ok=True)

        # Download files
        if enriched.files:
            client.download_challenge_files(enriched, challenge_dir)

        # Save challenge info
        challenge_info = {
            "name": enriched.name,
            "category": enriched.category,
            "points": enriched.points,
            "description": enriched.description,
            "hints": enriched.hints,
            "connection_info": enriched.connection_info,
        }

        if extra_hints:
            challenge_info["extra_hints"] = extra_hints

        (challenge_dir / "challenge.json").write_text(
            json.dumps(challenge_info, indent=2)
        )

        challenge_json = json.dumps(challenge_info)

        # Run solver in a separate process (blocking call, but that's OK for MCP tools)
        try:
            flag = solve_in_process(
                challenge_json, str(challenge_dir), model, max_turns
            )
        except Exception as e:
            flag = None
            log.error("Solver error for %s: %s", enriched.name, e)

        # Save result
        _save_result(enriched.name, enriched.category, enriched.points, flag)

        if flag:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            f"SOLVED: {enriched.name}\n"
                            f"Flag: {flag}\n"
                            f"Workdir: {challenge_dir}"
                        ),
                    }
                ]
            }
        else:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            f"FAILED: {enriched.name}\n"
                            f"The solver could not find the flag after {max_turns} turns.\n"
                            f"Workdir: {challenge_dir}\n"
                            f"Check the workdir for any partial progress."
                        ),
                    }
                ]
            }

    @tool(
        "solve_challenges_parallel",
        "Spawn multiple solver agents in parallel. "
        "Provide a list of challenge IDs and the number of workers. "
        "Returns a JSON object mapping challenge IDs to their results (flag or null).",
        {"challenge_ids": str, "max_workers": int},
    )
    async def solve_challenges_parallel(args):
        # challenge_ids comes as a JSON string of a list
        try:
            ids = json.loads(args["challenge_ids"])
        except (json.JSONDecodeError, TypeError):
            # Try comma-separated
            ids = [x.strip() for x in args["challenge_ids"].split(",")]

        workers = min(args.get("max_workers", 4) or 4, len(ids))

        # Fetch all challenges once
        all_challenges = client.get_challenges()
        challenge_map = {c.id: c for c in all_challenges}

        results = {}
        futures = {}

        with ProcessPoolExecutor(max_workers=workers) as pool:
            for cid in ids:
                target = challenge_map.get(cid)
                if not target:
                    results[cid] = {"status": "error", "message": f"Not found: {cid}"}
                    continue

                enriched = client.enrich_challenge(target)

                safe_name = "".join(
                    c if c.isalnum() or c in "-_" else "_" for c in enriched.name
                )
                challenge_dir = WORKDIR / f"{safe_name}_{enriched.id}"
                challenge_dir.mkdir(parents=True, exist_ok=True)

                if enriched.files:
                    client.download_challenge_files(enriched, challenge_dir)

                challenge_info = {
                    "name": enriched.name,
                    "category": enriched.category,
                    "points": enriched.points,
                    "description": enriched.description,
                    "hints": enriched.hints,
                    "connection_info": enriched.connection_info,
                }
                (challenge_dir / "challenge.json").write_text(
                    json.dumps(challenge_info, indent=2)
                )

                future = pool.submit(
                    solve_in_process,
                    json.dumps(challenge_info),
                    str(challenge_dir),
                    model,
                    max_turns,
                )
                futures[future] = (cid, enriched)

            for future in as_completed(futures):
                cid, enriched = futures[future]
                try:
                    flag = future.result()
                except Exception as e:
                    flag = None
                    log.error("Solver error for %s: %s", enriched.name, e)

                _save_result(
                    enriched.name, enriched.category, enriched.points, flag
                )

                if flag:
                    results[cid] = {
                        "status": "solved",
                        "name": enriched.name,
                        "flag": flag,
                    }
                else:
                    results[cid] = {
                        "status": "failed",
                        "name": enriched.name,
                        "flag": None,
                    }

        solved = sum(1 for r in results.values() if r.get("status") == "solved")
        failed = sum(1 for r in results.values() if r.get("status") == "failed")

        return {
            "content": [
                {
                    "type": "text",
                    "text": (
                        f"Parallel solve complete: {solved} solved, {failed} failed\n\n"
                        f"{json.dumps(results, indent=2)}"
                    ),
                }
            ]
        }

    # ──────────────────── progress tools ────────────────────

    @tool(
        "get_progress",
        "Get a summary of all solve attempts so far. "
        "Returns stats (total solved, failed, points earned) and recent results.",
        {},
    )
    async def get_progress(args):
        results_file = LOGDIR / "results.jsonl"
        if not results_file.exists():
            return {
                "content": [{"type": "text", "text": "No results yet."}]
            }

        records = []
        for line in results_file.read_text().strip().split("\n"):
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

        solved = [r for r in records if r.get("solved")]
        failed = [r for r in records if not r.get("solved")]
        total_points = sum(r.get("points", 0) for r in solved)

        summary = {
            "total_attempts": len(records),
            "solved": len(solved),
            "failed": len(failed),
            "total_points_earned": total_points,
            "solved_challenges": [
                {"name": r["challenge"], "points": r["points"], "flag": r["flag"]}
                for r in solved
            ],
            "failed_challenges": [
                {"name": r["challenge"], "points": r["points"]}
                for r in failed
            ],
        }

        return {
            "content": [
                {"type": "text", "text": json.dumps(summary, indent=2)}
            ]
        }

    # ──────────────────── helper ────────────────────

    def _save_result(name: str, category: str, points: int, flag: str | None):
        LOGDIR.mkdir(parents=True, exist_ok=True)
        results_file = LOGDIR / "results.jsonl"
        record = {
            "timestamp": datetime.now().isoformat(),
            "challenge": name,
            "category": category,
            "points": points,
            "flag": flag,
            "solved": flag is not None,
        }
        with open(results_file, "a") as f:
            f.write(json.dumps(record) + "\n")

    # ──────────────────── build server ────────────────────

    server = create_sdk_mcp_server(
        name="ctf",
        version="1.0.0",
        tools=[
            list_challenges,
            get_challenge_details,
            submit_flag,
            solve_challenge,
            solve_challenges_parallel,
            get_progress,
        ],
    )

    return server
