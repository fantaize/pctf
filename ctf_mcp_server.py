#!/usr/bin/env python3
"""
Standalone stdio MCP server for the CTF orchestrator.

Communicates via JSON-RPC over stdin/stdout. This avoids the known
CLIConnectionError race condition in the Python SDK's in-process MCP
server implementation.

The Claude Code CLI spawns this as a subprocess and manages the lifecycle.

Environment variables (set by the orchestrator before spawning):
    PICOCTF_USERNAME, PICOCTF_PASSWORD, PICOCTF_URL — picoCTF credentials
    MODEL — Claude model to use for solvers
    MAX_TURNS_SOLVER — max turns per solver agent
"""

import asyncio
import json
import logging
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from picoctf_client import PicoCTFClient, Challenge
from solver import solve_in_process

log = logging.getLogger(__name__)

# ── Paths ──
WORKDIR = Path(os.environ.get("CTF_WORKDIR", "/app/workdir"))
LOGDIR = Path(os.environ.get("CTF_LOGDIR", "/app/logs"))


# ──────────────────────────────────────────────────────────────────
# picoCTF client singleton (lazily initialized)
# ──────────────────────────────────────────────────────────────────

_client: PicoCTFClient | None = None


def _get_client() -> PicoCTFClient:
    global _client
    if _client is None:
        username = os.environ.get("PICOCTF_USERNAME", "")
        password = os.environ.get("PICOCTF_PASSWORD", "")
        base_url = os.environ.get("PICOCTF_URL", "https://play.picoctf.org")
        _client = PicoCTFClient(base_url, username, password)
        if not _client.login():
            log.error("Failed to log in to picoCTF in MCP server")
            # Continue anyway — some tools might still work
        else:
            log.info("MCP server: logged in to picoCTF as %s", username)
    return _client


def _get_model() -> str:
    return os.environ.get("MODEL", "claude-opus-4-6")


def _get_max_turns() -> int:
    return int(os.environ.get("MAX_TURNS_SOLVER", "30"))


# ──────────────────────────────────────────────────────────────────
# Tool implementations
# ──────────────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "list_challenges",
        "description": (
            "List picoCTF challenges. Returns JSON array with id, name, category, "
            "points, solved status. Use filters to narrow results. "
            "Results are sorted by points (easiest first)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "category": {"type": "string", "description": "Filter by category name"},
                "max_points": {"type": "integer", "description": "Maximum points to include"},
                "unsolved_only": {"type": "boolean", "description": "Only unsolved challenges (default true)"},
            },
        },
    },
    {
        "name": "get_challenge_details",
        "description": (
            "Get full details for a challenge: description, hints, files, connection info. "
            "Also starts on-demand instances if needed."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "challenge_id": {"type": "string", "description": "The challenge ID"},
            },
            "required": ["challenge_id"],
        },
    },
    {
        "name": "submit_flag",
        "description": "Submit a flag for a challenge. Returns whether it was accepted.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "challenge_id": {"type": "string", "description": "The challenge ID"},
                "flag": {"type": "string", "description": "The flag string to submit"},
            },
            "required": ["challenge_id", "flag"],
        },
    },
    {
        "name": "solve_challenge",
        "description": (
            "Spawn a Claude Code solver agent to attempt a single challenge. "
            "Downloads files, builds a prompt, and runs the solver in a subprocess. "
            "Returns the flag if found, or a failure message. "
            "Use extra_hints to provide additional strategy tips for the solver."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "challenge_id": {"type": "string", "description": "The challenge ID"},
                "extra_hints": {"type": "string", "description": "Additional strategy hints for the solver"},
            },
            "required": ["challenge_id"],
        },
    },
    {
        "name": "solve_challenges_parallel",
        "description": (
            "Spawn multiple solver agents in parallel. "
            "Provide a list of challenge IDs (JSON array string or comma-separated) "
            "and the number of workers. "
            "Returns a JSON object mapping challenge IDs to their results."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "challenge_ids": {
                    "type": "string",
                    "description": "JSON array of challenge IDs, or comma-separated IDs",
                },
                "max_workers": {"type": "integer", "description": "Max parallel workers (default 4)"},
            },
            "required": ["challenge_ids"],
        },
    },
    {
        "name": "get_progress",
        "description": (
            "Get a summary of all solve attempts so far. "
            "Returns stats (total solved, failed, points earned) and recent results."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


def _handle_list_challenges(args: dict) -> dict:
    client = _get_client()
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

    return {"content": [{"type": "text", "text": f"{summary}\n\n{json.dumps(result, indent=2)}"}]}


def _handle_get_challenge_details(args: dict) -> dict:
    client = _get_client()
    cid = args["challenge_id"]

    all_challenges = client.get_challenges()
    target = None
    for c in all_challenges:
        if c.id == cid:
            target = c
            break

    if not target:
        return {
            "content": [{"type": "text", "text": f"Challenge {cid} not found"}],
            "isError": True,
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

    return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}


def _handle_submit_flag(args: dict) -> dict:
    client = _get_client()
    cid = args["challenge_id"]
    flag = args["flag"]

    ch = Challenge(id=cid, name="", category="", points=0, description="")
    accepted = client.submit_flag(ch, flag)
    status = "ACCEPTED" if accepted else "REJECTED"

    _save_result(ch.name or cid, "", 0, flag if accepted else None)

    return {"content": [{"type": "text", "text": f"Flag submission for challenge {cid}: {status}"}]}


def _handle_solve_challenge(args: dict) -> dict:
    client = _get_client()
    cid = args["challenge_id"]
    extra_hints = args.get("extra_hints", "")
    model = _get_model()
    max_turns = _get_max_turns()

    all_challenges = client.get_challenges()
    target = None
    for c in all_challenges:
        if c.id == cid:
            target = c
            break

    if not target:
        return {
            "content": [{"type": "text", "text": f"Challenge {cid} not found"}],
            "isError": True,
        }

    enriched = client.enrich_challenge(target)

    # Prepare workdir
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in enriched.name)
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

    (challenge_dir / "challenge.json").write_text(json.dumps(challenge_info, indent=2))

    challenge_json = json.dumps(challenge_info)

    # Run solver in a separate process
    try:
        flag = solve_in_process(challenge_json, str(challenge_dir), model, max_turns)
    except Exception as e:
        flag = None
        log.error("Solver error for %s: %s", enriched.name, e)

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


def _handle_solve_challenges_parallel(args: dict) -> dict:
    client = _get_client()
    model = _get_model()
    max_turns = _get_max_turns()

    # Parse challenge IDs
    try:
        ids = json.loads(args["challenge_ids"])
    except (json.JSONDecodeError, TypeError):
        ids = [x.strip() for x in args["challenge_ids"].split(",")]

    workers = min(args.get("max_workers", 4) or 4, len(ids))

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

            _save_result(enriched.name, enriched.category, enriched.points, flag)

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


def _handle_get_progress(args: dict) -> dict:
    results_file = LOGDIR / "results.jsonl"
    if not results_file.exists():
        return {"content": [{"type": "text", "text": "No results yet."}]}

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

    return {"content": [{"type": "text", "text": json.dumps(summary, indent=2)}]}


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


# Tool dispatch table
TOOL_HANDLERS = {
    "list_challenges": _handle_list_challenges,
    "get_challenge_details": _handle_get_challenge_details,
    "submit_flag": _handle_submit_flag,
    "solve_challenge": _handle_solve_challenge,
    "solve_challenges_parallel": _handle_solve_challenges_parallel,
    "get_progress": _handle_get_progress,
}


# ──────────────────────────────────────────────────────────────────
# JSON-RPC stdio MCP server loop
# ──────────────────────────────────────────────────────────────────

SERVER_INFO = {
    "name": "ctf",
    "version": "1.0.0",
}

PROTOCOL_VERSION = "2024-11-05"


def _make_response(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _make_error(req_id, code, message):
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def handle_request(request: dict) -> dict | None:
    """Handle a single JSON-RPC request and return a response (or None for notifications)."""
    req_id = request.get("id")
    method = request.get("method", "")
    params = request.get("params", {})

    if method == "initialize":
        return _make_response(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "serverInfo": SERVER_INFO,
            "capabilities": {
                "tools": {},
            },
        })

    elif method == "notifications/initialized":
        # This is a notification, no response needed
        return None

    elif method == "tools/list":
        return _make_response(req_id, {
            "tools": TOOLS,
        })

    elif method == "tools/call":
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})

        handler = TOOL_HANDLERS.get(tool_name)
        if not handler:
            return _make_response(req_id, {
                "content": [{"type": "text", "text": f"Unknown tool: {tool_name}"}],
                "isError": True,
            })

        try:
            result = handler(tool_args)
            return _make_response(req_id, result)
        except Exception as e:
            log.error("Tool %s error: %s", tool_name, e, exc_info=True)
            return _make_response(req_id, {
                "content": [{"type": "text", "text": f"Error in {tool_name}: {str(e)}"}],
                "isError": True,
            })

    elif method == "ping":
        return _make_response(req_id, {})

    elif method.startswith("notifications/"):
        # All notifications: no response
        return None

    else:
        return _make_error(req_id, -32601, f"Method not found: {method}")


def main():
    """Run the stdio MCP server loop."""
    # Setup logging to stderr (stdout is for JSON-RPC)
    logging.basicConfig(
        level=logging.INFO,
        format="[MCP] %(levelname)s %(message)s",
        stream=sys.stderr,
    )

    log.info("CTF MCP server starting (stdio mode)")

    # Read JSON-RPC messages from stdin, write responses to stdout
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except json.JSONDecodeError as e:
            log.error("Invalid JSON: %s", e)
            error_resp = _make_error(None, -32700, f"Parse error: {str(e)}")
            sys.stdout.write(json.dumps(error_resp) + "\n")
            sys.stdout.flush()
            continue

        response = handle_request(request)

        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()

    log.info("CTF MCP server shutting down")


if __name__ == "__main__":
    main()
