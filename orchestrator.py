#!/usr/bin/env python3
"""
AI Orchestrator for PicoCTF Autonomous Solver.

A Claude Code agent that strategically manages solver sub-agents.
It decides which challenges to attempt, in what order, learns from
failures, and adapts its strategy over time.

Runs fully autonomously until the turn budget is exhausted.

Usage:
    docker-compose up                     # orchestrator mode (default)
    docker-compose run ctf-agent          # same
    docker-compose run ctf-agent python3 agent.py --list  # fallback to direct mode
"""

import asyncio
import json
import logging
import os
import sys
from pathlib import Path

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    TextBlock,
    ToolResultBlock,
    ToolUseBlock,
    ThinkingBlock,
    UserMessage,
    query,
)
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text

LOGDIR = Path("/app/logs")
console = Console()


ORCHESTRATOR_PROMPT = """\
You are an elite CTF competition strategist managing an autonomous team of AI solver agents on picoCTF.

## Your Tools

You have MCP tools for:
- **list_challenges**: List challenges filtered by category, max_points, unsolved_only
- **get_challenge_details**: Get full description, hints, files for a specific challenge
- **solve_challenge**: Spawn a solver agent for a single challenge (can include extra strategy hints)
- **solve_challenges_parallel**: Spawn multiple solver agents in parallel
- **submit_flag**: Submit a discovered flag for a challenge
- **get_progress**: Check your overall progress (solved count, points, failed challenges)

You also have Bash, Read, Write, Glob, and Grep for any direct investigation.

## Strategy

1. **Start**: Call list_challenges to see all unsolved challenges. Analyze the landscape.

2. **Prioritize**: Pick the easiest wins first:
   - General Skills (usually simple string/encoding puzzles) → lowest points first
   - Cryptography (common ciphers like Caesar, RSA with small keys)
   - Forensics (file analysis, steganography)
   - Reverse Engineering (only easy ones)
   - Web Exploitation and Binary Exploitation last (they often need live servers)

3. **Batch solving**: Use solve_challenges_parallel for groups of similar-difficulty challenges.
   Start with 3-4 workers. Don't overload — quality over quantity.

4. **After each batch**:
   - Check get_progress to see your stats
   - For SOLVED challenges: call submit_flag with the discovered flag
   - For FAILED challenges: look at the solver's workdir (use Read/Bash) to understand why
   - Decide: retry with extra_hints, or skip and move on

5. **Smart retries**: When retrying a failed challenge, provide extra_hints like:
   - "The file is a PNG with hidden data in the EXIF metadata"
   - "This is a Caesar cipher with shift 13 (ROT13)"
   - "Use binwalk to extract embedded files"
   Base these on what you learned from the previous attempt's workdir.

6. **Know when to stop**: Skip challenges that:
   - Require live server interactions you can't reach
   - Have very low solve rates (< 100 solvers) and high points (> 300)
   - You've already failed 2+ times

7. **Report**: After each major phase, summarize your progress.

## Important Notes

- The solver agents run in separate processes. They have full Linux tool access.
- Challenge files are downloaded to /app/workdir/<challenge_name>_<id>/
- Each solver gets up to 30 turns to find the flag.
- Flags look like: picoCTF{...}
- After solve_challenge returns a flag, you MUST call submit_flag to get credit.
- Be strategic. There are 440+ challenges — focus on maximizing points per time spent.
- Solvers write a `writeup.md` in their workdir for every solved challenge. These writeups
  explain the approach step-by-step. When a challenge FAILS, read the workdir contents to
  understand what the solver tried, then retry with better extra_hints.
- All writeups are saved to /app/workdir/<challenge_name>_<id>/writeup.md and persist
  on the host via the volume mount, so you're also building a library of CTF solutions.
"""


def setup_logging(level: str = "INFO"):
    LOGDIR.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(message)s",
        datefmt="%H:%M:%S",
        handlers=[
            RichHandler(console=console, rich_tracebacks=True, show_path=False),
        ],
    )
    return logging.getLogger(__name__)


def print_message(message, turn_counter: list[int]):
    """Pretty-print a message from the orchestrator."""
    if isinstance(message, AssistantMessage):
        turn_counter[0] += 1
        console.print(f"\n[bold blue]── Orchestrator Turn {turn_counter[0]} ──[/bold blue]")

        for block in message.content:
            if isinstance(block, TextBlock):
                console.print(Panel(
                    block.text,
                    title="[bold magenta]Orchestrator[/bold magenta]",
                    border_style="magenta",
                    padding=(0, 1),
                ))

            elif isinstance(block, ThinkingBlock):
                console.print(Panel(
                    Text(block.thinking, style="dim"),
                    title="[bold blue]Thinking[/bold blue]",
                    border_style="blue",
                    padding=(0, 1),
                ))

            elif isinstance(block, ToolUseBlock):
                tool_name = block.name
                tool_input = block.input
                if tool_name == "Bash" and "command" in tool_input:
                    content = Syntax(
                        tool_input["command"], "bash",
                        theme="monokai", word_wrap=True,
                    )
                else:
                    content = Text(
                        json.dumps(tool_input, indent=2) if isinstance(tool_input, dict) else str(tool_input),
                        style="yellow",
                    )
                console.print(Panel(
                    content,
                    title=f"[bold yellow]Tool: {tool_name}[/bold yellow]",
                    border_style="yellow",
                    padding=(0, 1),
                ))

            elif isinstance(block, ToolResultBlock):
                result_content = ""
                if isinstance(block.content, str):
                    result_content = block.content
                elif isinstance(block.content, list):
                    parts = []
                    for item in block.content:
                        if isinstance(item, dict) and "text" in item:
                            parts.append(item["text"])
                        else:
                            parts.append(str(item))
                    result_content = "\n".join(parts)
                else:
                    result_content = str(block.content or "")

                style = "red" if block.is_error else "green"
                label = "Error" if block.is_error else "Result"
                display = result_content[:5000]
                if len(result_content) > 5000:
                    display += f"\n... ({len(result_content) - 5000} more chars)"
                console.print(Panel(
                    Text(display),
                    title=f"[bold {style}]{label}[/bold {style}]",
                    border_style=style,
                    padding=(0, 1),
                ))

    elif isinstance(message, UserMessage):
        pass



async def run_orchestrator():
    """Launch the orchestrator Claude Code agent autonomously."""
    log_level = os.environ.get("LOG_LEVEL", "INFO")
    log = setup_logging(log_level)

    username = os.environ.get("PICOCTF_USERNAME")
    password = os.environ.get("PICOCTF_PASSWORD")
    base_url = os.environ.get("PICOCTF_URL", "https://play.picoctf.org")
    model = os.environ.get("MODEL", "claude-opus-4-6")
    max_turns_solver = int(os.environ.get("MAX_TURNS_SOLVER", "30"))
    max_turns_total = int(os.environ.get("MAX_TURNS", "200"))

    if not os.environ.get("CLAUDE_CODE_OAUTH_TOKEN"):
        console.print("[red]ERROR: CLAUDE_CODE_OAUTH_TOKEN not set[/red]")
        sys.exit(1)
    if not username or not password:
        console.print("[red]ERROR: PICOCTF_USERNAME / PICOCTF_PASSWORD not set[/red]")
        sys.exit(1)

    # ── Build MCP server config (external stdio subprocess) ──
    ctf_server_config = {
        "command": "python3",
        "args": ["/app/ctf_mcp_server.py"],
        "env": {
            "PICOCTF_USERNAME": username,
            "PICOCTF_PASSWORD": password,
            "PICOCTF_URL": base_url,
            "MODEL": model,
            "MAX_TURNS_SOLVER": str(max_turns_solver),
            "CLAUDE_CODE_OAUTH_TOKEN": os.environ.get("CLAUDE_CODE_OAUTH_TOKEN", ""),
            "CTF_WORKDIR": "/app/workdir",
            "CTF_LOGDIR": "/app/logs",
        },
    }

    # ── Print banner ──
    console.print(f"\n[bold magenta]{'═' * 60}[/bold magenta]")
    console.print("[bold magenta]  CTF ORCHESTRATOR AGENT (Autonomous)  [/bold magenta]")
    console.print(f"[bold magenta]{'═' * 60}[/bold magenta]")
    console.print(f"  Model: {model}")
    console.print(f"  Max turns: {max_turns_total}")
    console.print(f"  Solver turns: {max_turns_solver}")
    console.print(f"  MCP server: ctf_mcp_server.py (stdio)")
    console.print(f"[bold magenta]{'═' * 60}[/bold magenta]\n")

    # ── Run autonomously ──
    total_cost = 0.0
    turn_counter = [0]  # mutable ref for print_message

    prompt = (
        "Begin the CTF challenge. List all unsolved challenges, analyze them, "
        "and start solving the easiest ones first. Use parallel solving when appropriate. "
        "Submit flags as you find them. Keep going until you've attempted all feasible challenges."
    )

    options = ClaudeAgentOptions(
        system_prompt=ORCHESTRATOR_PROMPT,
        mcp_servers={"ctf": ctf_server_config},
        allowed_tools=[
            "Bash", "Read", "Write", "Glob", "Grep",
            "mcp__ctf__list_challenges",
            "mcp__ctf__get_challenge_details",
            "mcp__ctf__submit_flag",
            "mcp__ctf__solve_challenge",
            "mcp__ctf__solve_challenges_parallel",
            "mcp__ctf__get_progress",
        ],
        permission_mode="bypassPermissions",
        max_turns=max_turns_total,
        model=model,
    )

    async for message in query(prompt=prompt, options=options):
        if isinstance(message, ResultMessage):
            if message.total_cost_usd:
                total_cost += message.total_cost_usd

            console.print(f"\n[dim]  Turns: {message.num_turns}/{max_turns_total}, "
                          f"cost: ${total_cost:.4f}[/dim]")

            if message.subtype == "success":
                console.print("[bold green]Orchestrator completed.[/bold green]")
            elif message.subtype == "error_max_turns":
                console.print("[yellow]Reached maximum turn budget.[/yellow]")
            else:
                console.print(f"[yellow]Session ended: {message.subtype}[/yellow]")
        else:
            print_message(message, turn_counter)

    # ── Final summary with progress ──
    console.print(f"\n[bold magenta]{'═' * 60}[/bold magenta]")
    console.print("[bold magenta]  SESSION COMPLETE  [/bold magenta]")
    console.print(f"  Total cost: ${total_cost:.4f}")
    console.print(f"[bold magenta]{'═' * 60}[/bold magenta]")

    # Show solve progress from results log
    results_file = LOGDIR / "results.jsonl"
    if results_file.exists():
        import json as _json
        records = []
        for line in results_file.read_text().strip().split("\n"):
            if line:
                try:
                    records.append(_json.loads(line))
                except _json.JSONDecodeError:
                    pass
        solved = [r for r in records if r.get("solved")]
        failed = [r for r in records if not r.get("solved")]
        total_points = sum(r.get("points", 0) for r in solved)
        console.print(f"\n[bold]Challenges solved: {len(solved)}[/bold]")
        console.print(f"[bold]Challenges failed: {len(failed)}[/bold]")
        console.print(f"[bold]Points earned:     {total_points}[/bold]")


def main():
    asyncio.run(run_orchestrator())


if __name__ == "__main__":
    main()
