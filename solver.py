"""
Claude Code SDK-powered CTF solver.

Sends challenge context to Claude Code, which autonomously reasons,
writes code, executes it via Bash, and iterates until it finds a flag.
"""

import asyncio
import json
import logging
import re
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
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text

log = logging.getLogger(__name__)
console = Console()

SYSTEM_PROMPT = """\
You are an elite CTF player. Your goal: find the flag for the given challenge.

## Approach
1. **Analyze first**: Read the description, hints, and any provided files carefully.
2. **Identify the category**: crypto, rev, pwn, forensics, web, misc, general skills.
3. **Hypothesize**: State what you think the vulnerability or trick is.
4. **Solve**: Write and execute code or shell commands to extract the flag.
5. **Iterate**: If your approach fails, try a different angle. Don't repeat failed attempts.

## Rules
- The working directory contains all challenge files already downloaded.
- You have full access to Linux tools: strings, xxd, binwalk, gdb, python3, gcc, etc.
- Python libraries available: pwntools, pycryptodome, z3-solver, Pillow, angr, sympy, gmpy2, numpy
- Be efficient. Start with simple approaches (strings, file inspection) before complex ones.
- For remote challenges, connection info is provided — write pwntools scripts to interact.
- Never guess flags. Only submit what you can verify.
- When you find the flag, output it clearly as: FLAG: picoCTF{...}

## Writeup Requirement
When you find the flag, you MUST write a detailed writeup to `writeup.md` in the working directory BEFORE reporting the flag. The writeup must follow this format:

```markdown
# <Challenge Name>

**Category:** <category>
**Points:** <points>
**Flag:** `picoCTF{...}`

## Description
<paste the challenge description>

## Solution

### Analysis
<what you observed about the challenge, initial thoughts>

### Approach
<step-by-step explanation of how you solved it>

### Key Commands / Code
```
<the exact commands or scripts you used>
```

### Flag
```
picoCTF{...}
```
```

Write the writeup in a way that a beginner could follow and learn from it. Include all the commands and code you used. This is mandatory — always write the writeup before outputting the flag.
"""

# Regex for common CTF flag formats
FLAG_PATTERNS = [
    r"picoCTF\{[^}]+\}",
    r"pico[Cc][Tt][Ff]\{[^}]+\}",
    r"FLAG:\s*(\S+)",
]


def _extract_flag(text: str) -> str | None:
    """Try to extract a flag from text."""
    for pattern in FLAG_PATTERNS:
        match = re.search(pattern, text)
        if match:
            flag = match.group(1) if match.lastindex else match.group(0)
            if "picoCTF{" in flag or "picoctf{" in flag.lower():
                return flag
            if flag.startswith("picoCTF{"):
                return flag
    return None


def _build_challenge_prompt(challenge_info: dict, workdir: Path) -> str:
    """Build the initial prompt describing the challenge."""
    parts = [
        f"# Challenge: {challenge_info['name']}",
        f"**Category:** {challenge_info['category']}",
        f"**Points:** {challenge_info['points']}",
        f"\n## Description\n{challenge_info['description']}",
    ]

    if challenge_info.get("hints"):
        parts.append("\n## Hints")
        for i, hint in enumerate(challenge_info["hints"], 1):
            parts.append(f"{i}. {hint}")

    if challenge_info.get("connection_info"):
        parts.append(f"\n## Connection Info\n`{challenge_info['connection_info']}`")

    # List downloaded files
    files = [f for f in workdir.iterdir() if f.name != "challenge.json"]
    if files:
        parts.append("\n## Files in working directory")
        for f in sorted(files):
            size = f.stat().st_size
            parts.append(f"- `{f.name}` ({size:,} bytes)")

    parts.append(
        "\n## Instructions\n"
        "Analyze the challenge and find the flag. Use Bash to run commands and "
        "execute solution scripts. The flag format is picoCTF{...}\n"
        "Start by inspecting the provided files with `file`, `strings`, `xxd`, etc."
    )

    return "\n".join(parts)


async def _solve_async(prompt: str, workdir: str, model: str, max_turns: int) -> str | None:
    """Run the Claude Code query and scan for flags. Must run in its own event loop."""
    options = ClaudeAgentOptions(
        system_prompt=SYSTEM_PROMPT,
        allowed_tools=["Bash", "Read", "Write", "Glob", "Grep"],
        permission_mode="bypassPermissions",
        max_turns=max_turns,
        cwd=workdir,
        model=model,
    )

    all_text = []
    turn = 0

    async for message in query(prompt=prompt, options=options):
        if isinstance(message, AssistantMessage):
            turn += 1
            console.print(f"\n[bold blue]── Turn {turn} ──[/bold blue]")

            for block in message.content:
                if isinstance(block, TextBlock):
                    console.print(Panel(
                        block.text,
                        title="[bold cyan]Claude[/bold cyan]",
                        border_style="cyan",
                        padding=(0, 1),
                    ))
                    flag = _extract_flag(block.text)
                    if flag:
                        console.print(f"[bold green]FLAG FOUND: {flag}[/bold green]")
                        return flag
                    all_text.append(block.text)

                elif isinstance(block, ThinkingBlock):
                    console.print(Panel(
                        Text(block.thinking, style="dim"),
                        title="[bold magenta]Thinking[/bold magenta]",
                        border_style="magenta",
                        padding=(0, 1),
                    ))

                elif isinstance(block, ToolUseBlock):
                    tool_input = block.input
                    tool_name = block.name
                    if tool_name == "Bash" and "command" in tool_input:
                        content = Syntax(
                            tool_input["command"],
                            "bash",
                            theme="monokai",
                            word_wrap=True,
                        )
                    elif tool_name in ("Read", "Write", "Glob", "Grep"):
                        content = Text(str(tool_input), style="yellow")
                    else:
                        content = Text(str(tool_input), style="yellow")
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
                    display = result_content[:3000]
                    if len(result_content) > 3000:
                        display += f"\n... ({len(result_content) - 3000} more chars)"
                    console.print(Panel(
                        Text(display),
                        title=f"[bold {style}]{label}[/bold {style}]",
                        border_style=style,
                        padding=(0, 1),
                    ))
                    flag = _extract_flag(result_content)
                    if flag:
                        console.print(f"[bold green]FLAG FOUND: {flag}[/bold green]")
                        return flag
                    all_text.append(result_content)

        elif isinstance(message, UserMessage):
            pass

        elif isinstance(message, ResultMessage):
            console.print(f"\n[bold]Session complete[/bold]  "
                          f"turns={message.num_turns}  "
                          f"duration={message.duration_ms / 1000:.1f}s")
            if message.total_cost_usd is not None:
                console.print(f"  cost=${message.total_cost_usd:.4f}")

    # Final pass
    combined = "\n".join(all_text)
    flag = _extract_flag(combined)
    if flag:
        console.print(f"[bold green]FLAG FOUND (final scan): {flag}[/bold green]")
        return flag

    console.print("[bold red]Claude Code session ended without finding a flag[/bold red]")
    return None


def solve_in_process(challenge_json: str, workdir: str, model: str, max_turns: int) -> str | None:
    """
    Entry point for subprocess workers.
    Runs its own asyncio event loop — fully isolated from the parent.
    Accepts serialized challenge info (JSON string) so it's picklable.
    """
    challenge_info = json.loads(challenge_json)
    prompt = _build_challenge_prompt(challenge_info, Path(workdir))
    return asyncio.run(_solve_async(prompt, workdir, model, max_turns))
