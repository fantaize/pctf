# 🤖 PicoCTF Autonomous Solver Agent

A fully autonomous, Dockerized agent that logs into PicoCTF, scrapes challenges, solves them using Claude Code, and submits flags — all hands-off.

Powered by the [Claude Agent SDK](https://github.com/anthropics/claude-agent-sdk-python) — Claude Code handles all reasoning, code generation, and execution natively.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                 Docker Container                 │
│                                                  │
│  agent.py (Orchestrator)                         │
│    ├── picoctf_client.py  → Login, scrape, submit│
│    └── solver.py          → Claude Code SDK agent│
│                                                  │
│  Claude Code CLI (bundled with SDK)              │
│    └── Bash, Read, Write, Glob, Grep tools       │
│                                                  │
│  Pre-installed: pwntools, z3, angr, binwalk,     │
│  gdb, radare2, steghide, john, etc.              │
└─────────────────────────────────────────────────┘
```

## Quick Start

### 1. Clone & configure

```bash
cp .env.example .env
# Generate an OAuth token from your Claude Code subscription:
claude setup-token
# Edit .env:
#   CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-...
#   PICOCTF_USERNAME=your_user
#   PICOCTF_PASSWORD=your_pass
```

### 2. Build & run

```bash
# Solve all unsolved challenges (easiest first)
docker-compose up --build

# Solve only crypto challenges
docker-compose run ctf-agent --category crypto

# Solve a specific challenge
docker-compose run ctf-agent --challenge "Mod 26"

# List challenges without solving
docker-compose run ctf-agent --list

# Dry run (solve but don't submit flags)
docker-compose run ctf-agent --dry-run

# Only challenges worth ≤200 points
docker-compose run ctf-agent --max-points 200
```

## How It Works

### Solve Loop (per challenge)

1. **Download** — Fetches challenge files to a local working directory
2. **Prompt** — Builds a structured prompt with description, hints, files, and connection info
3. **Claude Code** — The Claude Agent SDK spawns a Claude Code session with Bash, Read, Write, Glob, and Grep tools. Claude autonomously reasons, writes scripts, executes them, reads output, and iterates (up to 30 turns)
4. **Extract** — Regex scans all Claude Code output for `picoCTF{...}` flags
5. **Submit** — POSTs the flag to picoCTF and logs the result
6. **Retry** — If no flag found, retries with fresh context (up to 3 attempts)

### Platform Client

The picoCTF client tries multiple strategies to interact with the platform:
- GraphQL API (`/api/graphql`)
- REST API (`/api/challenges`, `/api/v1/challenges`)
- HTML scraping (fallback)

It similarly tries multiple submission endpoints to maximize compatibility across picoCTF versions.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `CLAUDE_CODE_OAUTH_TOKEN` | (required) | OAuth token from `claude setup-token` (uses your subscription) |
| `PICOCTF_USERNAME` | (required) | PicoCTF login |
| `PICOCTF_PASSWORD` | (required) | PicoCTF password |
| `PICOCTF_URL` | `https://play.picoctf.org` | Platform URL |
| `MODEL` | `claude-opus-4-6` | Claude model to use |
| `MAX_ATTEMPTS_PER_CHALLENGE` | `3` | Retries per challenge |
| `CATEGORIES` | (all) | Comma-separated filter |
| `MAX_POINTS` | `500` | Skip harder challenges |
| `DRY_RUN` | `false` | Don't submit flags |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

## Output

```
./workdir/           # Per-challenge working directories
  Challenge_Name_123/
    challenge.json   # Challenge metadata
    (downloaded files + any scripts Claude Code creates)

./logs/
  agent_YYYYMMDD_HHMMSS.log   # Full session log
  results.jsonl                # Structured results (one JSON per line)
```

## Pre-installed Tools

### System
binwalk, foremost, steghide, exiftool, john, hashcat, gdb, radare2, nmap, netcat, socat, strings, xxd, upx, qemu-user-static, tesseract-ocr

### Python
pwntools, pycryptodome, z3-solver, Pillow, angr, capstone, keystone, unicorn, ropper, sympy, gmpy2, numpy, requests, beautifulsoup4, httpx

## Tips

- **Start with `--max-points 100`** to validate the setup on easy challenges first
- **Check `./logs/results.jsonl`** for a machine-readable summary
- **The platform API changes** — if login fails, you may need to update `picoctf_client.py` by inspecting the site with browser dev tools
- **For web challenges with remote services**, make sure `network_mode: host` is set in docker-compose.yml
- **To use Claude Opus for hard challenges**, set `MODEL=claude-opus-4-6` in `.env`

## Limitations

- PicoCTF's API is not officially documented and may change between competition years
- Some challenges require GUI interaction (browser-based) which this agent can't do
- Very hard pwn/rev challenges may exceed Claude's iteration budget
- Rate limits on both your Claude subscription and picoCTF may apply
