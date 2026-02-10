# PicoCTF Autonomous Solver Agent

A fully autonomous, Dockerized agent that logs into PicoCTF, scrapes challenges, solves them using Claude Code, and submits flags — all hands-off.

Powered by the [Claude Agent SDK](https://github.com/anthropics/claude-agent-sdk-python) — Claude Code handles all reasoning, code generation, and execution natively.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                 Docker Container                 │
│                                                  │
│  orchestrator.py  → Strategic agent manager      │
│  agent.py         → Direct solve mode            │
│    ├── picoctf_client.py  → Login, scrape, submit│
│    └── solver.py          → Claude Code SDK agent│
│                                                  │
│  Claude Code CLI (bundled with SDK)              │
│    └── Bash, Read, Write, Glob, Grep tools       │
│                                                  │
│  Pre-installed: pwntools, pycryptodome, binwalk, │
│  nmap, netcat, Pillow, numpy, sympy, etc.        │
└─────────────────────────────────────────────────┘
```

## Prerequisites

You need three things: **Git**, **Docker**, and a **Claude Code subscription**.

### macOS (with Colima)

```bash
# Install Homebrew if you don't have it
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Git, Docker CLI, Docker Compose, and Colima
brew install git docker docker-compose colima

# Start Colima (Docker runtime)
colima start

# Verify Docker is working
docker info
```

### macOS (with Docker Desktop)

```bash
# Install Docker Desktop from https://www.docker.com/products/docker-desktop/
# Or via Homebrew:
brew install --cask docker

# Open Docker Desktop and wait for it to start
# Verify:
docker info
```

### Linux (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install -y git docker.io docker-compose-plugin
sudo systemctl start docker
sudo usermod -aG docker $USER
# Log out and back in, then verify:
docker info
```

### Install Claude Code CLI

You need the Claude Code CLI to generate an OAuth token. Install it with npm (comes with Node.js):

```bash
# Install Node.js if needed (https://nodejs.org or via your package manager)
brew install node        # macOS
# sudo apt install nodejs npm  # Linux

# Install Claude Code CLI
npm install -g @anthropic-ai/claude-code
```

## Setup

### 1. Clone the repo

```bash
git clone git@github.com:fantaize/pctf.git
cd pctf
```

### 2. Create your `.env` file

```bash
cp .env.example .env
```

### 3. Generate a Claude Code OAuth token

```bash
claude setup-token
```

This opens a browser to authenticate with your Anthropic account and prints a token starting with `sk-ant-oat01-...`.

### 4. Fill in your `.env`

Open `.env` in your editor and set:

```
CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-...your-token-here...
PICOCTF_USERNAME=your_picoctf_username
PICOCTF_PASSWORD=your_picoctf_password
```

You need a [picoCTF](https://play.picoctf.org) account — sign up for free if you don't have one.

### 5. Build the Docker image

```bash
docker-compose build
```

This takes a few minutes the first time (installs Python, Node.js, CTF tools).

## Usage

```bash
# Orchestrator mode — autonomous strategist that manages solver sub-agents
docker-compose run orchestrator

# Direct mode — solve all unsolved challenges (easiest first)
docker-compose run ctf-agent

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

# Parallel solving (4 challenges at once)
docker-compose run ctf-agent --workers 4
```

## How It Works

### Solve Loop (per challenge)

1. **Download** — Fetches challenge files to a local working directory
2. **Prompt** — Builds a structured prompt with description, hints, files, and connection info
3. **Claude Code** — The Claude Agent SDK spawns a Claude Code session with Bash, Read, Write, Glob, and Grep tools. Claude autonomously reasons, writes scripts, executes them, reads output, and iterates (up to 30 turns)
4. **Extract** — Regex scans all Claude Code output for `picoCTF{...}` flags
5. **Submit** — POSTs the flag to picoCTF and logs the result
6. **Retry** — If no flag found, retries with fresh context (up to 3 attempts)

### Orchestrator vs Direct Mode

- **Orchestrator** (`orchestrator.py`) — A meta-agent that strategically picks challenges, spawns solver sub-agents, learns from failures, retries with hints, and maximizes points. Best for unattended runs.
- **Direct** (`agent.py`) — Sequentially solves challenges matching your filters. Simpler, gives you more control via CLI flags.

### Platform Client

The picoCTF client authenticates via django-allauth and uses the REST API for challenges and submissions.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `CLAUDE_CODE_OAUTH_TOKEN` | (required) | OAuth token from `claude setup-token` |
| `PICOCTF_USERNAME` | (required) | PicoCTF login |
| `PICOCTF_PASSWORD` | (required) | PicoCTF password |
| `PICOCTF_URL` | `https://play.picoctf.org` | Platform URL |
| `MODEL` | `claude-opus-4-6` | Claude model to use |
| `MAX_ATTEMPTS_PER_CHALLENGE` | `3` | Retries per challenge |
| `CATEGORIES` | (all) | Comma-separated filter |
| `MAX_POINTS` | `500` | Skip harder challenges |
| `DRY_RUN` | `false` | Don't submit flags |
| `WORKERS` | `1` | Parallel solvers (direct mode) |
| `MAX_TURNS` | `200` | Orchestrator turn budget |
| `MAX_TURNS_SOLVER` | `30` | Solver turn budget per challenge |
| `LOG_LEVEL` | `INFO` | Logging verbosity |

## Output

```
./workdir/           # Per-challenge working directories
  Challenge_Name_123/
    challenge.json   # Challenge metadata
    writeup.md       # Step-by-step solution writeup
    (downloaded files + any scripts Claude creates)

./logs/
  agent_YYYYMMDD_HHMMSS.log   # Full session log
  results.jsonl                # Structured results (one JSON per line)
```

## Tips

- **Start with `--max-points 100`** to validate the setup on easy challenges first
- **Check `./logs/results.jsonl`** for a machine-readable summary
- **The platform API changes** — if login fails, you may need to update `picoctf_client.py`
- **For web challenges with remote services**, `network_mode: host` is set in docker-compose.yml
- **To use a different model**, set `MODEL=claude-sonnet-4-5-20250929` in `.env`

## Limitations

- PicoCTF's API is not officially documented and may change between competition years
- Some challenges require GUI interaction (browser-based) which this agent can't do
- Very hard pwn/rev challenges may exceed Claude's iteration budget
- Rate limits on both your Claude subscription and picoCTF may apply
