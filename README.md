# XeroDay's API Sniffer

API Sniffer is a GitHub-focused secret discovery toolkit for scanning public repositories and identifying exposed API keys, tokens, webhooks, and other sensitive credentials. It is part of the X3r0Day Framework and is built for security research, defensive analysis, and responsible disclosure.

The project is organized around discovery, scanning, and querying, with an AI-first launcher, a workflow orchestrator, shared routing/search utilities, and a live scanner dashboard.

---

## Configuration

- `export GROQ_API_KEY="gsk_xx"`: Required for AI workflow routing and AI search. If not set, the tools will prompt for it.
- `export GITHUB_TOKEN="github_pat_xx"` / `export GH_TOKEN="github_pat_xx"`: Optional. Increases GitHub API rate limits for metadata and archive requests.
- `AI_POLICY_PATH`: Optional. Overrides the default policy path (`config/ai_policy.json`).

**`config/ai_policy.json`**
- Defines the Groq API endpoint, model name, and temperature settings.
- Controls workflow routing rules and the AI query planner behavior.

**`data/signatures.json`**
- Contains all signature definitions (name + regex + tags).
- Heroku rules are tagged `heroku` and can be included with `--scan-heroku-keys`.

---

## How It Works

API Sniffer supports two operating modes:

1. **AI workflow orchestration** via `AIWorkflow.py`, where natural-language requests are routed into discovery, scanning, direct database querying, or chained workflows.
2. **Manual execution** via `main.py`, which exposes a control center for running each stage or the full pipeline.

The core pipeline is:

**Stage 1 - Discovery (`APISniffer.py`)**: Queries GitHub for newly created public repositories across a recent time window, deduplicates them against the live queue and prior scan history, and stores fresh targets in `recent_repos.json`.

**Stage 2 - Scanning (`APIScanner.py`)**: Pulls repositories from the queue, resolves the repo's default branch when needed, downloads repository archives, scans matching files, optionally scans recent commit patches, and writes results into `leaked_keys.json`, `clean_repos.json`, or `failed_repos.json`.

**Stage 3 - AI Search (`AISearch.py`)**: Queries the local findings database with natural language. The search runtime is shared with the AI workflow, so database questions like `show all the API keys` can be answered directly from the launcher flow.

### Project Flow

```text
main.py
├── Enter
│   └── src/AIWorkflow.py
│       ├── Query request -> src/shared/ai_search_runtime.py -> leaked_keys.json
│       ├── Discovery request -> src/APISniffer.py -> recent_repos.json
│       ├── Scanner request -> src/APIScanner.py -> leaked_keys.json / clean_repos.json / failed_repos.json
│       └── Mixed request -> orchestrated multi-step workflow
└── Manual
    └── Control Center
        ├── src/APISniffer.py
        ├── src/APIScanner.py
        ├── src/AISearch.py
        └── src/AIWorkflow.py
```

---

## Components

- **`APISniffer.py` (Discovery)**
  - Queries GitHub search for newly created public repos.
  - Uses a time-windowed, chunked search with adaptive splitting for high-volume windows.
  - Deduplicates against historical outputs and the live queue.
  - Supports proxy fallback via `live_proxies.txt` when direct requests fail or rate-limit.

- **`APIScanner.py` (Scanner)**
  - Pulls targets from `recent_repos.json` and scans repository archives.
  - Filters by file extension and filename to reduce noise.
  - Optionally scans recent commit history (patches) to catch secrets removed after commit.
  - Provides a live Rich-based dashboard with queue stats, thread status, and recent leaks.
  - Supports interactive repo injection during runtime (AI-assisted or regex-based).

- **`AISearch.py` + `shared/ai_search_runtime.py` (AI Query Engine)**
  - Uses Groq's OpenAI-compatible API to interpret natural-language queries.
  - Plans category/term filters, searches `leaked_keys.json`, and returns results.
  - Supports summary mode (counts and top categories) and full search results.

- **Shared Utilities (`src/shared/`)**
  - `ai_client.py`: Groq API calls and key handling (`GROQ_API_KEY`).
  - `ai_policy.py`: Loads policy from `config/ai_policy.json` and supports overrides.
  - `ai_search_runtime.py`: Query planning, filtering, and result rendering.
  - `api_signatures.py` + `signature_loader.py`: Data-driven signature loading from `data/signatures.json`.
  - `category_routing.py`: Maps user queries to signature categories.
  - `scanner_matcher.py`: Regex matching + normalization (e.g., Firebase URL expansion).
  - `scanner_targets.py`: Repo target extraction (regex + AI assist).
  - `scanner_dashboard.py`: Live scanner dashboard layout.

---

## Project Structure

```text
API Sniffer/
├── main.py                         # Control center launcher
├── config/
│   └── ai_policy.json              # AI routing + model config
├── data/
│   └── signatures.json             # Signature definitions (regex + tags)
├── src/
│   ├── APISniffer.py               # Stage 1: GitHub repository discovery
│   ├── APIScanner.py               # Stage 2: Repository scanning and secret detection
│   ├── AISearch.py                 # Stage 3: AI-powered local database search
│   ├── AIWorkflow.py               # AI workflow router and stage orchestrator
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── scanner_state.py        # Global constants + mutable runtime state
│   │   ├── scanner_args.py         # CLI parsing, overrides, state reset
│   │   ├── scanner_signals.py      # OS signal handlers
│   │   ├── scanner_token.py        # GitHub token prompt
│   │   ├── scanner_branch.py       # Branch name resolution
│   │   ├── scanner_proxy.py        # Proxy list I/O and health tracking
│   │   ├── scanner_io.py           # Atomic JSON persistence
│   │   ├── scanner_network.py      # HTTP download + proxy-fallback loop
│   │   ├── scanner_archive.py      # ZIP / TAR / git archive handling
│   │   ├── scanner_ui.py           # Dashboard state + log queues
│   │   ├── scanner_keyboard.py     # Background keyboard monitor
│   │   └── scanner_targets_live.py # Runtime AI-driven target injection
│   └── shared/
│       ├── __init__.py
│       ├── ai_client.py            # Groq API client + key handling
│       ├── ai_policy.py            # AI policy loader + templates
│       ├── ai_search_runtime.py    # Shared AI query runtime used by AISearch and AIWorkflow
│       ├── api_signatures.py       # API signature loader entry point
│       ├── category_routing.py     # Query/category inference helpers
│       ├── scanner_dashboard.py    # Dashboard rendering for the scanner
│       ├── scanner_matcher.py      # Regex matching and finding extraction
│       ├── scanner_targets.py      # Repo target extraction from prompts/URLs
│       └── signature_loader.py     # Loads signatures.json -> compiled regex
├── requirements.txt
├── live_proxies.txt                # Optional proxy list to bypass rate limits
└── README.md
```

The following files are generated at runtime and are not part of the source code:

| File | Purpose |
|---|---|
| `recent_repos.json` | Queue of discovered repositories waiting to be scanned |
| `leaked_keys.json` | Database of detected secrets |
| `clean_repos.json` | Repositories that were scanned with no findings |
| `failed_repos.json` | Repositories that failed to download or parse |

Optional local input file:

- `live_proxies.txt` - User-managed proxy list in `ip:port` format

---

## Requirements

- Python 3.8 or later
- The packages listed in `requirements.txt`

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

### Unified Launcher (Recommended)

```bash
python main.py
```

This opens the launcher. From there:

- Press `Enter` to launch the AI workflow directly OR,
- Type `Manual` to open the numbered control center OR,
- Type `help` to see how the workflow works

### How to Use: AI Workflow

The AI workflow is the fastest way to run the tool because it understands natural language and chains the right stages for you.

1. Start the launcher with `python main.py`.
2. At the launch screen, press `Enter` to go into the AI workflow.
3. When prompted, describe what you want in plain English.
4. The workflow will plan the steps (discovery, scanning, query) and run them in order.
5. When the run finishes, you can ask another question or switch to Manual mode.

Examples you can type:

1. `discover new repos for the last 5 minutes, then scan`
2. `scan the current queue with commit history off`
3. `show all Slack tokens from the findings`
4. `run discovery and scanning, then summarize leaks by category`

Notes:
1. If your request is only about existing results (like “show all API keys”), it skips discovery and scanning and just queries the local database.
2. For larger runs, setting `GITHUB_TOKEN` (or `GH_TOKEN`) helps avoid GitHub rate limits.
3. If you want the scanner to persist proxy pruning, launch with `python main.py --up-proxy`.

### AI Workflow Orchestrator

```bash
python src/AIWorkflow.py
```

This prompts for a natural-language request, routes it using `config/ai_policy.json`, and runs the required stages in sequence. It uses Groq's OpenAI-compatible API (default model is configured in `config/ai_policy.json`).

### Stage 1: Discover Repositories

```bash
python src/APISniffer.py
```

CLI flags:

```text
--lookback-mins
--chunk-mins
--pages-to-scrape
--proxy-retry-limit
```

Discovery queries GitHub for recently created repositories and writes fresh entries to `recent_repos.json`. It skips repositories already present in `clean_repos.json`, `failed_repos.json`, or `leaked_keys.json`. If your IP gets rate-limited, it can fall back to proxies from `live_proxies.txt`.

### Stage 2: Scan for Leaked Secrets

```bash
python src/APIScanner.py
```

CLI flags:

```text
--max-threads
--history-depth
--scan-heroku-keys
--no-commit-history
--prefer-proxy
--up-proxy
```

The scanner reads from `recent_repos.json`, resolves the repository's default branch when possible, downloads each repository as a ZIP archive, and scans it against the supported secret signatures. It can also inspect recent commit patches. Results are written to `leaked_keys.json`, `clean_repos.json`, or `failed_repos.json`. Scanned repositories are removed from the queue.
If you are scanning at scale, set `GITHUB_TOKEN` (or `GH_TOKEN`) in your environment so GitHub gives you a higher rate limit.

**Scanner controls:**
- `Space`: Pause/resume scanning
- `i`: Enter AI-assisted repo insertion mode
- `Esc`: Cancel repo insertion input

### Stage 3: Query the Database

```bash
python src/AISearch.py
```

One-shot query:

```bash
python src/AISearch.py --query "Show all AWS keys"
```

---

## Proxy Configuration

All network-facing scripts support HTTP proxy rotation. Create a file named `live_proxies.txt` in the working directory with one proxy per line:

```text
103.21.244.0:8080
45.77.56.114:3128
192.168.1.100:8888
```

Proxies are used as a fallback when direct GitHub requests are rate-limited or blocked.
By default the scanner does not rewrite your proxy list. If you want it to prune dead proxies and persist only the working ones, run the launcher with `python main.py --up-proxy` (or run the scanner directly with `python src/APIScanner.py --up-proxy`).

---

## Supported API Key Signatures

Signature rules are data-driven and loaded from `data/signatures.json`. You can add or update patterns there and they will be picked up automatically.

Examples of supported categories include:

| Category | Examples |
|---|---|
| AI and LLM Providers | OpenAI (legacy/project), Anthropic, Groq, xAI (Grok), OpenRouter, HuggingFace, Replicate, Cerebras |
| Cloud and Infrastructure | AWS Access Keys, AWS Session Tokens, DigitalOcean, Google API/GCP, Heroku, Databricks |
| Source Control | GitHub classic PATs, GitHub fine-grained PATs, GitLab PATs |
| Package Registries | NPM, PyPI |
| Communication and Webhooks | Discord bot tokens, Discord webhooks, Slack bot/user tokens, Slack webhooks, Telegram |
| Payments and Commerce | Stripe, Square, Shopify |
| Email and Messaging | SendGrid, Mailgun, Twilio |
| Database and Backend Services | Supabase, Firebase, PlanetScale, Airtable, Appwrite, Deta, PocketBase |
| Other Utilities | Postman, Mapbox, Sentry |

---

## Outputs and Data Files

**`recent_repos.json`** (discovery queue)

```json[
  {
    "name": "owner/repo",
    "created_at": "2024-01-01T00:00:00Z",
    "url": "https://github.com/owner/repo",
    "stars": 0
  }
]
```

**`leaked_keys.json`** (findings database)

```json[
  {
    "repo": "owner/repo",
    "url": "https://github.com/owner/repo",
    "status": "leaked",
    "total_secrets": 2,
    "findings":[
      {
        "file": "path/to/file",
        "line": 12,
        "type": "OpenAI API Key (Legacy)",
        "secret": "sk-..."
      }
    ]
  }
]
```

**`clean_repos.json`** (no findings)

```json[
  {
    "repo": "owner/repo",
    "url": "https://github.com/owner/repo",
    "status": "clean"
  }
]
```

**`failed_repos.json`** (download/scan failures)

```json[
  {
    "repo": "owner/repo",
    "status": "failed",
    "reason": "Forbidden 403 (Skipped)"
  }
]
```

---

## Disclaimer

This tool is intended for educational purposes, security research, and defensive analysis only. It works with public repository data and does not exploit, access, or modify any system.

Use it responsibly, respect platform rules and rate limits, and follow responsible disclosure practices if you discover exposed credentials.

---

## License

Part of the X3r0Day Framework. Free to use, modify, and redistribute with "**proper credit**" to the original project.
