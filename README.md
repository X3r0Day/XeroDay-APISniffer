# XeroDay's API Sniffer

API Sniffer is a GitHub-focused secret discovery toolkit for scanning public repositories and identifying exposed API keys, tokens, webhooks, and other sensitive credentials. It is part of the X3r0Day Framework and is built for security research, defensive analysis, and responsible disclosure.

The project is organized around discovery, scanning, and querying, with an AI-first launcher, a workflow orchestrator, shared routing and search utilities, scanner dashboard helpers, repo-target extraction helpers.

---

## How It Works

API Sniffer supports two operating modes:

1. **AI-first launch path** through `main.py` -> `AIWorkflow.py`, where natural-language requests are routed into discovery, scanning, direct database querying, or chained workflows.
2. **Manual stage execution** where you run the modules yourself or use the numbered launcher menu.

The core pipeline is:

**Stage 1 - Discovery (`APISniffer.py`)**: Queries GitHub for newly created public repositories across a recent time window, deduplicates them against the live queue and prior scan history, and stores fresh targets in `recent_repos.json`.

**Stage 2 - Scanning (`APIScanner.py`)**: Pulls repositories from the queue, resolves the repo's default branch when needed, downloads repository archives, scans matching files, optionally scans recent commit patches, and writes results into `leaked_keys.json`, `clean_repos.json`, or `failed_repos.json`.

**Stage 3 - AI Search (`AISearch.py`)**: Queries the local findings database with natural language. The search runtime is shared with the AI workflow, so database questions like `show all the API keys` can be answered directly from the launcher flow.

**Shared runtime modules (`src/shared/`)**: Hold reusable logic for API signature definitions, category routing, AI-assisted search, scanner matching, scanner dashboard rendering, and GitHub repo target extraction.

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

## Project Structure

```text
API Sniffer/
├── main.py                         # Control center entry point
├── src/
│   ├── APISniffer.py               # Stage 1: GitHub repository discovery
│   ├── APIScanner.py               # Stage 2: Repository scanning and secret detection
│   ├── AISearch.py                 # Stage 3: AI-powered local database search
│   ├── AIWorkflow.py               # AI workflow router and stage orchestrator
│   └── shared/
│       ├── __init__.py
│       ├── ai_search_runtime.py    # Shared AI query runtime used by AISearch and AIWorkflow
│       ├── api_signatures.py       # Secret signature definitions
│       ├── category_routing.py     # Query/category inference helpers
│       ├── scanner_dashboard.py    # Dashboard rendering for the scanner
│       ├── scanner_matcher.py      # Regex matching and finding extraction
│       └── scanner_targets.py      # Repo target extraction from prompts/URLs
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

## Execution Order

The modules can run one by one, and the launcher provides the fastest path through the full workflow.

### Unified Launcher (Recommended)

```bash
python main.py
```

This opens the launcher. From there:

- Type `help` to see how the workflow works
- Type `Manual` to open the numbered control center
- Press `Enter` to open the AI workflow directly

Example requests:

- `show all the API keys`
- `find any Discord tokens`
- `start scanning`
- `run discovery for last 3 minutes, then scan`

### Stage 1: Discover Repositories

```bash
python src/APISniffer.py
```

This queries GitHub for recently created repositories and writes fresh entries to `recent_repos.json`. Discovery also skips repositories that already exist in the queue or in the historical output files (`clean_repos.json`, `failed_repos.json`, and `leaked_keys.json`). If your IP gets rate-limited, it can fall back to proxies from `live_proxies.txt`.

### Stage 2: Scan for Leaked Secrets

```bash
python src/APIScanner.py
```

This reads from `recent_repos.json`, resolves the repository's default branch when possible, downloads each repository as a ZIP archive, and scans it against the supported secret signatures. It can also inspect recent commit patches. Results are written to `leaked_keys.json`, `clean_repos.json`, or `failed_repos.json`. Scanned repositories are removed from the queue.

The scanner opens a full-screen terminal dashboard.

- Press `Space` to pause or resume
- Press `i` to insert to ask AI to insert GitHub repo targets while the scanner is running
- Repo insertion accepts GitHub URLs or `owner/repo` targets and pushes them into the live queue or just AI query

### Stage 3: Query the Database

```bash
python src/AISearch.py
```

This opens the AI search prompt for the local database. It requires a Groq API key, which can be set through `GROQ_API_KEY` or entered at runtime.

You can also run a one-shot query without opening the interactive prompt:

```bash
python src/AISearch.py --query "Show all AWS keys"
```

Example queries:

- `Show me all AWS keys`
- `Find any Discord tokens`
- `List all AI-related API keys`

---

## Proxy Configuration

All network-facing scripts support HTTP proxy rotation. Create a file named `live_proxies.txt` in the working directory with one proxy per line:

```text
103.21.244.0:8080
45.77.56.114:3128
192.168.1.100:8888
```

Proxies are used as a fallback when direct GitHub requests are rate-limited or blocked.

---

## Supported API Key Signatures

The signature set includes:

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

## Configuration

Key values can be adjusted by editing the constants at the top of the scripts.

**APISniffer.py**
- `LOOKBACK_MINS` - How far back to search for new repositories
- `CHUNK_MINS` - Time window size used per GitHub search chunk
- `PAGES_TO_SCRAPE` - Number of GitHub API result pages to fetch
- `PROXY_RETRY_LIMIT` - Maximum number of proxies to try before giving up

**APIScanner.py**
- `MAX_THREADS` - Number of concurrent scanning threads
- `SCAN_COMMIT_HISTORY` - Whether to scan commit diffs as well
- `MAX_HISTORY_DEPTH` - Number of recent commits to scan
- `SCAN_HEROKU_KEYS` - Whether to include the Heroku UUID pattern
- `FAT_FILE_LIMIT` - Skip files larger than this size
- `MAX_DOWNLOAD_SIZE_BYTES` - Abort downloads larger than this size

---

## Disclaimer

This tool is intended for educational purposes, security research, and defensive analysis only. It works with public repository data and does not exploit, access, or modify any system.

Use it responsibly, respect platform rules and rate limits, and follow responsible disclosure practices if you discover exposed credentials.

---

## License

Part of the X3r0Day Framework. Free to use, modify, and redistribute with proper credit to the original project.
