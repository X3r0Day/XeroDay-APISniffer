# XeroDay's API Sniffer

API Sniffer is a modular toolkit for scanning publicly available GitHub repositories and identifying exposed API keys, tokens, and secrets. It is part of the X3r0Day Framework and is designed for security research, defensive analysis, and responsible disclosure.

The tool works in three stages: discovery, scanning, and querying. Each stage is handled by a dedicated script that reads from and writes to shared JSON files on disk, allowing them to run independently or as part of an automated pipeline.

---

## How It Works

API Sniffer operates as a three-stage pipeline. Each stage produces output that feeds into the next.

**Stage 1 – Discovery (`APISniffer.py`)**: Searches GitHub for recently created repositories within a set time window. New results are filtered to avoid duplicates and saved to a local queue file. Proxy rotation helps handle rate limits.

**Stage 2 – Scanning (`APIScanner.py`)**: Takes repositories from the discovery stage, downloads their source archives, and scans selected files using regex patterns. It also checks commit history via Atom feed patches. Found secrets are stored in a JSON database, and a multithreaded dashboard shows real-time scanning progress.

**Stage 3 – AI-Assisted Search (`AISearch.py`)**: Lets users search the leaked keys database using natural language. A language model (Llama-3 via Groq as default) interprets the query and finds matching API key categories, then displays the results in a formatted table. This feature is optional and requires a Groq API key.

---

## Project Structure

```
API Sniffer/
├── src/
│   ├── APISniffer.py        # Stage 1: GitHub repository discovery
│   ├── APIScanner.py        # Stage 2: Repository scanning and secret detection
│   └── AISearch.py          # Stage 3: AI-powered database search
├── requirements.txt
├── .gitignore
└── README.md
```

The following files are generated at runtime and excluded from version control:

| File | Purpose |
|---|---|
| `recent_repos.json` | Queue of discovered repositories pending scan |
| `leaked_keys.json` | Database of detected secrets |
| `clean_repos.json` | Repositories that passed scanning with no findings |
| `failed_repos.json` | Repositories that failed to download or parse |
| `live_proxies.txt` | Optional list of HTTP proxies (one per line, `ip:port` format) |

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

The scripts are meant to be run sequentially. Each stage depends on the output of the previous one.

### Stage 1: Discover Repositories

```bash
python src/APISniffer.py
```

This queries GitHub for repositories created in the last 100 minutes (configurable via `LOOKBACK_MINS`) and writes new entries to `recent_repos.json`. If your IP gets rate-limited, it will fall back to proxies listed in `live_proxies.txt`.

### Stage 2: Scan for Leaked Secrets

```bash
python src/APIScanner.py
```

This reads from `recent_repos.json`, downloads each repository as a ZIP archive, and scans the contents against 37 API key signatures. Results are written to `leaked_keys.json`, `clean_repos.json`, or `failed_repos.json` depending on the outcome. Scanned repositories are removed from the queue.

The scanner opens a full-screen terminal dashboard. Press **Space** to pause or resume scanning. Pausing also triggers a proxy list reload from disk, so you can update `live_proxies.txt` without restarting.

### Stage 3: Query the Database (Optional)

```bash
python src/AISearch.py
```

This opens an interactive prompt where you can ask natural language questions about the scan results. It requires a Groq API key, which can be provided through the `GROQ_API_KEY` environment variable or entered at the prompt.

Example queries:
- "Show me all AWS keys"
- "Find any Discord tokens"
- "List all AI-related API keys"

---

## Proxy Configuration

All network-facing scripts support HTTP proxy rotation. Create a file named `live_proxies.txt` in the working directory with one proxy per line:

```
103.21.244.0:8080
45.77.56.114:3128
192.168.1.100:8888
```

Proxies are used as a fallback when direct connections to GitHub are rate-limited or blocked. The scanner shuffles the proxy list before each attempt.

---

## Supported API Key Signatures

The scanner detects the following secret types:

| Category | Examples |
|---|---|
| AI and LLM Providers | OpenAI, Anthropic, Groq, xAI (Grok), OpenRouter, HuggingFace, Replicate, Cerebras |
| Cloud Platforms | AWS Access Keys, AWS Session Tokens, DigitalOcean, Heroku, Google Cloud, Databricks |
| Source Control | GitHub PATs, GitLab PATs |
| Package Registries | NPM, PyPI |
| Communication | Discord (Bot Tokens, Webhooks), Slack (Bot, User, Webhooks), Telegram |
| Payment and Commerce | Stripe, Square, Shopify |
| Email and Messaging | SendGrid, Mailgun, Twilio |
| Other | Postman, Mapbox, Sentry |

---

## Configuration

Key parameters can be adjusted by editing the constants at the top of each script.

**APISniffer.py**
- `LOOKBACK_MINS` — How far back in time to search for new repositories (default: 100 minutes)
- `PAGES_TO_SCRAPE` — Number of GitHub API result pages to fetch (default: 10, at 100 results per page)
- `PROXY_RETRY_LIMIT` — Maximum number of proxies to try before giving up (default: 200)

**APIScanner.py**
- `MAX_THREADS` — Number of concurrent scanning threads (default: 15)
- `SCAN_COMMIT_HISTORY` — Whether to scan commit diffs in addition to the latest source (default: True)
- `MAX_HISTORY_DEPTH` — Number of recent commits to scan (default: 10)
- `SCAN_HEROKU_KEYS` — Whether to include the Heroku UUID pattern, which can produce false positives (default: False)
- `FAT_FILE_LIMIT` — Skip individual files larger than this size in bytes (default: 10 MB)
- `MAX_DOWNLOAD_SIZE_BYTES` — Abort downloads exceeding this size (default: 20 MB)

---

## Disclaimer

This tool is intended for educational purposes, security research, and defensive analysis only. It queries publicly available GitHub repository metadata and does not exploit, access, or modify any system.

Users are solely responsible for how this software is used. Always respect platform policies, rate limits, and the privacy of developers. If you discover sensitive information or exposed credentials during research, follow responsible disclosure practices and notify the affected parties.

---

## License

Part of the X3r0Day Framework. Free to use, modify, and redistribute with proper credit to the original project.
