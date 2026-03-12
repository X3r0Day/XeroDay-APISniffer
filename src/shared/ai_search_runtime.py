import json
import os
from collections import Counter
from typing import Any, Dict, List, Optional

import requests
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from .api_signatures import API_SIGNATURE_CATEGORIES
from .category_routing import infer_categories_from_query, is_summary_query, normalize_categories


LEAKS_JSON = "leaked_keys.json"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.3-70b-versatile"
AVAILABLE_CATEGORIES = list(API_SIGNATURE_CATEGORIES)
DEFAULT_RESULT_LIMIT = 50
MAX_RESULT_LIMIT = 100
AI_PREVIEW_LIMIT = 10
VALID_INTENTS = {"search", "summary"}
VALID_ORIGINS = {"any", "commit", "repo_file"}


def count_unique_repositories(entries: list) -> int:
    return len(
        {
            str(entry.get("repo", "")).strip().lower()
            for entry in entries
            if isinstance(entry, dict) and entry.get("repo")
        }
    )


def count_total_findings(entries: list) -> int:
    total = 0
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        findings = entry.get("findings", [])
        total += len(findings) if isinstance(findings, list) else int(entry.get("total_secrets", 0) or 0)
    return total


def render_header(console: Console) -> None:
    console.print(
        Panel.fit(
            "[bold magenta]API Sniffer - AI Database Query Engine[/]\n[dim]Powered by Llama-3 via Groq[/]",
            border_style="magenta",
        )
    )


def get_groq_api_key(console: Console) -> str:
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        console.print("[bold yellow][!] GROQ_API_KEY environment variable not found.[/]")
        api_key = Prompt.ask("[bold cyan]Please enter your Groq API Key (gsk_...)[/]", password=True, console=console)
        os.environ["GROQ_API_KEY"] = api_key
    return api_key


def load_database(console: Console) -> list:
    if not os.path.exists(LEAKS_JSON):
        console.print(f"[bold red][X] Database file '{LEAKS_JSON}' not found. Please run the scanner first.[/]")
        return []

    try:
        with open(LEAKS_JSON, "r", encoding="utf-8") as file_ptr:
            raw_data = json.load(file_ptr)
            if not isinstance(raw_data, list):
                raise ValueError("Database file does not contain a JSON list.")
            return raw_data
    except Exception as error:
        console.print(f"[bold red][X] Error reading database: {error}[/]")
        return []


def render_database_overview(console: Console, db_data: list) -> None:
    repo_count = count_unique_repositories(db_data)
    total_findings = count_total_findings(db_data)
    console.print(f"[green]Loaded database with {repo_count} repositories and {total_findings} findings.[/]")


def extract_json_blob(raw_text: str) -> Dict[str, object]:
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        start = raw_text.find("{")
        end = raw_text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(raw_text[start : end + 1])
        raise


def normalize_terms(raw_terms: Any) -> List[str]:
    if not isinstance(raw_terms, list):
        return []

    cleaned_terms = []
    seen_terms = set()
    for raw_term in raw_terms:
        cleaned_term = " ".join(str(raw_term).strip().strip("`'\"").split())
        if not cleaned_term:
            continue
        normalized_term = cleaned_term.casefold()
        if normalized_term in seen_terms:
            continue
        seen_terms.add(normalized_term)
        cleaned_terms.append(cleaned_term)
    return cleaned_terms


def clamp_limit(raw_value: Any, default: int = DEFAULT_RESULT_LIMIT) -> int:
    try:
        limit_value = int(raw_value)
    except (TypeError, ValueError):
        return default
    return max(1, min(MAX_RESULT_LIMIT, limit_value))


def normalize_query_plan(ai_instructions: dict) -> Dict[str, object]:
    understanding = str(ai_instructions.get("understanding", "")).strip() if isinstance(ai_instructions, dict) else ""
    intent = str(ai_instructions.get("intent", "search")).strip().lower() if isinstance(ai_instructions, dict) else "search"
    if intent not in VALID_INTENTS:
        intent = "search"

    raw_categories = ai_instructions.get("target_categories", []) if isinstance(ai_instructions, dict) else []
    if not isinstance(raw_categories, list):
        raw_categories = []

    origin = str(ai_instructions.get("origin", "any")).strip().lower() if isinstance(ai_instructions, dict) else "any"
    if origin not in VALID_ORIGINS:
        origin = "any"

    return {
        "understanding": understanding,
        "intent": intent,
        "target_categories": normalize_categories([str(category) for category in raw_categories]),
        "repo_terms": normalize_terms(ai_instructions.get("repo_terms", []) if isinstance(ai_instructions, dict) else []),
        "file_terms": normalize_terms(ai_instructions.get("file_terms", []) if isinstance(ai_instructions, dict) else []),
        "origin": origin,
        "limit": clamp_limit(ai_instructions.get("limit", DEFAULT_RESULT_LIMIT) if isinstance(ai_instructions, dict) else DEFAULT_RESULT_LIMIT),
    }


def build_fallback_query_plan(user_query: str) -> Dict[str, object]:
    return {
        "understanding": "",
        "intent": "summary" if is_summary_query(user_query) else "search",
        "target_categories": infer_categories_from_query(user_query),
        "repo_terms": [],
        "file_terms": [],
        "origin": "any",
        "limit": DEFAULT_RESULT_LIMIT,
    }


def ask_ai_for_query_plan(user_query: str, api_key: str) -> dict:
    system_prompt = f"""You are X3r0Day's API Sniffer's AI query planner.
Your job is to convert the user's request into a structured search plan for leaked_keys.json.
You must return valid JSON only.

Database shape:
- top-level JSON list
- each item looks like:
  {{
    "repo": "owner/repo",
    "findings": [
      {{
        "type": "Exact Category Name",
        "secret": "raw secret value",
        "file": "path/to/file" or "Commit abc123",
        "line": 12
      }}
    ]
  }}

AVAILABLE EXACT CATEGORIES:
{json.dumps(AVAILABLE_CATEGORIES)}

Return this exact JSON shape:
{{
  "understanding": "One short sentence describing what will be searched.",
  "intent": "search",
  "target_categories": ["Exact Category Name"],
  "repo_terms": ["substring from the user's request"],
  "file_terms": ["substring from the user's request"],
  "origin": "any",
  "limit": 50
}}

Rules:
1. Use ONLY exact category names from AVAILABLE EXACT CATEGORIES.
2. If the user asks about all findings or does not constrain a category, leave target_categories empty.
3. Put repo_terms and file_terms only when the user clearly specifies them.
4. origin must be one of:
   - "any"
   - "commit" when the user asks about commits, commit history, or patches
   - "repo_file" when the user explicitly asks about files rather than commits
5. intent must be:
   - "search" for detailed matches
   - "summary" for counts, statistics, overview, category lists, or broad summaries
6. Do not invent categories, repo names, file paths, or facts not implied by the request.
7. limit should be a reasonable row cap based on the request. Use 50 if unspecified.
"""

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": GROQ_MODEL,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_query},
        ],
        "temperature": 0.1,
    }

    response = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=20)
    response.raise_for_status()
    data = response.json()
    return extract_json_blob(data["choices"][0]["message"]["content"])


def mask_secret(secret_value: str) -> str:
    normalized_secret = str(secret_value or "")
    if len(normalized_secret) <= 12:
        return normalized_secret
    return f"{normalized_secret[:4]}...{normalized_secret[-4:]}"


def build_scope_text(query_plan: Dict[str, object]) -> str:
    scope_parts = []
    target_categories = query_plan.get("target_categories", [])
    repo_terms = query_plan.get("repo_terms", [])
    file_terms = query_plan.get("file_terms", [])
    origin = query_plan.get("origin", "any")

    if target_categories:
        scope_parts.append(f"categories={', '.join(target_categories)}")
    else:
        scope_parts.append("categories=all")

    if repo_terms:
        scope_parts.append(f"repo~{', '.join(repo_terms)}")
    if file_terms:
        scope_parts.append(f"file~{', '.join(file_terms)}")
    if origin == "commit":
        scope_parts.append("origin=commits")
    elif origin == "repo_file":
        scope_parts.append("origin=repository files")

    scope_parts.append(f"limit={query_plan.get('limit', DEFAULT_RESULT_LIMIT)}")
    return "; ".join(scope_parts)


def finding_origin(file_value: str) -> str:
    normalized_file = str(file_value or "").strip()
    return "commit" if normalized_file.startswith("Commit ") else "repo_file"


def matches_terms(value: str, terms: List[str]) -> bool:
    if not terms:
        return True
    normalized_value = str(value or "").casefold()
    return any(term.casefold() in normalized_value for term in terms)


def collect_matches(query_plan: Dict[str, object], db_data: list) -> List[Dict[str, str]]:
    category_set = set(query_plan.get("target_categories", []))
    repo_terms = query_plan.get("repo_terms", [])
    file_terms = query_plan.get("file_terms", [])
    origin_filter = query_plan.get("origin", "any")
    collected = []

    for repo_entry in db_data:
        if not isinstance(repo_entry, dict):
            continue

        repo_name = str(repo_entry.get("repo", "Unknown"))
        findings = repo_entry.get("findings", [])
        if not isinstance(findings, list):
            continue

        for finding in findings:
            if not isinstance(finding, dict):
                continue

            finding_type = str(finding.get("type", "Unknown"))
            file_value = str(finding.get("file", "Unknown"))
            match_origin = finding_origin(file_value)

            if category_set and finding_type not in category_set:
                continue
            if origin_filter != "any" and match_origin != origin_filter:
                continue
            if not matches_terms(repo_name, repo_terms):
                continue
            if not matches_terms(file_value, file_terms):
                continue

            collected.append(
                {
                    "repo": repo_name,
                    "type": finding_type,
                    "secret": str(finding.get("secret", "N/A")),
                    "file": file_value,
                    "origin": match_origin,
                    "line": str(finding.get("line", "?")),
                }
            )

    return sorted(collected, key=lambda match: (match["repo"].lower(), match["type"].lower(), match["file"].lower(), match["line"]))


def build_result_context(query_plan: Dict[str, object], matches: List[Dict[str, str]]) -> Dict[str, object]:
    type_counts = Counter(match["type"] for match in matches)
    repo_counts = Counter(match["repo"] for match in matches)
    preview_matches = [
        {
            "repo": match["repo"],
            "type": match["type"],
            "file": match["file"],
            "origin": match["origin"],
            "secret_preview": mask_secret(match["secret"]),
        }
        for match in matches[:AI_PREVIEW_LIMIT]
    ]

    return {
        "scope": build_scope_text(query_plan),
        "intent": query_plan.get("intent", "search"),
        "match_count": len(matches),
        "repository_count": len({match["repo"] for match in matches}),
        "top_categories": [{"name": name, "count": count} for name, count in type_counts.most_common(5)],
        "top_repositories": [{"name": name, "count": count} for name, count in repo_counts.most_common(5)],
        "sample_matches": preview_matches,
    }


def ask_ai_for_result_summary(user_query: str, query_plan: Dict[str, object], matches: List[Dict[str, str]], api_key: str) -> str:
    system_prompt = """You explain search results from a local leaked-secrets database.
Reply in 1 or 2 short sentences.
Do not invent anything that is not in the result context.
If there are zero results, say that clearly.
Do not print or reconstruct full secret values from previews.
"""

    user_payload = {
        "user_query": user_query,
        "query_plan": query_plan,
        "result_context": build_result_context(query_plan, matches),
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_payload)},
        ],
        "temperature": 0.2,
    }

    response = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=20)
    response.raise_for_status()
    response_data = response.json()
    return str(response_data["choices"][0]["message"]["content"]).strip()


def fallback_summary_text(user_query: str, query_plan: Dict[str, object], matches: List[Dict[str, str]]) -> str:
    categories = query_plan.get("target_categories", [])
    if categories:
        scope_label = ", ".join(categories)
    else:
        scope_label = "all tracked findings"

    if query_plan.get("repo_terms"):
        scope_label += f" in repos matching {', '.join(query_plan['repo_terms'])}"
    if query_plan.get("file_terms"):
        scope_label += f" with files matching {', '.join(query_plan['file_terms'])}"
    if query_plan.get("origin") == "commit":
        scope_label += " from commit history"
    elif query_plan.get("origin") == "repo_file":
        scope_label += " from repository files"

    if query_plan.get("intent") == "summary":
        return f"I summarized {scope_label} and found {len(matches)} matching findings."

    return f"I searched {scope_label} and found {len(matches)} matching findings."


def search_and_display(query_plan: Dict[str, object], matches: List[Dict[str, str]], console: Console) -> None:
    console.print(f"\n[dim]=> AI search scope: {build_scope_text(query_plan)}[/]")

    table = Table(title="[bold cyan]API Sniffer's Database Search Results[/]", border_style="cyan", expand=True)
    table.add_column("Repository", style="magenta", overflow="fold", ratio=2)
    table.add_column("API Type", style="yellow", overflow="fold", ratio=2)
    table.add_column("Secret / Key", style="red", overflow="fold", ratio=4)
    table.add_column("File / Origin", style="dim", overflow="fold", ratio=2)

    limited_matches = matches[: int(query_plan.get("limit", DEFAULT_RESULT_LIMIT))]
    for match in limited_matches:
        table.add_row(match["repo"], match["type"], match["secret"], match["file"])

    if matches:
        repo_count = len({match["repo"] for match in matches})
        finding_label = "finding" if len(matches) == 1 else "findings"
        repo_label = "repository" if repo_count == 1 else "repositories"
        console.print(table)
        if len(matches) > len(limited_matches):
            console.print(f"[dim]Showing {len(limited_matches)} of {len(matches)} total matches based on the AI-selected limit.[/]")
        console.print(
            f"[bold green]Successfully pulled {len(matches)} matching {finding_label} "
            f"across {repo_count} {repo_label} from the local database.[/]\n"
        )
        return

    console.print("[bold yellow][!] Search finished. 0 records found in the local database for the AI-selected filters.[/]\n")


def display_summary(query_plan: Dict[str, object], matches: List[Dict[str, str]], console: Console) -> None:
    console.print(f"\n[dim]=> AI summary scope: {build_scope_text(query_plan)}[/]")

    repo_count = len({match["repo"] for match in matches})
    type_counts = Counter(match["type"] for match in matches)
    repo_counts = Counter(match["repo"] for match in matches)
    scoped_category_count = len(query_plan.get("target_categories", [])) or len(AVAILABLE_CATEGORIES)

    summary_table = Table(title="[bold cyan]API Sniffer Summary[/]", border_style="cyan", expand=False)
    summary_table.add_column("Metric", style="yellow")
    summary_table.add_column("Value", style="green", justify="right")
    summary_table.add_row("Scope", build_scope_text(query_plan))
    summary_table.add_row("Repositories with matches", str(repo_count))
    summary_table.add_row("Matching findings in local DB", str(len(matches)))
    summary_table.add_row("Categories searched", str(scoped_category_count))
    console.print(summary_table)

    if type_counts:
        top_types_table = Table(title="[bold cyan]Top Categories[/]", border_style="cyan", expand=False)
        top_types_table.add_column("Category", style="yellow")
        top_types_table.add_column("Count", style="green", justify="right")
        for category_name, count in type_counts.most_common(5):
            top_types_table.add_row(category_name, str(count))
        console.print(top_types_table)

    if repo_counts:
        top_repos_table = Table(title="[bold cyan]Top Repositories[/]", border_style="cyan", expand=False)
        top_repos_table.add_column("Repository", style="magenta")
        top_repos_table.add_column("Count", style="green", justify="right")
        for repo_name, count in repo_counts.most_common(5):
            top_repos_table.add_row(repo_name, str(count))
        console.print(top_repos_table)

    console.print()


def process_query(cleaned_input: str, api_key: str, db_data: list, console: Console) -> None:
    with console.status("[bold yellow]AI is planning the search...[/]", spinner="dots"):
        try:
            query_plan = normalize_query_plan(ask_ai_for_query_plan(cleaned_input, api_key))
        except Exception as error:
            console.print(f"[bold yellow][!] AI planner fallback engaged: {error}[/]")
            query_plan = build_fallback_query_plan(cleaned_input)

    matches = collect_matches(query_plan, db_data)

    with console.status("[bold yellow]AI is analyzing the results...[/]", spinner="dots"):
        try:
            ai_summary = ask_ai_for_result_summary(cleaned_input, query_plan, matches, api_key)
        except Exception as error:
            console.print(f"[bold yellow][!] AI summary fallback engaged: {error}[/]")
            ai_summary = ""

    understanding = ai_summary or query_plan.get("understanding") or fallback_summary_text(cleaned_input, query_plan, matches)
    console.print(f"[bold green]AI:[/] {understanding}")

    if query_plan.get("intent") == "summary":
        display_summary(query_plan, matches, console)
        return

    search_and_display(query_plan, matches, console)


def run_single_query(
    query_text: str,
    console: Optional[Console] = None,
    show_header: bool = False,
    api_key: Optional[str] = None,
) -> None:
    active_console = console or Console()
    cleaned_query = query_text.strip()
    if not cleaned_query:
        return

    if show_header:
        render_header(active_console)

    resolved_api_key = api_key or get_groq_api_key(active_console)
    db_data = load_database(active_console)
    if not db_data:
        return

    if show_header:
        render_database_overview(active_console, db_data)

    process_query(cleaned_query, resolved_api_key, db_data, active_console)


def run_interactive_search(console: Optional[Console] = None) -> None:
    active_console = console or Console()
    render_header(active_console)

    api_key = get_groq_api_key(active_console)
    db_data = load_database(active_console)
    if not db_data:
        return

    render_database_overview(active_console, db_data)
    active_console.print("[dim]Type 'exit' or 'quit' to close the terminal.[/]\n")

    while True:
        try:
            user_input = Prompt.ask("[bold cyan]Ask AI[/]", console=active_console)
            cleaned_input = user_input.strip()
            if not cleaned_input:
                continue

            if cleaned_input.lower() in {"exit", "quit"}:
                active_console.print("[bold magenta]Shutting down AI Engine...[/]")
                break

            process_query(cleaned_input, api_key, db_data, active_console)
        except KeyboardInterrupt:
            active_console.print("\n[bold magenta]Shutting down AI Engine...[/]")
            break
        except Exception as error:
            active_console.print(f"[bold red]Unexpected Error: {error}[/]")
