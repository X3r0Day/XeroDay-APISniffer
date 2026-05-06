import json
import os
from collections import Counter
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from .ai_client import ask_json, ask_text, build_msgs, get_key, remember_exchange
from .ai_policy import fill_tpl, load_pol
from .api_signatures import API_SIGNATURE_CATEGORIES
from .category_routing import infer_categories_from_query, is_summary_query, normalize_categories


LEAKS_JSON = "leaked_keys.json"
AVAILABLE_CATEGORIES = list(API_SIGNATURE_CATEGORIES)
AI_PREVIEW_LIMIT = 10


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
    return get_key(console)


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


def clamp_limit(raw_value: Any, default: int, max_limit: int) -> int:
    try:
        limit_value = int(raw_value)
    except (TypeError, ValueError):
        return default
    return max(1, min(max_limit, limit_value))


def _q_cfg(pol: Dict[str, Any]) -> Dict[str, Any]:
    q = pol.get("query", {}) if isinstance(pol, dict) else {}
    lim = q.get("limit", {}) if isinstance(q, dict) else {}
    intents = q.get("valid_intents") or ["search", "summary"]
    origins = q.get("valid_origins") or ["any", "commit", "repo_file"]
    lim_def = int(lim.get("default", 50) or 50)
    lim_max = int(lim.get("max", 100) or 100)
    return {
        "intents": {str(x).strip().lower() for x in intents if str(x).strip()},
        "origins": {str(x).strip().lower() for x in origins if str(x).strip()},
        "lim_def": lim_def,
        "lim_max": lim_max,
        "sys": str(q.get("system", "")).strip(),
    }


def normalize_query_plan(ai_instructions: dict, pol: Dict[str, Any]) -> Dict[str, object]:
    cfg = _q_cfg(pol)
    understanding = str(ai_instructions.get("understanding", "")).strip() if isinstance(ai_instructions, dict) else ""
    intent = str(ai_instructions.get("intent", "search")).strip().lower() if isinstance(ai_instructions, dict) else "search"
    if intent not in cfg["intents"]:
        intent = "search"

    raw_categories = ai_instructions.get("target_categories", []) if isinstance(ai_instructions, dict) else []
    if not isinstance(raw_categories, list):
        raw_categories = []

    origin = str(ai_instructions.get("origin", "any")).strip().lower() if isinstance(ai_instructions, dict) else "any"
    if origin not in cfg["origins"]:
        origin = "any"

    return {
        "understanding": understanding,
        "intent": intent,
        "target_categories": normalize_categories([str(category) for category in raw_categories]),
        "repo_terms": normalize_terms(ai_instructions.get("repo_terms", []) if isinstance(ai_instructions, dict) else []),
        "file_terms": normalize_terms(ai_instructions.get("file_terms", []) if isinstance(ai_instructions, dict) else []),
        "origin": origin,
        "limit": clamp_limit(
            ai_instructions.get("limit", cfg["lim_def"]) if isinstance(ai_instructions, dict) else cfg["lim_def"],
            cfg["lim_def"],
            cfg["lim_max"],
        ),
    }


def build_fallback_query_plan(user_query: str, pol: Dict[str, Any]) -> Dict[str, object]:
    cfg = _q_cfg(pol)
    return {
        "understanding": "",
        "intent": "summary" if is_summary_query(user_query) else "search",
        "target_categories": infer_categories_from_query(user_query),
        "repo_terms": [],
        "file_terms": [],
        "origin": "any",
        "limit": cfg["lim_def"],
    }


def ask_ai_for_query_plan(
    user_query: str,
    api_key: str,
    pol: Dict[str, Any],
    history: Optional[List[Dict[str, str]]] = None,
) -> dict:
    cfg = _q_cfg(pol)
    rep = {
        "__CATEGORIES__": json.dumps(AVAILABLE_CATEGORIES),
        "__VALID_INTENTS__": json.dumps(sorted(cfg["intents"])),
        "__VALID_ORIGINS__": json.dumps(sorted(cfg["origins"])),
        "__LIMIT_DEFAULT__": str(cfg["lim_def"]),
    }
    sys_tpl = cfg["sys"]
    if not sys_tpl:
        raise RuntimeError("AI query policy missing.")
    sys_txt = fill_tpl(sys_tpl, rep)
    msgs = build_msgs(sys_txt, user_query, history)
    cfg_llm = pol.get("llm", {})
    return ask_json(msgs, api_key, cfg_llm)


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

    scope_parts.append(f"limit={query_plan.get('limit', 50)}")
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


def ask_ai_for_result_summary(
    user_query: str,
    query_plan: Dict[str, object],
    matches: List[Dict[str, str]],
    api_key: str,
    pol: Dict[str, Any],
) -> str:
    sys_txt = str(pol.get("summary", {}).get("system", "")).strip()
    if not sys_txt:
        raise RuntimeError("AI summary policy missing.")

    user_payload = {
        "user_query": user_query,
        "query_plan": query_plan,
        "result_context": build_result_context(query_plan, matches),
    }
    msgs = [
        {"role": "system", "content": sys_txt},
        {"role": "user", "content": json.dumps(user_payload)},
    ]
    cfg_llm = pol.get("llm", {})
    return ask_text(msgs, api_key, cfg_llm)


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

    limited_matches = matches[: int(query_plan.get("limit", 50))]
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


def process_query(
    cleaned_input: str,
    api_key: str,
    db_data: list,
    console: Console,
    pol: Dict[str, Any],
    history: Optional[List[Dict[str, str]]] = None,
) -> None:
    with console.status("[bold yellow]AI is planning the search...[/]", spinner="dots"):
        try:
            query_plan = normalize_query_plan(ask_ai_for_query_plan(cleaned_input, api_key, pol, history), pol)
        except Exception as error:
            console.print(f"[bold yellow][!] AI planner fallback engaged: {error}[/]")
            query_plan = build_fallback_query_plan(cleaned_input, pol)

    matches = collect_matches(query_plan, db_data)

    with console.status("[bold yellow]AI is analyzing the results...[/]", spinner="dots"):
        try:
            ai_summary = ask_ai_for_result_summary(cleaned_input, query_plan, matches, api_key, pol)
        except Exception as error:
            console.print(f"[bold yellow][!] AI summary fallback engaged: {error}[/]")
            ai_summary = ""

    understanding = ai_summary or query_plan.get("understanding") or fallback_summary_text(cleaned_input, query_plan, matches)
    console.print(f"[bold green]AI:[/] {understanding}")
    remember_exchange(history, cleaned_input, json.dumps({"query_plan": query_plan, "reply": understanding}))

    if query_plan.get("intent") == "summary":
        display_summary(query_plan, matches, console)
        return

    search_and_display(query_plan, matches, console)


def run_single_query(
    query_text: str,
    console: Optional[Console] = None,
    show_header: bool = False,
    api_key: Optional[str] = None,
    history: Optional[List[Dict[str, str]]] = None,
) -> None:
    active_console = console or Console()
    cleaned_query = query_text.strip()
    if not cleaned_query:
        return

    if show_header:
        render_header(active_console)

    pol = load_pol(log_fn=active_console.print)
    if not pol:
        return

    resolved_api_key = api_key or get_groq_api_key(active_console)
    db_data = load_database(active_console)
    if not db_data:
        return

    if show_header:
        render_database_overview(active_console, db_data)

    process_query(cleaned_query, resolved_api_key, db_data, active_console, pol, history)


def run_interactive_search(console: Optional[Console] = None) -> None:
    active_console = console or Console()
    render_header(active_console)

    pol = load_pol(log_fn=active_console.print)
    if not pol:
        return

    api_key = get_groq_api_key(active_console)
    db_data = load_database(active_console)
    if not db_data:
        return

    render_database_overview(active_console, db_data)
    active_console.print("[dim]Type 'exit' or 'quit' to close the terminal.[/]\n")
    query_history: List[Dict[str, str]] = []

    while True:
        try:
            user_input = Prompt.ask("[bold cyan]Ask AI[/]", console=active_console)
            cleaned_input = user_input.strip()
            if not cleaned_input:
                continue

            if cleaned_input.lower() in {"exit", "quit"}:
                active_console.print("[bold magenta]Shutting down AI Engine...[/]")
                break

            process_query(cleaned_input, api_key, db_data, active_console, pol, query_history)
        except KeyboardInterrupt:
            active_console.print("\n[bold magenta]Shutting down AI Engine...[/]")
            break
        except Exception as error:
            active_console.print(f"[bold red]Unexpected Error: {error}[/]")
