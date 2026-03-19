# ---------------------------------------------------------------------------------- #
#                            Part of the X3r0Day project.                            #
# ---------------------------------------------------------------------------------- #


import json
import os
import threading
from typing import Optional

from . import scanner_state as state
from .scanner_io import dump_json_safely, repo_identity, write_json_snapshot
from .scanner_ui import bump_score, log_msg


def queue_manual_target(repo_data: dict) -> bool:
    repo_name = repo_data["name"]
    repo_key = repo_identity(repo_name)

    with state.manual_target_mutex:
        if repo_key in state.manual_target_names:
            log_msg(f"[bold yellow][!] Target already pending:[/] {repo_name}")
            return False

    with state.io_mutex:
        current_queue: list = []
        if os.path.exists(state.QUEUE_JSON):
            try:
                with open(state.QUEUE_JSON, "r", encoding="utf-8") as fh:
                    current_queue = json.load(fh)
            except Exception:
                current_queue = []

        if any(repo_identity(r.get("name", "")) == repo_key for r in current_queue):
            log_msg(f"[bold yellow][!] Target already queued:[/] {repo_name}")
            return False

        current_queue.append(repo_data)
        write_json_snapshot(current_queue, state.QUEUE_JSON)

    with state.manual_target_mutex:
        state.manual_target_queue.append(repo_data)
        state.manual_target_names.add(repo_key)

    bump_score("total", 1)
    bump_score("remaining", 1)
    log_msg(f"[bold green][+] Inserted target:[/] {repo_name}")
    return True


def pop_manual_target() -> Optional[dict]:
    with state.manual_target_mutex:
        if not state.manual_target_queue:
            return None
        repo_data = state.manual_target_queue.popleft()
        state.manual_target_names.discard(repo_identity(repo_data.get("name", "")))
        return repo_data


def has_manual_targets() -> bool:
    with state.manual_target_mutex:
        return bool(state.manual_target_queue)


def handle_target_prompt(prompt_text: str) -> None:
    cleaned = prompt_text.strip()
    if not cleaned:
        return

    log_msg("[bold cyan][AI] Parsing repository targets from prompt...[/]")

    from shared.scanner_targets import resolve_repo_targets
    from shared.ai_policy import load_pol
    repo_targets = resolve_repo_targets(
        cleaned,
        os.environ.get("GROQ_API_KEY", "").strip(),
        state.AI_POL or load_pol(log_fn=log_msg),
        log_msg,
    )

    if not repo_targets:
        log_msg("[bold red][!] No valid GitHub repositories found in the submitted prompt.[/]")
        return

    inserted = sum(1 for r in repo_targets if queue_manual_target(r))
    if inserted > 1:
        log_msg(f"[bold green][+] Added {inserted} repositories from AI prompt.[/]")


def submit_target_prompt(prompt_text: str) -> None:
    if not prompt_text.strip():
        return
    threading.Thread(target=handle_target_prompt, args=(prompt_text,), daemon=True).start()
