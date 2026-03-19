# ---------------------------------------------------------------------------------- #
#                            Part of the X3r0Day project.                            #
# ---------------------------------------------------------------------------------- #


import json
from typing import List, Optional

from . import scanner_state as state
from .scanner_network import download_github_url


def normalize_branch_name(branch) -> Optional[str]:
    if not isinstance(branch, str):
        return None
    b = branch.strip().strip("/")
    if b.startswith("refs/heads/"):
        b = b[len("refs/heads/"):]
    return b or None


def fetch_repo_metadata(repo_name: str, thread_tag: str):
    url = f"https://api.github.com/repos/{repo_name}"
    payload, ip = download_github_url(url, thread_tag, "Resolving Repo Metadata")
    if not payload or payload in (b"FAILED", b"TOO_LARGE", b"FORBIDDEN_SKIP"):
        return None, ip
    try:
        meta = json.loads(payload.decode("utf-8", errors="ignore"))
    except Exception:
        return None, ip
    return (meta if isinstance(meta, dict) else None), ip


def resolve_default_branch(repo_data: dict, thread_tag: str) -> Optional[str]:
    stored = normalize_branch_name(repo_data.get("default_branch"))
    if stored:
        return stored
    repo_name = repo_data.get("name", "").strip()
    if not repo_name:
        return None
    meta, _ = fetch_repo_metadata(repo_name, thread_tag)
    if not meta:
        return None
    resolved = normalize_branch_name(meta.get("default_branch"))
    if resolved:
        repo_data["default_branch"] = resolved
    return resolved


def build_archive_branch_candidates(repo_data: dict, thread_tag: str) -> List[str]:
    seen: set = set()
    out: list = []

    def add(b):
        nb = normalize_branch_name(b)
        if nb and nb not in seen:
            seen.add(nb)
            out.append(nb)

    add(repo_data.get("default_branch"))
    add(resolve_default_branch(repo_data, thread_tag))
    for fb in state.DEFAULT_BRANCH_FALLBACKS:
        add(fb)
    return out