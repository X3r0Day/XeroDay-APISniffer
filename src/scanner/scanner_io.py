# ---------------------------------------------------------------------------------- #
#                            Part of the X3r0Day project.                            #
# ---------------------------------------------------------------------------------- #


import json
import os
import tempfile
from typing import Optional

from . import scanner_state as state


def write_json_snapshot(payload: list, filepath: str) -> None:
    directory = os.path.dirname(os.path.abspath(filepath)) or "."
    file_prefix = f".{os.path.basename(filepath)}."
    fd, temp_path = tempfile.mkstemp(prefix=file_prefix, suffix=".tmp", dir=directory)
    
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=4)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp_path, filepath)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def ensure_json_list_file(filepath: str) -> None:
    if not os.path.exists(filepath):
        write_json_snapshot([], filepath)


def repo_identity(repo_name: str) -> str:
    return (repo_name or "").strip().lower()


def dump_json_safely(filepath: str, json_blob: dict) -> None:
    with state.io_mutex:
        disk_content: list = []
        if os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as fh:
                    disk_content = json.load(fh)
                    if not isinstance(disk_content, list):
                        disk_content = []
            except json.JSONDecodeError:
                disk_content = []
                
        repo_key = repo_identity(json_blob.get("repo") or json_blob.get("name") or "")
        replaced = False

        if repo_key:
            for idx, existing in enumerate(disk_content):
                if not isinstance(existing, dict):
                    continue
                existing_key = repo_identity(existing.get("repo") or existing.get("name") or "")
                if existing_key == repo_key:
                    disk_content[idx] = json_blob
                    replaced = True
                    break
                    
        if not replaced:
            disk_content.append(json_blob)

        write_json_snapshot(disk_content, filepath)


def remove_from_queue(target_repo: str) -> None:
    with state.io_mutex:
        if not os.path.exists(state.QUEUE_JSON):
            return
        try:
            with open(state.QUEUE_JSON, "r", encoding="utf-8") as fh:
                current_queue = json.load(fh)
            fresh_queue = [r for r in current_queue if r.get("name") != target_repo]
            write_json_snapshot(fresh_queue, state.QUEUE_JSON)
        except Exception:
            pass
            