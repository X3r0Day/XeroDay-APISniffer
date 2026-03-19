# ---------------------------------------------------------------------------------- #
#                            Part of the X3r0Day project.                            #
# ---------------------------------------------------------------------------------- #


import io
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import zipfile
from typing import List, Optional, Tuple, Union

from . import scanner_state as state
from shared.scanner_matcher import regex_grep_text as _regex_grep
from .scanner_network import (
    ScanInterrupted,
    check_pause,
    download_github_url,
    raise_if_exit_requested,
)
from .scanner_ui import update_thread_board


def should_scan_filename(path: str) -> Tuple[bool, str]:
    lowered = path.lower()
    clean = os.path.basename(lowered)
    should = lowered.endswith(state.TARGET_EXTENSIONS) or clean in state.EXACT_FILENAMES
    return should, clean


def scan_zip_bytes(
    zip_buffer: bytes, thread_tag: str, active_ip: str,
    api_signatures: dict,
) -> Tuple[List[dict], Optional[str]]:
    caught = []
    last_ui = 0
    total_bytes = 0

    with zipfile.ZipFile(io.BytesIO(zip_buffer)) as zf:
        for info in zf.infolist():
            raise_if_exit_requested()
            check_pause(thread_tag, "[magenta]Scanning File...[/]", active_ip)
            if info.is_dir() or info.file_size > state.FAT_FILE_LIMIT:
                continue
            total_bytes += info.file_size
            if total_bytes > state.MAX_DOWNLOAD_SIZE_BYTES:
                return caught, "TOO_LARGE"

            ok, fname = should_scan_filename(info.filename)
            if not ok:
                continue

            if time.time() - last_ui > 0.1:
                short = fname[:25] + ".." if len(fname) > 25 else fname
                update_thread_board(thread_tag, action=f"[magenta]Scan: {short}[/]", active_ip=active_ip)
                last_ui = time.time()

            try:
                with zf.open(info) as fh:
                    raw = fh.read().decode("utf-8", errors="ignore")
                caught.extend(_regex_grep(raw, info.filename, api_signatures, state.LINE_CUTOFF))
            except Exception:
                pass

    return caught, None


def scan_tar_bytes(
    tar_buffer: bytes, thread_tag: str, active_ip: str,
    api_signatures: dict,
) -> Tuple[List[dict], Optional[str]]:
    caught = []
    last_ui = 0
    total_bytes = 0

    with tarfile.open(fileobj=io.BytesIO(tar_buffer), mode="r:*") as tf:
        for member in tf.getmembers():
            raise_if_exit_requested()
            check_pause(thread_tag, "[magenta]Scanning File...[/]", active_ip)
            if not member.isfile() or member.size > state.FAT_FILE_LIMIT:
                continue
            total_bytes += member.size
            if total_bytes > state.MAX_DOWNLOAD_SIZE_BYTES:
                return caught, "TOO_LARGE"

            ok, fname = should_scan_filename(member.name)
            if not ok:
                continue

            if time.time() - last_ui > 0.1:
                short = fname[:25] + ".." if len(fname) > 25 else fname
                update_thread_board(thread_tag, action=f"[magenta]Scan: {short}[/]", active_ip=active_ip)
                last_ui = time.time()

            try:
                fh = tf.extractfile(member)
                if fh is None:
                    continue
                raw = fh.read().decode("utf-8", errors="ignore")
                caught.extend(_regex_grep(raw, member.name, api_signatures, state.LINE_CUTOFF))
            except Exception:
                pass

    return caught, None


def scan_repo_dir(
    repo_dir: str, thread_tag: str, active_ip: str,
    api_signatures: dict,
) -> Tuple[List[dict], Optional[str]]:
    caught = []
    last_ui = 0
    total_bytes = 0

    for root, dirs, files in os.walk(repo_dir):
        raise_if_exit_requested()
        if ".git" in dirs:
            dirs.remove(".git")
        for filename in files:
            raise_if_exit_requested()
            file_path = os.path.join(root, filename)
            rel_path = os.path.relpath(file_path, repo_dir)
            ok, fname = should_scan_filename(rel_path)
            if not ok:
                continue
            try:
                file_size = os.path.getsize(file_path)
            except OSError:
                continue
            if file_size > state.FAT_FILE_LIMIT:
                continue
            total_bytes += file_size
            if total_bytes > state.MAX_DOWNLOAD_SIZE_BYTES:
                return caught, "TOO_LARGE"

            if time.time() - last_ui > 0.1:
                short = fname[:25] + ".." if len(fname) > 25 else fname
                update_thread_board(thread_tag, action=f"[magenta]Scan: {short}[/]", active_ip=active_ip)
                last_ui = time.time()

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                    raw = fh.read()
                caught.extend(_regex_grep(raw, rel_path, api_signatures, state.LINE_CUTOFF))
            except Exception:
                pass

    return caught, None


def clone_repo_git(
    repo_name: str, branch: str, thread_tag: str,
) -> Tuple[Optional[str], Optional[str]]:
    update_thread_board(thread_tag, action="[cyan]Cloning (git)...[/]", active_ip="git", dl_bytes=0)
    temp_dir = tempfile.mkdtemp(prefix="x3d_git_")
    repo_url = f"https://github.com/{repo_name}.git"
    cmd = ["git", "clone", "--depth", "1", "--single-branch", "--branch", branch, repo_url, temp_dir]

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_LFS_SKIP_SMUDGE"] = "1"

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
            env=env,
            timeout=120,
            text=True,
        )
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return None, "git-exception"

    if result.returncode != 0:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return None, (result.stderr or "git-failed").strip()

    return temp_dir, None


def build_archive_url_candidates(repo_name: str, branch: str) -> List[Tuple[str, str, str]]:
    """Return (label, url, kind) tuples to try in order."""
    return [
        ("ZIP (codeload)", f"https://codeload.github.com/{repo_name}/zip/refs/heads/{branch}", "zip"),
        ("ZIP (archive)",  f"https://github.com/{repo_name}/archive/refs/heads/{branch}.zip", "zip"),
        ("ZIP (zipball)",  f"https://api.github.com/repos/{repo_name}/zipball/{branch}", "zip"),
        ("TAR (tarball)",  f"https://api.github.com/repos/{repo_name}/tarball/{branch}", "tar"),
    ]


def download_repo_archive(
    repo_name: str, branch: str, thread_tag: str,
) -> Tuple[Optional[bytes], Optional[str], str]:
    for label, url, kind in build_archive_url_candidates(repo_name, branch):
        payload, current_ip = download_github_url(url, thread_tag, f"Downloading {label}")
        if payload in (b"TOO_LARGE", b"FORBIDDEN_SKIP"):
            return payload, kind, current_ip
        if payload is None or payload == b"FAILED":
            continue
        if isinstance(payload, bytes):
            return payload, kind, current_ip
    return None, None, "Direct IP"
