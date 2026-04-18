# ---------------------------------------------------------------------------------- #
#                            Part of the X3r0Day project.                            #
#              You are free to use, modify, and redistribute this code,              #
#          provided proper credit is given to the original project X3r0Day.          #
# ---------------------------------------------------------------------------------- #

#################################################################################################################################################
#    So This code basically scans the repos and in `recent_repos.json` file, and it uses proxy list if github API blocks/ratelimits your IP.    #
#################################################################################################################################################


# ---------------------------------------------------------------------------------- #
#                                   DISCLAIMER                                       #
# ---------------------------------------------------------------------------------- #
# This tool is part of the X3r0Day Framework and is intended for educational         #
# security research, and defensive analysis purposes only.                           #
#                                                                                    #
# The script queries publicly available GitHub repository metadata and stores it     #
# locally for further analysis. It does not exploit, access, or modify any system.   #
#                                                                                    #
# Users are solely responsible for how this software is used. The authors of the     #
# X3r0Day project do not encourage or condone misuse, unauthorized access, or any    #
# activity that violates applicable laws, regulations, or the terms of service of    #
# any platform.                                                                      #
#                                                                                    #
# Always respect platform policies, rate limits, and the privacy of developers.      #
# If you discover sensitive information or exposed credentials during research,      #
# follow responsible disclosure practices and notify the affected parties by         #
# opening **Issues**                                                                 #
#                                                                                    #
# By using this software, you acknowledge that you understand these conditions and   #
# accept full responsibility for your actions.                                       #
#                                                                                    #
# Project: X3r0Day Framework                                                         #
# Tool:    X3r0Day's API Sniffer                                                     #
# Author: XeroDay                                                                    #
# ---------------------------------------------------------------------------------- #


#--------------------------------------#
#     Error Codes and its meanings     #
# -------------------------------------#
#   422 = No more results after that   #
#   200 = OKAY/GOOD                    #
#   403 = Access Denied                #
#   404 = Not Found/Empty Repo)        #
# ------------------------------------ #

"""
APIScanner.py  —  Entry point + per-repo scan logic.

src/scanner/
    scanner_state.py            Global constants + mutable runtime state
    scanner_args.py             CLI parsing, overrides, state reset
    scanner_signals.py          OS signal handlers
    scanner_token.py            GitHub token prompt
    scanner_branch.py           Branch name resolution
    scanner_proxy.py            Proxy list I/O and health tracking
    scanner_io.py               Atomic JSON persistence
    scanner_network.py          HTTP download + proxy-fallback loop
    scanner_archive.py          ZIP / TAR / git archive handling
    scanner_ui.py               Dashboard state + log queues
    scanner_keyboard.py         Background keyboard monitor
    scanner_targets_live.py     Runtime AI-driven target injection
"""

import json
import re
import shutil
import tarfile
import threading
import time
import zipfile
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import List, Optional, Union

from rich.console import Console
from rich.live import Live

from scanner import scanner_state as state
from scanner.scanner_archive import (
    clone_repo_git,
    download_repo_archive,
    scan_repo_dir,
    scan_tar_bytes,
    scan_zip_bytes,
)
from scanner.scanner_args import apply_runtime_overrides, parse_args, reset_runtime_state
from scanner.scanner_branch import build_archive_branch_candidates
from scanner.scanner_io import dump_json_safely, ensure_json_list_file, remove_from_queue
from scanner.scanner_keyboard import keyboard_monitor
from scanner.scanner_network import (
    ScanInterrupted,
    check_pause,
    download_github_url,
    interruptible_sleep,
    raise_if_exit_requested,
)
from scanner.scanner_proxy import read_proxies, save_good_proxies, set_active_proxies
from scanner.scanner_signals import install_signal_handlers, request_shutdown
from scanner.scanner_targets_live import has_manual_targets, pop_manual_target
from scanner.scanner_token import prompt_github_token
from scanner.scanner_ui import bump_score, log_dead_repo, log_loot, log_msg, update_thread_board
from shared.ai_policy import load_pol
from shared.scanner_dashboard import paint_dashboard as render_scanner_dashboard
from shared.scanner_matcher import regex_grep_text as grep_scanner_text

console = Console()
API_SIGNATURES: dict = {}


def paint_dashboard():
    return render_scanner_dashboard(
        state.ui_mutex,
        state.pause_event,
        state.scoreboard,
        state.thread_dashboard,
        len(API_SIGNATURES),
        state.is_typing_url,
        state.input_buffer,
        state.log_history,
        state.leak_history,
        state.MAX_DOWNLOAD_SIZE_BYTES,
    )


def dedupe_by_secs(findings: List[dict]) -> List[dict]:
    unique_findings = []
    seen_secrets = set()

    for finding in findings:
        secret = finding.get("secret")
        if secret in seen_secrets:
            continue
        seen_secrets.add(secret)
        unique_findings.append(finding)

    return unique_findings


def scan_repo_via_git_fallback(
    repo_name: str,
    branch: str,
    thread_tag: str,
    api_signatures: dict,
) -> tuple[List[dict], Optional[str]]:
    git_dir, _git_err = clone_repo_git(repo_name, branch, thread_tag)
    if not git_dir:
        return [], "FAILED"

    try:
        return scan_repo_dir(git_dir, thread_tag, "git", api_signatures)
    finally:
        shutil.rmtree(git_dir, ignore_errors=True)


# This scans one repository end to end and returns the final payload used for persistence.
def dissect_repo_memory(repo_data: dict, thread_tag: str) -> dict:
    raise_if_exit_requested()
    start_time = time.time()
    target_repo = repo_data.get("name", "Unknown_Repo")
    
    update_thread_board(thread_tag, target=target_repo, action="[yellow]Initializing[/]", active_ip="-", reset_timer=True, dl_bytes=0)
    
    archive_payload: Optional[Union[bytes, str]] = None
    archive_kind: Optional[str] = None
    successful_ip = "Direct IP"
    branch_candidates = build_archive_branch_candidates(repo_data, thread_tag)
    successful_branch = branch_candidates[0] if branch_candidates else state.DEFAULT_BRANCH_FALLBACKS[0]
    

    # Try the known default branch first, then fall back to common names.
    for git_branch in branch_candidates:
        raise_if_exit_requested()
        archive_payload, archive_kind, current_ip = download_repo_archive(target_repo, git_branch, thread_tag)
        successful_ip = current_ip

        # Stop early if the direct IP is consistently forbidden.
        if archive_payload == b"FORBIDDEN_SKIP":
            break

        if archive_payload == b"TOO_LARGE":
            break

        if isinstance(archive_payload, bytes) and archive_payload not in [b"FAILED"]:
            successful_branch = git_branch
            break

        if archive_payload is None or archive_payload == b"FAILED":
            git_dir, _git_err = clone_repo_git(target_repo, git_branch, thread_tag)
            if git_dir:
                archive_payload = git_dir
                archive_kind = "git"
                successful_ip = "git"
                successful_branch = git_branch
                break
            
    elapsed = round(time.time() - start_time, 2)

    if archive_payload == b"FORBIDDEN_SKIP":
        log_dead_repo(target_repo, "Forbidden 403 (Skipped)", successful_ip, elapsed)
        bump_score("failed"); bump_score("scanned")
        return {"repo": target_repo, "status": "failed", "reason": "Forbidden 403 (Skipped)", "ip": successful_ip, "time_taken": elapsed}

    if archive_payload == b"TOO_LARGE":
        log_dead_repo(target_repo, "Skipped (Over 20MB Limit)", successful_ip, elapsed)
        bump_score("failed"); bump_score("scanned")
        return {"repo": target_repo, "status": "failed", "reason": "Over 20MB Limit", "ip": successful_ip, "time_taken": elapsed}

    if not archive_payload or archive_payload == b"FAILED":
        crash_reason = "Connection Stalled / Exhausted" if archive_payload == b"FAILED" else "404 Not Found"
        log_dead_repo(target_repo, crash_reason, successful_ip, elapsed)
        bump_score("failed"); bump_score("scanned")
        return {"repo": target_repo, "status": "failed", "reason": crash_reason, "ip": successful_ip, "time_taken": elapsed}

    update_thread_board(thread_tag, action="[magenta]Extracting...[/]", active_ip=successful_ip, dl_bytes=0)
    caught_keys = []
    scan_status = None
    git_dir = archive_payload if archive_kind == "git" else None

    try:
        if archive_kind == "zip" and isinstance(archive_payload, bytes):
            caught_keys, scan_status = scan_zip_bytes(archive_payload, thread_tag, successful_ip, API_SIGNATURES)
        elif archive_kind == "tar" and isinstance(archive_payload, bytes):
            caught_keys, scan_status = scan_tar_bytes(archive_payload, thread_tag, successful_ip, API_SIGNATURES)
        elif archive_kind == "git" and isinstance(archive_payload, str):
            caught_keys, scan_status = scan_repo_dir(archive_payload, thread_tag, successful_ip, API_SIGNATURES)
        else:
            scan_status = "FAILED"
    except zipfile.BadZipFile:
        if archive_kind != "git":
            log_msg(f"[yellow][!] Invalid ZIP payload for {target_repo}. Falling back to git clone.[/]")
            caught_keys, scan_status = scan_repo_via_git_fallback(
                target_repo,
                successful_branch,
                thread_tag,
                API_SIGNATURES,
            )
            if scan_status != "FAILED":
                successful_ip = "git"
        else:
            log_dead_repo(target_repo, "Corrupted Zip", successful_ip, round(time.time() - start_time, 2))
            bump_score("failed"); bump_score("scanned")
            return {"repo": target_repo, "status": "failed", "reason": "BadZipFile", "ip": successful_ip, "time_taken": round(time.time() - start_time, 2)}
    except tarfile.TarError:
        if archive_kind != "git":
            log_msg(f"[yellow][!] Invalid TAR payload for {target_repo}. Falling back to git clone.[/]")
            caught_keys, scan_status = scan_repo_via_git_fallback(
                target_repo,
                successful_branch,
                thread_tag,
                API_SIGNATURES,
            )
            if scan_status != "FAILED":
                successful_ip = "git"
        else:
            log_dead_repo(target_repo, "Corrupted Tar", successful_ip, round(time.time() - start_time, 2))
            bump_score("failed"); bump_score("scanned")
            return {"repo": target_repo, "status": "failed", "reason": "BadTarFile", "ip": successful_ip, "time_taken": round(time.time() - start_time, 2)}
    finally:
        if git_dir:
            shutil.rmtree(git_dir, ignore_errors=True)

    if scan_status == "TOO_LARGE":
        log_dead_repo(target_repo, "Skipped (Over 20MB Limit)", successful_ip, round(time.time() - start_time, 2))
        bump_score("failed"); bump_score("scanned")
        return {"repo": target_repo, "status": "failed", "reason": "Over 20MB Limit", "ip": successful_ip, "time_taken": round(time.time() - start_time, 2)}
    if scan_status == "FAILED":
        log_dead_repo(target_repo, "Scan Failed", successful_ip, round(time.time() - start_time, 2))
        bump_score("failed"); bump_score("scanned")
        return {"repo": target_repo, "status": "failed", "reason": "Scan Failed", "ip": successful_ip, "time_taken": round(time.time() - start_time, 2)}

    # Scan recent commit history as patch text as well.
    # For example, a key removed from the working tree can still appear in an older commit.
    if state.SCAN_COMMIT_HISTORY:
        atom_url = f"https://github.com/{target_repo}/commits/{successful_branch}.atom"
        atom_bytes, current_ip = download_github_url(atom_url, thread_tag, "Downloading History")
        
        if atom_bytes and atom_bytes not in[b"FAILED", b"TOO_LARGE", b"NOT_FOUND", b"FORBIDDEN_SKIP"]:
            atom_text = atom_bytes.decode('utf-8', errors='ignore')
            extracted_shas = re.findall(r"Commit/([a-f0-9]{40})", atom_text)
            
            unique_shas =[]
            seen_shas = set()
            for sha in extracted_shas:
                if sha not in seen_shas:
                    seen_shas.add(sha)
                    unique_shas.append(sha)
            
            commit_shas = unique_shas[:state.MAX_HISTORY_DEPTH]
            
            for idx, sha in enumerate(commit_shas):
                raise_if_exit_requested()
                patch_url = f"https://github.com/{target_repo}/commit/{sha}.patch"
                patch_action_str = f"DL Patch {idx+1}/{len(commit_shas)}"
                patch_bytes, patch_ip = download_github_url(patch_url, thread_tag, patch_action_str)
                
                if patch_bytes and patch_bytes not in[b"FAILED", b"TOO_LARGE", b"NOT_FOUND", b"FORBIDDEN_SKIP"]:
                    patch_text = patch_bytes.decode('utf-8', errors='ignore')
                    check_pause(thread_tag, f"[magenta]Scan Patch {idx+1}/{len(commit_shas)}[/]", patch_ip)
                    
                    new_keys = grep_scanner_text(patch_text, f"Commit {sha[:7]}", API_SIGNATURES, state.LINE_CUTOFF)
                    caught_keys.extend(new_keys)

    # Deduplicate findings, log results, update scores, and return the final scan summary
    bump_score("scanned")
    elapsed = round(time.time() - start_time, 2)
    
    if caught_keys:
        # Deduplicate by secret value so the same token does not flood the report.
        # For example, the same key may appear in both a source file and a patch.
        unique_findings = dedupe_by_secs(caught_keys)

        bump_score("leaks")
        files_with_hits = sorted({k["file"] for k in unique_findings})
        found_api_types = {k["type"] for k in unique_findings}
        repo_stars = repo_data.get("stars", 0)
        log_loot(target_repo, files_with_hits, len(unique_findings), found_api_types, successful_ip, elapsed, repo_stars)
        
        return {"repo": target_repo, "url": repo_data.get("url"), "status": "leaked", "total_secrets": len(unique_findings), "critical": repo_stars > 0, "stars": repo_stars, "findings": unique_findings, "ip": successful_ip, "time_taken": elapsed}
    else:
        bump_score("clean")
        log_msg(f"[green][+] Clean:[/] {target_repo} [dim]({elapsed}s)[/]")
        return {"repo": target_repo, "url": repo_data.get("url"), "status": "clean", "ip": successful_ip, "time_taken": elapsed}


def thread_runner(repo_data: dict):
    with state.tag_mutex:
        thread_tag = state.available_thread_tags.popleft() if state.available_thread_tags else "Thread-Unknown"

    try:
        return dissect_repo_memory(repo_data, thread_tag)
    except ScanInterrupted:
        raise
    except Exception:
        safe_name = repo_data.get("name", "Unknown_Repo")
        log_dead_repo(safe_name, "Critical Thread Crash", "-", 0.0)
        bump_score("failed"); bump_score("scanned")
        return {"repo": safe_name, "status": "failed", "reason": "Thread Crash", "ip": "-", "time_taken": 0.0}
    finally:
        update_thread_board(thread_tag, target="Idle", action="-", active_ip="-", reset_timer=True, dl_bytes=0)
        with state.tag_mutex:
            if thread_tag != "Thread-Unknown":
                state.available_thread_tags.append(thread_tag)

def main() -> None:
    global API_SIGNATURES
    keyboard_thread = None
    
    prompt_github_token()
    
    api_ref = [{}]
    reset_runtime_state(api_ref)
    API_SIGNATURES = api_ref[0]
    
    state.AI_POL = load_pol(log_fn=console.print)
    ensure_json_list_file(state.LEAKS_JSON)
    ensure_json_list_file(state.DEAD_TARGETS_JSON)
    ensure_json_list_file(state.BORING_REPOS_JSON)

    try:
        with open(state.QUEUE_JSON, "r", encoding="utf-8") as file_ptr:
            queued_targets = json.load(file_ptr)
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/] {state.QUEUE_JSON} not found. Run the fetcher first.")
        return

    if not queued_targets:
        console.print("[bold yellow]Queue is empty.[/] No new repositories to scan.")
        return

    set_active_proxies(read_proxies())
    state.scoreboard["total"] = len(queued_targets)
    state.scoreboard["remaining"] = len(queued_targets)
    
    keyboard_thread = threading.Thread(target=keyboard_monitor, daemon=True)
    keyboard_thread.start()
    log_msg("[bold green]Scanner initiated. Press SPACE to Pause/Resume or I for AI target insertion.[/]")

    try:
        with Live(get_renderable=paint_dashboard, refresh_per_second=6, screen=True) as live_screen:
            with ThreadPoolExecutor(max_workers=state.MAX_THREADS) as thread_pool:
                pending_tasks = set()
                idle_shutdown_deadline = None
                for target in queued_targets:
                    pending_tasks.add(thread_pool.submit(thread_runner, target))
                
                while pending_tasks or has_manual_targets() or state.is_typing_url or idle_shutdown_deadline is not None:
                    if state.exit_prog:
                        break
                    while True:
                        new_t = pop_manual_target()
                        if new_t is None:
                            break
                        pending_tasks.add(thread_pool.submit(thread_runner, new_t))
                        idle_shutdown_deadline = None
                        
                    if pending_tasks:
                        done_tasks, pending_tasks = wait(pending_tasks, timeout=0.25, return_when=FIRST_COMPLETED)
                        
                        for finished_task in done_tasks:
                            try:
                                task_outcome = finished_task.result()
                                if task_outcome is None:
                                    continue
                                if task_outcome["status"] == "leaked": dump_json_safely(state.LEAKS_JSON, task_outcome)
                                elif task_outcome["status"] == "failed": dump_json_safely(state.DEAD_TARGETS_JSON, task_outcome)
                                elif task_outcome["status"] == "clean": dump_json_safely(state.BORING_REPOS_JSON, task_outcome)
                                    
                                remove_from_queue(task_outcome.get("repo"))
                                bump_score("remaining", -1)
                            except ScanInterrupted:
                                continue
                            except Exception:
                                pass
                        
                        live_screen.update(paint_dashboard())
                        if state.exit_prog:
                            break
                        if pending_tasks or has_manual_targets() or state.is_typing_url:
                            idle_shutdown_deadline = None
                        else:
                            idle_shutdown_deadline = time.time() + 1.5
                    else:
                        if state.is_typing_url or has_manual_targets():
                            idle_shutdown_deadline = None
                            if not interruptible_sleep(0.1):
                                break
                        elif idle_shutdown_deadline is None:
                            idle_shutdown_deadline = time.time() + 1.5
                            log_msg("[bold yellow][!] Queue drained. Waiting briefly for AI target prompts...[/]")
                            if not interruptible_sleep(0.1):
                                break
                        elif time.time() >= idle_shutdown_deadline:
                            break
                        else:
                            if not interruptible_sleep(0.1):
                                break

        if state.exit_prog:
            console.print("\n[bold yellow]Scanner stopped by user. Remaining targets stayed in the queue.[/]")
        else:
            console.print("\n[bold green]Queue Exhausted. Scan Complete.[/]")
    except KeyboardInterrupt:
        request_shutdown()
        console.print("\n[bold yellow]Scanner stop requested. Waiting for active threads to unwind...[/]")
        
    finally:
        state.exit_prog = True
        if state.pause_event:
            state.pause_event.set()
        if keyboard_thread is not None:
            keyboard_thread.join(timeout=1.0)
        save_good_proxies(console)

if __name__ == "__main__":
    install_signal_handlers()
    apply_runtime_overrides(parse_args())
    main()
