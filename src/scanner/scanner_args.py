# ---------------------------------------------------------------------------------- #
#                            Part of the X3r0Day project.                            #
# ---------------------------------------------------------------------------------- #


import argparse
import os
import threading
from collections import deque

from shared.api_signatures import build_api_signatures
from . import scanner_state as state


def parse_args():
    parser = argparse.ArgumentParser(description="Scan discovered repositories for leaked secrets.")
    parser.add_argument("--max-threads", type=int, help="Number of concurrent scanning workers.")
    parser.add_argument("--history-depth", type=int, help="Number of recent commits to scan.")
    parser.add_argument("--scan-heroku-keys", action="store_true", help="Enable Heroku key pattern scanning.")
    parser.add_argument("--no-commit-history", action="store_true", help="Disable commit history scanning.")
    parser.add_argument("--prefer-proxy", action="store_true", help="Try proxy download before direct IP.")
    parser.add_argument("--up-proxy", action="store_true", help="Persist proxy updates to live_proxies.txt.")
    return parser.parse_args()


def apply_runtime_overrides(args) -> None:
    if os.environ.get("X3D_UP_PROXY", "").strip().lower() in {"1", "true", "yes", "y", "on"}:
        state.UPDATE_PROXY_FILE = True
    if args.max_threads is not None:
        state.MAX_THREADS = max(1, args.max_threads)
    if args.history_depth is not None:
        state.MAX_HISTORY_DEPTH = max(1, args.history_depth)
    if args.scan_heroku_keys:
        state.SCAN_HEROKU_KEYS = True
    if args.no_commit_history:
        state.SCAN_COMMIT_HISTORY = False
    if args.prefer_proxy:
        state.PREFER_PROXY = True
    if args.up_proxy:
        state.UPDATE_PROXY_FILE  = True


def reset_runtime_state(api_signatures_ref: list) -> None:
    api_signatures_ref[0] = build_api_signatures(include_heroku=state.SCAN_HEROKU_KEYS)

    state.pause_event = threading.Event()
    state.pause_event.set()
    state.exit_prog = False
    state.active_proxies = []

    state.is_typing_url = False
    state.input_buffer = ""
    state.manual_target_queue = deque()
    state.manual_target_names = set()

    state.available_thread_tags = deque([f"Thread-{i+1}" for i in range(state.MAX_THREADS)])
    state.thread_dashboard = {
        f"Thread-{i+1}": {
            "target": "Idle",
            "action": "-",
            "active_ip": "-",
            "clock_start": 0,
            "dl_bytes": 0,
        }
        for i in range(state.MAX_THREADS)
    }
    state.log_history  = deque(maxlen=6)
    state.fail_history = deque(maxlen=10)
    state.leak_history = deque(maxlen=10)
    state.scoreboard   = {"total": 0, "scanned": 0, "leaks": 0, "clean": 0, "failed": 0, "remaining": 0}