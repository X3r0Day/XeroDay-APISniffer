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




import argparse
import requests, random, json, io, os, sys, zipfile, re, time, threading, signal, tempfile

from collections import deque
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from typing import List, Optional, Tuple

from rich.live import Live
from rich.console import Console
from shared.api_signatures import build_api_signatures
from shared.scanner_dashboard import paint_dashboard as render_scanner_dashboard
from shared.scanner_matcher import regex_grep_text as grep_scanner_text
from shared.scanner_targets import resolve_repo_targets as resolve_scanner_targets
from shared.ai_policy import load_pol


QUEUE_JSON = "recent_repos.json"
LEAKS_JSON = "leaked_keys.json"
DEAD_TARGETS_JSON = "failed_repos.json"
BORING_REPOS_JSON = "clean_repos.json"
PROXY_LIST_TXT = "live_proxies.txt"
MAX_THREADS = 15          
DEFAULT_BRANCH_FALLBACKS = ("main", "master")

SCAN_HEROKU_KEYS = False                 
SCAN_COMMIT_HISTORY = True           
MAX_HISTORY_DEPTH = 10               

FAT_FILE_LIMIT = 10 * 1024 * 1024  
LINE_CUTOFF = 2000                       

# 5s to connect, 15s to wait for the first byte from GitHub's zip downloader
NET_TIMEOUTS = (5.0, 15.0)              

# This is for idle timeout and kills the connection if >15 seconds
IDLE_STALL_TIMEOUT_SEC = 15.0 
MAX_DOWNLOAD_SIZE_BYTES = 20 * 1024 * 1024  
PROXY_TIMEOUTS = (15.0, 20.0)
PREFER_PROXY = False

TARGET_EXTENSIONS = (
    ".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yml", ".yaml", ".xml", 
    ".txt", ".env", ".ini", ".conf", ".config", ".sh", ".bash", ".php", 
    ".java", ".c", ".cpp", ".h", ".hpp", ".cs", ".go", ".rb", ".swift", 
    ".kt", ".kts", ".rs", ".sql", ".md", ".toml", ".properties", "tfvars",
    ".tf", ".hcl", ".gradle", ".plist", ".cfg", ".envrc", ".lua", ".dart",
    ".zsh", ".fish", ".bat", ".cmd", ".psm1", "ps1"
)
EXACT_FILENAMES = ("dockerfile", "makefile", "gemfile")

# This user agent is used because GitHub was less likely to return 403 for archive requests.
SPOOFED_USER_AGENT = "Wget/1.21.2"

API_SIGNATURES = build_api_signatures(include_heroku=SCAN_HEROKU_KEYS)

console = Console()
ui_mutex = threading.Lock()
io_mutex = threading.Lock() 

tag_mutex = threading.Lock()

pause_event = None
exit_prog = False
active_proxies = []
good_proxies = set()
good_proxy_lock = threading.Lock()
proxy_fail = {}
proxy_lock = threading.Lock()
PROXY_FAIL_LIMIT = 1

# To check if new target should be injected
is_typing_url = False
input_buffer = ""
manual_target_queue = deque()
manual_target_names = set()

available_thread_tags = deque()
thread_dashboard = {}
log_history = deque(maxlen=6)
fail_history = deque(maxlen=10)
leak_history = deque(maxlen=10)
scoreboard = {"total": 0, "scanned": 0, "leaks": 0, "clean": 0, "failed": 0, "remaining": 0}
manual_target_mutex = threading.Lock()
AI_POL = None


class ScanInterrupted(Exception):
    pass


def parse_args():
    parser = argparse.ArgumentParser(description="Scan discovered repositories for leaked secrets.")
    parser.add_argument("--max-threads", type=int, help="Number of concurrent scanning workers.")
    parser.add_argument("--history-depth", type=int, help="Number of recent commits to scan.")
    parser.add_argument("--scan-heroku-keys", action="store_true", help="Enable Heroku key pattern scanning.")
    parser.add_argument("--no-commit-history", action="store_true", help="Disable commit history scanning.")
    parser.add_argument("--prefer-proxy", action="store_true", help="Try proxy download before direct IP.")
    return parser.parse_args()


def apply_runtime_overrides(args) -> None:
    global MAX_THREADS, MAX_HISTORY_DEPTH, SCAN_HEROKU_KEYS, SCAN_COMMIT_HISTORY, PREFER_PROXY

    if args.max_threads is not None:
        MAX_THREADS = max(1, args.max_threads)
    if args.history_depth is not None:
        MAX_HISTORY_DEPTH = max(1, args.history_depth)
    if args.scan_heroku_keys:
        SCAN_HEROKU_KEYS = True
    if args.no_commit_history:
        SCAN_COMMIT_HISTORY = False
    if args.prefer_proxy:
        PREFER_PROXY = True


def reset_runtime_state() -> None:
    global API_SIGNATURES, pause_event, exit_prog, active_proxies
    global is_typing_url, input_buffer, manual_target_queue, manual_target_names
    global available_thread_tags, thread_dashboard
    global log_history, fail_history, leak_history, scoreboard

    API_SIGNATURES = build_api_signatures(include_heroku=SCAN_HEROKU_KEYS)

    pause_event = threading.Event()
    pause_event.set()
    exit_prog = False
    active_proxies = []

    is_typing_url = False
    input_buffer = ""
    manual_target_queue = deque()
    manual_target_names = set()

    available_thread_tags = deque([f"Thread-{i+1}" for i in range(MAX_THREADS)])
    thread_dashboard = {
        f"Thread-{i+1}": {
            "target": "Idle",
            "action": "-",
            "active_ip": "-",
            "clock_start": 0,
            "dl_bytes": 0,
        }
        for i in range(MAX_THREADS)
    }
    log_history = deque(maxlen=6)
    fail_history = deque(maxlen=10)
    leak_history = deque(maxlen=10)
    scoreboard = {"total": 0, "scanned": 0, "leaks": 0, "clean": 0, "failed": 0, "remaining": 0}


def write_json_snapshot(payload: list, filepath: str) -> None:
    directory = os.path.dirname(os.path.abspath(filepath)) or "."
    file_prefix = f".{os.path.basename(filepath)}."
    file_descriptor, temp_path = tempfile.mkstemp(prefix=file_prefix, suffix=".tmp", dir=directory)

    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as file_ptr:
            json.dump(payload, file_ptr, indent=4)
            file_ptr.flush()
            os.fsync(file_ptr.fileno())
        os.replace(temp_path, filepath)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def ensure_json_list_file(filepath: str) -> None:
    if os.path.exists(filepath):
        return
    write_json_snapshot([], filepath)


def request_shutdown(_signum=None, _frame=None) -> None:
    global exit_prog
    if exit_prog:
        return
    exit_prog = True
    if pause_event is not None:
        pause_event.set()
    log_msg("[bold yellow][!] Stop requested. Finishing active work and leaving the remaining queue on disk.[/]")


def install_signal_handlers() -> None:
    signal.signal(signal.SIGINT, request_shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, request_shutdown)


def interruptible_sleep(seconds: float) -> bool:
    deadline = time.time() + max(0.0, seconds)
    while time.time() < deadline:
        if exit_prog:
            return False
        time.sleep(min(0.1, deadline - time.time()))
    return not exit_prog


def raise_if_exit_requested() -> None:
    if exit_prog:
        raise ScanInterrupted

def read_proxies(filepath: str = PROXY_LIST_TXT) -> List[str]:
    try:
        with open(filepath, "r", encoding="utf-8") as file_ptr:
            return[line.strip() for line in file_ptr if line.strip()]
    except FileNotFoundError:
        return[]

def set_active_proxies(proxy_list: List[str]) -> None:
    with proxy_lock:
        active_proxies.clear()
        active_proxies.extend(proxy_list)

def get_active_proxies() -> List[str]:
    with proxy_lock:
        return list(active_proxies)

def write_proxy_file(lines: List[str]) -> None:
    try:
        with open(PROXY_LIST_TXT, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(f"{line}\n")
    except Exception:
        console.print(f"[bold red][X] Failed to update {PROXY_LIST_TXT}[/]")

def mark_proxy_ok(proxy_ip: str) -> None:
    # We keep the original string so it writes back exactly as the user provided.
    # Example: "http://1.2.3.4:8080" stays that way in live_proxies.txt.
    if not proxy_ip:
        return
    with good_proxy_lock:
        good_proxies.add(proxy_ip.strip())
    with proxy_lock:
        proxy_fail.pop(proxy_ip.strip(), None)

def mark_proxy_bad(proxy_ip: str, reason: bytes) -> None:
    # We only drop it after N fails so one bad hop doesn't nuke the list.
    p = proxy_ip.strip()
    with proxy_lock:
        cnt = proxy_fail.get(p, 0) + 1
        proxy_fail[p] = cnt
        if cnt < PROXY_FAIL_LIMIT:
            return
        if p in active_proxies:
            active_proxies.remove(p)
        proxy_fail.pop(p, None)
    with good_proxy_lock:
        good_proxies.discard(p)
    write_proxy_file(get_active_proxies())

def save_good_proxies() -> None:
    if not active_proxies:
        return
    with good_proxy_lock:
        kept = sorted(good_proxies)
    try:
        write_proxy_file(kept)
        if kept:
            console.print(f"[bold green][+] Saved {len(kept)} working proxies to {PROXY_LIST_TXT}[/]")
        else:
            console.print(f"[bold yellow][!] No working proxies found. {PROXY_LIST_TXT} cleared.[/]")
    except Exception:
        console.print(f"[bold red][X] Failed to update {PROXY_LIST_TXT}[/]")

def fmt_proxy(p: str) -> dict:
    base = p.strip()
    if "://" not in base:
        base = f"http://{base}"
    return {"http": base, "https": base}

def toggle_pause():
    global active_proxies
    if pause_event.is_set():
        pause_event.clear()
        log_msg("[bold yellow][!] ⏸ PAUSE INITIATED: Halting all threads...[/]")
        with ui_mutex:
            for tag, state in thread_dashboard.items():
                if state["target"] != "Idle":
                    state["action"] = "[bold red]⏸ PAUSED[/]"
    else:
        set_active_proxies(read_proxies())
        log_msg(f"[bold green][▶] RESUMED: Reloaded {len(get_active_proxies())} proxies and unfreezing threads.[/]")
        pause_event.set()

def keyboard_monitor():
    global is_typing_url, input_buffer
    try:
        import msvcrt
        is_windows = True
    except ImportError:
        import select, tty, termios
        is_windows = False

    if is_windows:
        import msvcrt
        while not exit_prog:
            if msvcrt.kbhit():
                char = msvcrt.getch()
                if char == b"\x03":
                    request_shutdown()
                    return
                if is_typing_url:
                    if char in[b'\r', b'\n']:
                        submitted_prompt = input_buffer
                        is_typing_url = False
                        input_buffer = ""
                        submit_target_prompt(submitted_prompt)
                    elif char == b'\x08': # Backspace
                        input_buffer = input_buffer[:-1]
                    elif char == b'\x1b': # Esc
                        is_typing_url = False
                        input_buffer = ""
                    else:
                        try:
                            input_buffer += char.decode('utf-8')
                        except Exception: pass
                else:
                    if char in [b' ', b' ']:
                        toggle_pause()
                        if not interruptible_sleep(0.3):
                            return
                    elif char.lower() == b'i':
                        is_typing_url = True
                        input_buffer = ""
            if not interruptible_sleep(0.1):
                return
    else:
        import select, tty, termios
        fd = sys.stdin.fileno()
        if not os.isatty(fd): return
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while not exit_prog:
                if select.select([sys.stdin],[],[], 0.1)[0]:
                    char = sys.stdin.read(1)
                    if char == "\x03":
                        request_shutdown()
                        return
                    if is_typing_url:
                        if char in ['\n', '\r']:
                            submitted_prompt = input_buffer
                            is_typing_url = False
                            input_buffer = ""
                            submit_target_prompt(submitted_prompt)
                        elif char in ['\x7f', '\b']: # Backspace
                            input_buffer = input_buffer[:-1]
                        elif char == '\x1b': # Esc
                            is_typing_url = False
                            input_buffer = ""
                        else:
                            input_buffer += char
                    else:
                        if char == ' ':
                            toggle_pause()
                            if not interruptible_sleep(0.3):
                                return
                        elif char.lower() == 'i':
                            is_typing_url = True
                            input_buffer = ""
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

def update_thread_board(thread_tag: str, target=None, action=None, active_ip=None, reset_timer=False, dl_bytes=None):
    with ui_mutex:
        if thread_tag in thread_dashboard:
            if target is not None: thread_dashboard[thread_tag]["target"] = target
            if action is not None: thread_dashboard[thread_tag]["action"] = action
            if active_ip is not None: thread_dashboard[thread_tag]["active_ip"] = active_ip
            if reset_timer: thread_dashboard[thread_tag]["clock_start"] = time.time()
            if dl_bytes is not None: thread_dashboard[thread_tag]["dl_bytes"] = dl_bytes

def check_pause(thread_tag: str, current_action: str, current_ip: str):
    while not pause_event.is_set():
        raise_if_exit_requested()
        update_thread_board(thread_tag, action="[bold red]⏸ PAUSED[/]", active_ip="-")
        pause_event.wait(0.1)
    raise_if_exit_requested()
    update_thread_board(thread_tag, action=current_action, active_ip=current_ip)

def log_msg(msg: str):
    with ui_mutex: log_history.append(msg)

def log_dead_repo(target: str, crash_reason: str, ip: str, elapsed: float):
    with ui_mutex: fail_history.append(f"[red]{target}[/] - [dim]{crash_reason} ({elapsed}s via {ip})[/]")

def log_loot(target: str, file_list: List[str], total_hits: int, api_types: set, ip: str, elapsed: float):
    short_file_list = ", ".join(file_list[:3]) + ("..." if len(file_list) > 3 else "")
    detected_types = ", ".join(list(api_types))
    with ui_mutex: 
        leak_history.append(f"[bold red]{target}[/] - {total_hits} secret(s) ([magenta]{detected_types}[/]) in [yellow]{short_file_list}[/][dim] ({elapsed}s via {ip})[/]")

def bump_score(metric: str, step: int = 1):
    with ui_mutex: scoreboard[metric] += step

def dump_json_safely(filepath: str, json_blob: dict):
    with io_mutex:
        disk_content =[]
        if os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as file_ptr:
                    disk_content = json.load(file_ptr)
                    if not isinstance(disk_content, list):
                        disk_content = []
            except json.JSONDecodeError:
                disk_content = []

        repo_key = repo_identity(json_blob.get("repo") or json_blob.get("name"))
        replaced_existing = False

        if repo_key:
            for idx, existing_entry in enumerate(disk_content):
                if not isinstance(existing_entry, dict):
                    continue
                existing_key = repo_identity(existing_entry.get("repo") or existing_entry.get("name"))
                if existing_key == repo_key:
                    disk_content[idx] = json_blob
                    replaced_existing = True
                    break

        if not replaced_existing:
            disk_content.append(json_blob)

        write_json_snapshot(disk_content, filepath)

def repo_identity(repo_name: str) -> str:
    return (repo_name or "").strip().lower()

def resolve_repo_targets(prompt_text: str) -> List[dict]:
    global AI_POL
    if AI_POL is None:
        AI_POL = load_pol(log_fn=log_msg)
    return resolve_scanner_targets(
        prompt_text,
        os.environ.get("GROQ_API_KEY", "").strip(),
        AI_POL,
        log_msg,
    )

def queue_manual_target(repo_data: dict) -> bool:
    repo_name = repo_data["name"]
    repo_key = repo_identity(repo_name)

    with manual_target_mutex:
        if repo_key in manual_target_names:
            log_msg(f"[bold yellow][!] Target already pending:[/] {repo_name}")
            return False

    with io_mutex:
        current_queue = []
        if os.path.exists(QUEUE_JSON):
            try:
                with open(QUEUE_JSON, "r", encoding="utf-8") as f:
                    current_queue = json.load(f)
            except Exception:
                current_queue = []

        if any(repo_identity(r.get("name", "")) == repo_key for r in current_queue):
            log_msg(f"[bold yellow][!] Target already queued:[/] {repo_name}")
            return False

        current_queue.append(repo_data)
        write_json_snapshot(current_queue, QUEUE_JSON)

    with manual_target_mutex:
        manual_target_queue.append(repo_data)
        manual_target_names.add(repo_key)

    bump_score("total", 1)
    bump_score("remaining", 1)
    log_msg(f"[bold green][+] Inserted target:[/] {repo_name}")
    return True

def pop_manual_target() -> Optional[dict]:
    with manual_target_mutex:
        if not manual_target_queue:
            return None
        repo_data = manual_target_queue.popleft()
        manual_target_names.discard(repo_identity(repo_data.get("name", "")))
        return repo_data

def has_manual_targets() -> bool:
    with manual_target_mutex:
        return bool(manual_target_queue)

def handle_target_prompt(prompt_text: str):
    cleaned_prompt = prompt_text.strip()
    if not cleaned_prompt:
        return

    log_msg("[bold cyan][AI] Parsing repository targets from prompt...[/]")
    repo_targets = resolve_repo_targets(cleaned_prompt)
    if not repo_targets:
        log_msg("[bold red][!] No valid GitHub repositories found in the submitted prompt.[/]")
        return

    inserted_count = 0
    for repo_data in repo_targets:
        if queue_manual_target(repo_data):
            inserted_count += 1

    if inserted_count > 1:
        log_msg(f"[bold green][+] Added {inserted_count} repositories from AI prompt.[/]")

def submit_target_prompt(prompt_text: str):
    if not prompt_text.strip():
        return
    threading.Thread(target=handle_target_prompt, args=(prompt_text,), daemon=True).start()

def remove_from_queue(target_repo: str):
    with io_mutex:
        if not os.path.exists(QUEUE_JSON): return
        try:
            with open(QUEUE_JSON, "r", encoding="utf-8") as file_ptr:
                current_queue = json.load(file_ptr)
            fresh_queue =[r for r in current_queue if r.get("name") != target_repo]
            write_json_snapshot(fresh_queue, QUEUE_JSON)
        except Exception: pass

def fetch_with_progress(
    url: str,
    headers: dict,
    proxy_dict: Optional[dict],
    thread_tag: str,
    ip_str: str,
    action_label: str,
    tmo: Tuple[float, float] = NET_TIMEOUTS,
) -> bytes:
    raise_if_exit_requested()
    last_chunk_time = time.time()
    total_bytes = 0
    last_ui_update = 0
    
    try:
        with requests.get(url, headers=headers, proxies=proxy_dict, timeout=tmo, stream=True) as r:
            if r.status_code == 404: return b"NOT_FOUND"
            if r.status_code == 429: return b"RATE_LIMITED"
            if r.status_code == 403:
                # GitHub rate limits often show up as 403 with remaining=0 or a retry hint.
                # Example: X-RateLimit-Remaining=0 => treat it like 429 so proxies can try.
                if r.headers.get("X-RateLimit-Remaining", "") == "0":
                    return b"RATE_LIMITED"
                if r.headers.get("Retry-After"):
                    return b"RATE_LIMITED"
                return b"FORBIDDEN"
            if r.status_code != 200: return f"FAILED_{r.status_code}".encode()
            
            content = bytearray()
            for chunk in r.iter_content(chunk_size=32768):
                raise_if_exit_requested()
                if not pause_event.is_set():
                    check_pause(thread_tag, action_label, ip_str)
                    last_chunk_time = time.time()
                    
                if time.time() - last_chunk_time > IDLE_STALL_TIMEOUT_SEC:
                    return b"TIMEOUT"
                
                if chunk:
                    last_chunk_time = time.time() 
                    content.extend(chunk)
                    total_bytes += len(chunk)
                    
                    if total_bytes > MAX_DOWNLOAD_SIZE_BYTES:
                        return b"TOO_LARGE"
                        
                    if time.time() - last_ui_update > 0.15:
                        update_thread_board(thread_tag, action=action_label, active_ip=ip_str, dl_bytes=total_bytes)
                        last_ui_update = time.time()
                        
            return bytes(content)
            
    except ScanInterrupted:
        raise
    except requests.exceptions.ReadTimeout: return b"TIMEOUT"
    except requests.exceptions.ChunkedEncodingError: return b"CONN_DROPPED"
    except requests.exceptions.ConnectionError: return b"CONN_ERROR"
    except Exception: return b"FAILED_EXC"
# This tries the direct download path first and only falls back to proxies for retryable failures.
def download_github_url(target_url: str, thread_tag: str, action_label: str) -> Tuple[Optional[bytes], str]:
    global active_proxies
    raise_if_exit_requested()
    http_headers = {"User-Agent": SPOOFED_USER_AGENT}
    
    res = b"FAILED"
    tried_proxies = False

    def is_fail(val: Optional[bytes]) -> bool:
        return isinstance(val, bytes) and (val in[b"FAILED", b"TIMEOUT", b"RATE_LIMITED", b"FORBIDDEN", b"CONN_DROPPED", b"CONN_ERROR", b"FAILED_EXC"] or val.startswith(b"FAILED"))

    def try_proxies() -> Tuple[Optional[bytes], str]:
        mixed = get_active_proxies()
        if not mixed:
            return b"FAILED", "-"
        random.shuffle(mixed)
        for proxy_ip in mixed:
            raise_if_exit_requested()
            check_pause(thread_tag, "[cyan]Testing Proxy...[/]", proxy_ip)
            update_thread_board(thread_tag, action="[cyan]Testing Proxy...[/]", active_ip=proxy_ip, dl_bytes=0)
            proxy_dict = fmt_proxy(proxy_ip)
            out = fetch_with_progress(target_url, http_headers, proxy_dict, thread_tag, proxy_ip, action_label, PROXY_TIMEOUTS)
            if out == b"NOT_FOUND":
                mark_proxy_ok(proxy_ip)
                return None, proxy_ip
            if out == b"TOO_LARGE":
                mark_proxy_ok(proxy_ip)
                return b"TOO_LARGE", proxy_ip
            if not (isinstance(out, bytes) and (out in[b"TIMEOUT", b"RATE_LIMITED", b"FORBIDDEN", b"CONN_DROPPED", b"CONN_ERROR", b"FAILED_EXC"] or out.startswith(b"FAILED"))):
                mark_proxy_ok(proxy_ip)
                return out, proxy_ip
            if out in [b"TIMEOUT", b"CONN_DROPPED", b"CONN_ERROR", b"FAILED_EXC"] or (isinstance(out, bytes) and out.startswith(b"FAILED")) or out == b"FORBIDDEN":
                mark_proxy_bad(proxy_ip, out)
        return b"FAILED", "All Proxies Failed"

    # Prefer proxy first when requested (handy for testing).
    if PREFER_PROXY and get_active_proxies():
        tried_proxies = True
        res, ip = try_proxies()
        if res is None or res == b"TOO_LARGE" or not is_fail(res):
            return res, ip

    for attempt in range(6):
        raise_if_exit_requested()
        action_str = f"[yellow]Connecting...[/]" if attempt == 0 else f"[yellow]Retrying Direct ({attempt}/5)...[/]"
        check_pause(thread_tag, action_str, "Direct IP")
        update_thread_board(thread_tag, action=action_str, active_ip="Direct IP", dl_bytes=0)
        
        res = fetch_with_progress(target_url, http_headers, None, thread_tag, "Direct IP", action_label)
        
        if res == b"NOT_FOUND": return None, "Direct IP"
        if res == b"TOO_LARGE": return b"TOO_LARGE", "Direct IP"
        
        if not (isinstance(res, bytes) and (res in[b"TIMEOUT", b"RATE_LIMITED", b"FORBIDDEN", b"CONN_DROPPED", b"CONN_ERROR", b"FAILED_EXC"] or res.startswith(b"FAILED"))):
            return res, "Direct IP"
            
        # Retry 403 a few times before giving up.
        # In practice, the same target can briefly flip between allowed and forbidden responses.
        if res == b"FORBIDDEN":
            if not interruptible_sleep(1.5):
                raise ScanInterrupted
            continue
            
        # Retry a smaller number of times for other transient failures so one repo does not stall the queue.
        if attempt >= 1:
            break
        else:
            if not interruptible_sleep(1.0):
                raise ScanInterrupted
            continue
            
    # Turn transport errors into short status text for the dashboard.
    reason_str = "Failed"
    if res == b"RATE_LIMITED": reason_str = "Rate Limited"
    elif res == b"FORBIDDEN": reason_str = "Forbidden (403)"
    elif res == b"TIMEOUT": reason_str = "Timeout"
    elif res == b"CONN_DROPPED": reason_str = "Conn Dropped"
    elif res == b"CONN_ERROR": reason_str = "Conn Error"
    elif isinstance(res, bytes) and res.startswith(b"FAILED_"): 
        reason_str = f"Failed ({res.split(b'_')[1].decode()})"

    update_thread_board(thread_tag, action=f"[red]Direct {reason_str}[/]", active_ip="Direct IP", dl_bytes=0)
    if not interruptible_sleep(1.0):
        raise ScanInterrupted

    if tried_proxies:
        return b"FAILED", "All Proxies Failed"
    return try_proxies()

def regex_grep_text(raw_text: str, filename: str) -> List[dict]:
    return grep_scanner_text(raw_text, filename, API_SIGNATURES, LINE_CUTOFF)

def normalize_branch_name(branch_name: Optional[str]) -> Optional[str]:
    if not isinstance(branch_name, str):
        return None
    cleaned_branch = branch_name.strip().strip("/")
    if cleaned_branch.startswith("refs/heads/"):
        cleaned_branch = cleaned_branch[len("refs/heads/"):]
    return cleaned_branch or None

def fetch_repo_metadata(repo_name: str, thread_tag: str) -> Tuple[Optional[dict], str]:
    metadata_url = f"https://api.github.com/repos/{repo_name}"
    metadata_bytes, current_ip = download_github_url(metadata_url, thread_tag, "Resolving Repo Metadata")
    if not metadata_bytes or metadata_bytes in [b"FAILED", b"TOO_LARGE", b"FORBIDDEN_SKIP"]:
        return None, current_ip

    try:
        metadata = json.loads(metadata_bytes.decode("utf-8", errors="ignore"))
    except Exception:
        return None, current_ip

    return metadata if isinstance(metadata, dict) else None, current_ip

def resolve_default_branch(repo_data: dict, thread_tag: str) -> Optional[str]:
    stored_branch = normalize_branch_name(repo_data.get("default_branch"))
    if stored_branch:
        return stored_branch

    repo_name = repo_data.get("name", "").strip()
    if not repo_name:
        return None

    metadata, _ = fetch_repo_metadata(repo_name, thread_tag)
    if not metadata:
        return None

    resolved_branch = normalize_branch_name(metadata.get("default_branch"))
    if resolved_branch:
        repo_data["default_branch"] = resolved_branch
    return resolved_branch

def build_archive_branch_candidates(repo_data: dict, thread_tag: str) -> List[str]:
    branch_candidates = []
    seen_branches = set()

    def add_branch(branch_name: Optional[str]) -> None:
        normalized_branch = normalize_branch_name(branch_name)
        if not normalized_branch or normalized_branch in seen_branches:
            return
        seen_branches.add(normalized_branch)
        branch_candidates.append(normalized_branch)

    add_branch(repo_data.get("default_branch"))
    add_branch(resolve_default_branch(repo_data, thread_tag))
    for fallback_branch in DEFAULT_BRANCH_FALLBACKS:
        add_branch(fallback_branch)

    return branch_candidates

# This scans one repository end to end and returns the final payload used for persistence.
def dissect_repo_memory(repo_data: dict, thread_tag: str) -> dict:
    raise_if_exit_requested()
    start_time = time.time()
    target_repo = repo_data.get("name", "Unknown_Repo")
    
    update_thread_board(thread_tag, target=target_repo, action="[yellow]Initializing[/]", active_ip="-", reset_timer=True, dl_bytes=0)
    
    zip_buffer = None
    successful_ip = "Direct IP"
    branch_candidates = build_archive_branch_candidates(repo_data, thread_tag)
    successful_branch = branch_candidates[0] if branch_candidates else DEFAULT_BRANCH_FALLBACKS[0]
    

    # Try the known default branch first, then fall back to common names.
    for git_branch in branch_candidates:
        raise_if_exit_requested()
        download_link = f"https://codeload.github.com/{target_repo}/zip/refs/heads/{git_branch}"
        zip_buffer, current_ip = download_github_url(download_link, thread_tag, "Downloading ZIP")
        successful_ip = current_ip
        
        # Stop early if the direct IP is consistently forbidden.
        if zip_buffer == b"FORBIDDEN_SKIP":
            break
            
        if zip_buffer is not None and zip_buffer not in[b"FAILED", b"TOO_LARGE"]: 
            successful_branch = git_branch
            break
            
    elapsed = round(time.time() - start_time, 2)

    if zip_buffer == b"FORBIDDEN_SKIP":
        log_dead_repo(target_repo, "Forbidden 403 (Skipped)", successful_ip, elapsed)
        bump_score("failed"); bump_score("scanned")
        return {"repo": target_repo, "status": "failed", "reason": "Forbidden 403 (Skipped)", "ip": successful_ip, "time_taken": elapsed}

    if zip_buffer == b"TOO_LARGE":
        log_dead_repo(target_repo, "Skipped (Over 20MB Limit)", successful_ip, elapsed)
        bump_score("failed"); bump_score("scanned")
        return {"repo": target_repo, "status": "failed", "reason": "Over 20MB Limit", "ip": successful_ip, "time_taken": elapsed}

    if not zip_buffer or zip_buffer == b"FAILED":
        crash_reason = "Connection Stalled / Exhausted" if zip_buffer == b"FAILED" else "404 Not Found"
        log_dead_repo(target_repo, crash_reason, successful_ip, elapsed)
        bump_score("failed"); bump_score("scanned")
        return {"repo": target_repo, "status": "failed", "reason": crash_reason, "ip": successful_ip, "time_taken": elapsed}

    update_thread_board(thread_tag, action="[magenta]Extracting...[/]", active_ip=successful_ip, dl_bytes=0)
    caught_keys =[]
    last_ui_update = 0 
    
    try:
        with zipfile.ZipFile(io.BytesIO(zip_buffer)) as zipped_archive:
            for zipped_file in zipped_archive.infolist():
                raise_if_exit_requested()
                check_pause(thread_tag, "[magenta]Scanning File...[/]", successful_ip)
                if zipped_file.is_dir() or zipped_file.file_size > FAT_FILE_LIMIT: continue
                
                lowered_name = zipped_file.filename.lower()
                clean_filename = lowered_name.split('/')[-1]
                
                # Keep the scan focused on text-like files where secrets usually live.
                # For example, this skips binaries and large generated assets.
                if not (lowered_name.endswith(TARGET_EXTENSIONS) or clean_filename in EXACT_FILENAMES): continue
                
                if time.time() - last_ui_update > 0.1:
                    short_filename = clean_filename[:25] + ".." if len(clean_filename) > 25 else clean_filename
                    update_thread_board(thread_tag, action=f"[magenta]Scan: {short_filename}[/]", active_ip=successful_ip)
                    last_ui_update = time.time()

                try:
                    with zipped_archive.open(zipped_file) as extracted_file:
                        raw_text = extracted_file.read().decode('utf-8', errors='ignore')
                    caught_keys.extend(regex_grep_text(raw_text, zipped_file.filename))
                except Exception: pass
    except zipfile.BadZipFile:
        log_dead_repo(target_repo, "Corrupted Zip", successful_ip, round(time.time() - start_time, 2))
        bump_score("failed"); bump_score("scanned")
        return {"repo": target_repo, "status": "failed", "reason": "BadZipFile", "ip": successful_ip, "time_taken": round(time.time() - start_time, 2)}

    # Scan recent commit history as patch text as well.
    # For example, a key removed from the working tree can still appear in an older commit.
    if SCAN_COMMIT_HISTORY:
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
            
            commit_shas = unique_shas[:MAX_HISTORY_DEPTH]
            
            for idx, sha in enumerate(commit_shas):
                raise_if_exit_requested()
                patch_url = f"https://github.com/{target_repo}/commit/{sha}.patch"
                patch_action_str = f"DL Patch {idx+1}/{len(commit_shas)}"
                patch_bytes, patch_ip = download_github_url(patch_url, thread_tag, patch_action_str)
                
                if patch_bytes and patch_bytes not in[b"FAILED", b"TOO_LARGE", b"NOT_FOUND", b"FORBIDDEN_SKIP"]:
                    patch_text = patch_bytes.decode('utf-8', errors='ignore')
                    check_pause(thread_tag, f"[magenta]Scan Patch {idx+1}/{len(commit_shas)}[/]", patch_ip)
                    
                    new_keys = regex_grep_text(patch_text, f"Commit {sha[:7]}")
                    caught_keys.extend(new_keys)

    # Deduplicate findings, log results, update scores, and return the final scan summary
    bump_score("scanned")
    elapsed = round(time.time() - start_time, 2)
    
    if caught_keys:
        unique_findings =[]
        seen_secrets = set()
        # Deduplicate by secret value so the same token does not flood the report.
        # For example, the same key may appear in both a source file and a patch.
        for k in caught_keys:
            if k["secret"] not in seen_secrets:
                seen_secrets.add(k["secret"])
                unique_findings.append(k)
                
        bump_score("leaks")
        files_with_hits = list(set([k["file"] for k in unique_findings]))
        found_api_types = set([k["type"] for k in unique_findings])
        log_loot(target_repo, files_with_hits, len(unique_findings), found_api_types, successful_ip, elapsed)
        
        return {"repo": target_repo, "url": repo_data.get("url"), "status": "leaked", "total_secrets": len(unique_findings), "findings": unique_findings, "ip": successful_ip, "time_taken": elapsed}
    else:
        bump_score("clean")
        log_msg(f"[green][+] Clean:[/] {target_repo} [dim]({elapsed}s)[/]")
        return {"repo": target_repo, "url": repo_data.get("url"), "status": "clean", "ip": successful_ip, "time_taken": elapsed}

def paint_dashboard():
    return render_scanner_dashboard(
        ui_mutex,
        pause_event,
        scoreboard,
        thread_dashboard,
        len(API_SIGNATURES),
        is_typing_url,
        input_buffer,
        log_history,
        leak_history,
        MAX_DOWNLOAD_SIZE_BYTES,
    )

def thread_runner(repo_data: dict):
    with tag_mutex:
        thread_tag = available_thread_tags.popleft() if available_thread_tags else "Thread-Unknown"

    try:
        return dissect_repo_memory(repo_data, thread_tag)
    except ScanInterrupted:
        raise
    except Exception as e:
        safe_name = repo_data.get("name", "Unknown_Repo")
        log_dead_repo(safe_name, f"Critical Thread Crash", "-", 0.0)
        bump_score("failed"); bump_score("scanned")
        return {"repo": safe_name, "status": "failed", "reason": "Thread Crash", "ip": "-", "time_taken": 0.0}
    finally:
        update_thread_board(thread_tag, target="Idle", action="-", active_ip="-", reset_timer=True, dl_bytes=0)
        with tag_mutex:
            if thread_tag != "Thread-Unknown":
                available_thread_tags.append(thread_tag)

def main():
    global exit_prog, active_proxies, AI_POL
    keyboard_thread = None
    reset_runtime_state()
    AI_POL = load_pol(log_fn=console.print)
    ensure_json_list_file(LEAKS_JSON)
    ensure_json_list_file(DEAD_TARGETS_JSON)
    ensure_json_list_file(BORING_REPOS_JSON)

    try:
        with open(QUEUE_JSON, "r", encoding="utf-8") as file_ptr:
            queued_targets = json.load(file_ptr)
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/] {QUEUE_JSON} not found. Run the fetcher first.")
        return

    if not queued_targets:
        console.print("[bold yellow]Queue is empty.[/] No new repositories to scan.")
        return

    set_active_proxies(read_proxies())
    scoreboard["total"] = len(queued_targets)
    scoreboard["remaining"] = len(queued_targets)
    
    keyboard_thread = threading.Thread(target=keyboard_monitor, daemon=True)
    keyboard_thread.start()
    log_msg("[bold green]Scanner initiated. Press SPACE to Pause/Resume or I for AI target insertion.[/]")

    try:
        with Live(get_renderable=paint_dashboard, refresh_per_second=6, screen=True) as live_screen:
            with ThreadPoolExecutor(max_workers=MAX_THREADS) as thread_pool:
                pending_tasks = set()
                idle_shutdown_deadline = None
                for target in queued_targets:
                    pending_tasks.add(thread_pool.submit(thread_runner, target))
                
                while pending_tasks or has_manual_targets() or is_typing_url or idle_shutdown_deadline is not None:
                    if exit_prog:
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
                                if task_outcome["status"] == "leaked": dump_json_safely(LEAKS_JSON, task_outcome)
                                elif task_outcome["status"] == "failed": dump_json_safely(DEAD_TARGETS_JSON, task_outcome)
                                elif task_outcome["status"] == "clean": dump_json_safely(BORING_REPOS_JSON, task_outcome)
                                    
                                remove_from_queue(task_outcome.get("repo"))
                                bump_score("remaining", -1)
                            except ScanInterrupted:
                                continue
                            except Exception:
                                pass
                        
                        live_screen.update(paint_dashboard())
                        if exit_prog:
                            break
                        if pending_tasks or has_manual_targets() or is_typing_url:
                            idle_shutdown_deadline = None
                        else:
                            idle_shutdown_deadline = time.time() + 1.5
                    else:
                        if is_typing_url or has_manual_targets():
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

        if exit_prog:
            console.print("\n[bold yellow]Scanner stopped by user. Remaining targets stayed in the queue.[/]")
        else:
            console.print("\n[bold green]Queue Exhausted. Scan Complete.[/]")
    except KeyboardInterrupt:
        request_shutdown()
        console.print("\n[bold yellow]Scanner stop requested. Waiting for active threads to unwind...[/]")
        
    finally:
        exit_prog = True
        if pause_event is not None:
            pause_event.set()
        if keyboard_thread is not None:
            keyboard_thread.join(timeout=1.0)
        save_good_proxies()

if __name__ == "__main__":
    install_signal_handlers()
    apply_runtime_overrides(parse_args())
    main()
