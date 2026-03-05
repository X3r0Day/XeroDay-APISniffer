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





import requests, random, json, io, os, sys, zipfile, re, time, threading

from collections import deque
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from typing import List, Optional, Tuple

from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.console import Console
from rich.text import Text


QUEUE_JSON = "recent_repos.json"
LEAKS_JSON = "leaked_keys.json"
DEAD_TARGETS_JSON = "failed_repos.json"
BORING_REPOS_JSON = "clean_repos.json"
PROXY_LIST_TXT = "live_proxies.txt"
MAX_THREADS = 15          

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

TARGET_EXTENSIONS = (
    ".py", ".js", ".ts", ".jsx", ".tsx", ".json", ".yml", ".yaml", ".xml", 
    ".txt", ".env", ".ini", ".conf", ".config", ".sh", ".bash", ".php", 
    ".java", ".c", ".cpp", ".h", ".hpp", ".cs", ".go", ".rb", ".swift", 
    ".kt", ".kts", ".rs", ".sql", ".md", ".toml", ".properties"
)
EXACT_FILENAMES = ("dockerfile", "makefile", "gemfile")

# Lol I used wget UA cuz when I made request from wget i didn't get 403 but with spoofed UA I got 403
SPOOFED_USER_AGENT = "Wget/1.21.2"

API_SIGNATURES = {
    "OpenAI API Key (Legacy)": re.compile(r"\bsk-[a-zA-Z0-9]{48}\b"),
    "OpenAI API Key (Project)": re.compile(r"\bsk-proj-[a-zA-Z0-9\-_]{48,}\b"),
    "Anthropic API Key": re.compile(r"\bsk-ant-api03-[a-zA-Z0-9\-_]{60,100}\b"),
    "Google API/GCP Key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "OpenRouter API Key": re.compile(r"\bsk-or-v1-[a-zA-Z0-9]{64}\b"),
    "xAI (Grok) API Key": re.compile(r"\bxai-[a-zA-Z0-9\-_]{60,100}\b"),
    "Groq API Key": re.compile(r"\bgsk_[a-zA-Z0-9]{32,64}\b"),
    "HuggingFace Token": re.compile(r"\bhf_[a-zA-Z]{34}\b"),
    "Replicate Token": re.compile(r"\br8_[a-zA-Z0-9]{37}\b"),
    "Cerebras Token": re.compile(r"\bcs-[a-zA-Z0-9]{32,64}\b"),
    "AWS Access Key ID": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "AWS Session Token": re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    "DigitalOcean PAT": re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),
    "Heroku API Key": re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    "Mapbox API Key": re.compile(r"\b(?:pk|sk)\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    "Sentry Token": re.compile(r"\bsntrys_[a-zA-Z0-9_-]{64,}\b"),
    "Databricks PAT": re.compile(r"\bdapi[a-h0-9]{32}\b"),
    "GitHub Classic PAT": re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}\b"),
    "GitHub Fine-Grained PAT": re.compile(r"\bgithub_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}\b"),
    "GitLab PAT": re.compile(r"\bglpat-[a-zA-Z0-9\-]{20}\b"),
    "NPM Access Token": re.compile(r"\b(?:npm_[a-zA-Z0-9]{36})\b"),
    "PyPI Upload Token": re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,150}\b"),
    "Postman API Key": re.compile(r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b"),
    "Discord Bot Token": re.compile(r"\b[MNO][a-zA-Z0-9_-]{23,27}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,38}\b"),
    "Discord Webhook": re.compile(r"https://discord\.com/api/webhooks/[0-9]{17,19}/[a-zA-Z0-9_-]{60,68}"),
    "Slack Bot Token": re.compile(r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}\b"),
    "Slack User Token": re.compile(r"\bxox[pausr]-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b"),
    "Slack Webhook": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,10}/B[a-zA-Z0-9_]{8,10}/[a-zA-Z0-9_]{24}"),
    "Telegram Bot Token": re.compile(r"\b[0-9]{8,10}:[a-zA-Z0-9_-]{35}\b"),
    "Twilio API Key": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
    "SendGrid API Key": re.compile(r"\bSG\.[a-zA-Z0-9_\-\.]{66}\b"),
    "Mailgun API Key": re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"),
    "Stripe Secret Key": re.compile(r"\b(?:sk|rk)_(?:test|live)_[0-9a-zA-Z]{24,99}\b"),
    "Square Access Token": re.compile(r"\bsq0atp-[0-9A-Za-z\-_]{22,43}\b"),
    "Square OAuth Secret": re.compile(r"\bsq0csp-[0-9A-Za-z\-_]{43}\b"),
    "Shopify Access Token": re.compile(r"\bshpat_[a-fA-F0-9]{32}\b"),
    "Shopify Custom App": re.compile(r"\bshpca_[a-fA-F0-9]{32}\b"),
    "Supabase PAT": re.compile(r"\bsbp_[a-zA-Z0-9]{40}\b"),
    "Supabase Anon/Service Role JWT": re.compile(r"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
    "Firebase Server Key": re.compile(r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b"),
    "Firebase Database URL": re.compile(r"https:\/\/[a-z0-9-]+\.firebaseio\.com"),
    "PlanetScale Password": re.compile(r"\bpscale_pw_[a-zA-Z0-9_\.\-]{43}\b"),
    "PlanetScale OAuth Token": re.compile(r"\bpscale_oauth_[a-zA-Z0-9_\.\-]{32,64}\b"),
    "Airtable PAT": re.compile(r"\bpat[a-zA-Z0-9]{14}\.[a-zA-Z0-9]{64}\b"),
    "Appwrite API Key": re.compile(r"(?i)appwrite[\w\s=-]{0,20}(?:key|token|secret)[\w\s=:\"\'-]{0,10}\b([a-zA-Z0-9\-_]{32,})\b"),
    "Deta Token": re.compile(r"(?i)deta[\w\s=-]{0,20}(?:key|token)[\w\s=:\"\'-]{0,10}\b([a-zA-Z0-9_]{32,})\b"),
    "PocketBase Token": re.compile(r"(?i)pocketbase[\w\s=-]{0,20}(?:key|token|admin)[\w\s=:\"\'-]{0,10}\b([a-zA-Z0-9\-_]{32,})\b"),
}

console = Console()
ui_mutex = threading.Lock()
io_mutex = threading.Lock() 

pause_event = threading.Event()
pause_event.set() 
exit_prog = False
active_proxies =[]

# To check if new target should be injected
is_typing_url = False
input_buffer = ""
new_manual_targets = []

available_thread_tags = deque([f"Thread-{i+1}" for i in range(MAX_THREADS)])
tag_mutex = threading.Lock()

thread_dashboard = {f"Thread-{i+1}": {"target": "Idle", "action": "-", "active_ip": "-", "clock_start": 0, "dl_bytes": 0} for i in range(MAX_THREADS)}
log_history = deque(maxlen=6)
fail_history = deque(maxlen=10)
leak_history = deque(maxlen=10)
scoreboard = {"total": 0, "scanned": 0, "leaks": 0, "clean": 0, "failed": 0, "remaining": 0}

def read_proxies(filepath: str = PROXY_LIST_TXT) -> List[str]:
    try:
        with open(filepath, "r", encoding="utf-8") as file_ptr:
            return[line.strip() for line in file_ptr if line.strip()]
    except FileNotFoundError:
        return[]

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
        active_proxies = read_proxies()
        log_msg(f"[bold green][▶] RESUMED: Reloaded {len(active_proxies)} proxies and unfreezing threads.[/]")
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
                if is_typing_url:
                    if char in[b'\r', b'\n']:
                        handle_new_url(input_buffer)
                        is_typing_url = False
                        input_buffer = ""
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
                        time.sleep(0.3) 
                    elif char.lower() == b'i':
                        is_typing_url = True
                        input_buffer = ""
            time.sleep(0.1)
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
                    if is_typing_url:
                        if char in ['\n', '\r']:
                            handle_new_url(input_buffer)
                            is_typing_url = False
                            input_buffer = ""
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
                            time.sleep(0.3) 
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
    if not pause_event.is_set():
        update_thread_board(thread_tag, action="[bold red]⏸ PAUSED[/]", active_ip="-")
        pause_event.wait()
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
            except json.JSONDecodeError: pass
        disk_content.append(json_blob)
        with open(filepath, "w", encoding="utf-8") as file_ptr:
            json.dump(disk_content, file_ptr, indent=4)

def handle_new_url(url_text: str):
    global new_manual_targets, scoreboard
    url_text = url_text.strip()
    if not url_text: return
    match = re.search(r'(?:github\.com/)?([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)', url_text)
    if match:
        repo_name = match.group(1)
        if repo_name.endswith('.git'): repo_name = repo_name[:-4]
        repo_data = {"name": repo_name, "url": f"https://github.com/{repo_name}"}
        
        with io_mutex:
            current_queue =[]
            if os.path.exists(QUEUE_JSON):
                try:
                    with open(QUEUE_JSON, "r", encoding="utf-8") as f:
                        current_queue = json.load(f)
                except Exception: pass
            
            if not any(r.get("name") == repo_name for r in current_queue):
                current_queue.append(repo_data)
                with open(QUEUE_JSON, "w", encoding="utf-8") as f:
                    json.dump(current_queue, f, indent=4)
                    
        new_manual_targets.append(repo_data)
        bump_score("total", 1)
        bump_score("remaining", 1)
        log_msg(f"[bold green][+] Inserted manual target:[/] {repo_name}")
    else:
        log_msg(f"[bold red][!] Invalid URL/Repo format for manual insert.[/]")

def remove_from_queue(target_repo: str):
    with io_mutex:
        if not os.path.exists(QUEUE_JSON): return
        try:
            with open(QUEUE_JSON, "r", encoding="utf-8") as file_ptr:
                current_queue = json.load(file_ptr)
            fresh_queue =[r for r in current_queue if r.get("name") != target_repo]
            with open(QUEUE_JSON, "w", encoding="utf-8") as file_ptr:
                json.dump(fresh_queue, file_ptr, indent=4)
        except Exception: pass

def fetch_with_progress(url: str, headers: dict, proxy_dict: Optional[dict], thread_tag: str, ip_str: str, action_label: str) -> bytes:
    last_chunk_time = time.time()
    total_bytes = 0
    last_ui_update = 0
    
    try:
        with requests.get(url, headers=headers, proxies=proxy_dict, timeout=NET_TIMEOUTS, stream=True) as r:
            if r.status_code == 404: return b"NOT_FOUND"
            if r.status_code == 429: return b"RATE_LIMITED"
            if r.status_code == 403: return b"FORBIDDEN"
            if r.status_code != 200: return f"FAILED_{r.status_code}".encode()
            
            content = bytearray()
            for chunk in r.iter_content(chunk_size=32768):
                if not pause_event.is_set():
                    pause_event.wait()
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
            
    except requests.exceptions.ReadTimeout: return b"TIMEOUT"
    except requests.exceptions.ChunkedEncodingError: return b"CONN_DROPPED"
    except requests.exceptions.ConnectionError: return b"CONN_ERROR"
    except Exception: return b"FAILED_EXC"

def download_github_url(target_url: str, thread_tag: str, action_label: str) -> Tuple[Optional[bytes], str]:
    global active_proxies
    http_headers = {"User-Agent": SPOOFED_USER_AGENT}
    
    res = b"FAILED"
    
    for attempt in range(6):
        action_str = f"[yellow]Connecting...[/]" if attempt == 0 else f"[yellow]Retrying Direct ({attempt}/5)...[/]"
        check_pause(thread_tag, action_str, "Direct IP")
        update_thread_board(thread_tag, action=action_str, active_ip="Direct IP", dl_bytes=0)
        
        res = fetch_with_progress(target_url, http_headers, None, thread_tag, "Direct IP", action_label)
        
        if res == b"NOT_FOUND": return None, "Direct IP"
        if res == b"TOO_LARGE": return b"TOO_LARGE", "Direct IP"
        
        if not (isinstance(res, bytes) and (res in[b"TIMEOUT", b"RATE_LIMITED", b"FORBIDDEN", b"CONN_DROPPED", b"CONN_ERROR", b"FAILED_EXC"] or res.startswith(b"FAILED"))):
            return res, "Direct IP"
            
        # This will check 403 multiple times cuz sometimes it may give false positive depending on the proxy and IP (According to my observation)
        if res == b"FORBIDDEN":
            time.sleep(1.5)
            continue
            
        # For other errors which idk I didn't added will retry 2 times
        if attempt >= 1:
            break
        else:
            time.sleep(1.0)
            continue
            
    # If we exhausted all retries and it's STILL a 403, we completely skip proxy fallback
    if res == b"FORBIDDEN":
        update_thread_board(thread_tag, action=f"[red]Direct Forbidden (403) - Skipping[/]", active_ip="Direct IP", dl_bytes=0)
        time.sleep(1.0)
        return b"FORBIDDEN_SKIP", "Direct IP"

    # I have these error parsings for now...
    reason_str = "Failed"
    if res == b"RATE_LIMITED": reason_str = "Rate Limited"
    elif res == b"TIMEOUT": reason_str = "Timeout"
    elif res == b"CONN_DROPPED": reason_str = "Conn Dropped"
    elif res == b"CONN_ERROR": reason_str = "Conn Error"
    elif isinstance(res, bytes) and res.startswith(b"FAILED_"): 
        reason_str = f"Failed ({res.split(b'_')[1].decode()})"

    update_thread_board(thread_tag, action=f"[red]Direct {reason_str}[/]", active_ip="Direct IP", dl_bytes=0)
    time.sleep(1.0)

    mixed_proxies = active_proxies[:]
    if not mixed_proxies: return b"FAILED", "-"
    random.shuffle(mixed_proxies)

    for proxy_ip in mixed_proxies:
        check_pause(thread_tag, "[cyan]Testing Proxy...[/]", proxy_ip)
        update_thread_board(thread_tag, action="[cyan]Testing Proxy...[/]", active_ip=proxy_ip, dl_bytes=0)
        proxy_dict = {"http": f"http://{proxy_ip}", "https": f"http://{proxy_ip}"}
        
        res = fetch_with_progress(target_url, http_headers, proxy_dict, thread_tag, proxy_ip, action_label)
        if res == b"NOT_FOUND": return None, proxy_ip
        if res == b"TOO_LARGE": return b"TOO_LARGE", proxy_ip
        if not (isinstance(res, bytes) and (res in[b"TIMEOUT", b"RATE_LIMITED", b"FORBIDDEN", b"CONN_DROPPED", b"CONN_ERROR", b"FAILED_EXC"] or res.startswith(b"FAILED"))):
            return res, proxy_ip
            
    return b"FAILED", "All Proxies Failed"

def regex_grep_text(raw_text: str, filename: str) -> List[dict]:
    caught_keys =[]
    for line_idx, line_data in enumerate(raw_text.splitlines(), 1):
        if len(line_data) > LINE_CUTOFF:
            split_pieces =[line_data[i:i+LINE_CUTOFF] for i in range(0, len(line_data), LINE_CUTOFF)]
        else:
            split_pieces = [line_data]
            
        for piece in split_pieces:
            for api_name, regex_obj in API_SIGNATURES.items():
                for hit in regex_obj.finditer(piece):
                    caught_keys.append({
                        "file": filename, "line": line_idx,
                        "type": api_name, "secret": hit.group(0)
                    })
    return caught_keys

def dissect_repo_memory(repo_data: dict, thread_tag: str) -> dict:
    start_time = time.time()
    target_repo = repo_data.get("name", "Unknown_Repo")
    
    update_thread_board(thread_tag, target=target_repo, action="[yellow]Initializing[/]", active_ip="-", reset_timer=True, dl_bytes=0)
    
    zip_buffer = None
    successful_ip = "Direct IP"
    successful_branch = "main"
    

    for git_branch in ["main", "master"]:
        download_link = f"https://codeload.github.com/{target_repo}/zip/refs/heads/{git_branch}"
        zip_buffer, current_ip = download_github_url(download_link, thread_tag, "Downloading ZIP")
        successful_ip = current_ip
        
        # This'll just give up if got hit by 403 on the Direct IP
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
                check_pause(thread_tag, "[magenta]Scanning File...[/]", successful_ip)
                if zipped_file.is_dir() or zipped_file.file_size > FAT_FILE_LIMIT: continue
                
                lowered_name = zipped_file.filename.lower()
                clean_filename = lowered_name.split('/')[-1]
                
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

    # Scan the repo's commit history using the Atom feed and pull patch files to check for anything interesting
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
        log_msg(f"[green][✓] Clean:[/] {target_repo} [dim]({elapsed}s)[/]")
        return {"repo": target_repo, "url": repo_data.get("url"), "status": "clean", "ip": successful_ip, "time_taken": elapsed}

def paint_dashboard() -> Layout:
    with ui_mutex:
        global is_typing_url, input_buffer
        state_tag = "[bold green]▶ RUNNING[/]" if pause_event.is_set() else "[bold blink red]⏸ PAUSED (Press SPACE to Resume)[/]"
        top_bar_text = (
            f"{state_tag}  |  "
            f"[bold white]Queue Remaining:[/] {scoreboard['remaining']}  |  "
            f"[bold cyan]Scanned:[/] {scoreboard['scanned']}  |  "
            f"[bold green]Clean:[/] {scoreboard['clean']}  |  "
            f"[bold red]Leaks:[/] {scoreboard['leaks']}  |  "
            f"[bold yellow]Failed:[/] {scoreboard['failed']}"
        )
        
        thread_grid = Table(expand=True, border_style="cyan", padding=(0, 1))
        thread_grid.add_column("Worker", style="dim", width=10)
        thread_grid.add_column("Target Repository", width=28)
        thread_grid.add_column("Status / Progress", width=42)
        thread_grid.add_column("Active IP", width=20)
        thread_grid.add_column("Elapsed", justify="right", width=10)

        for thread_tag, current_state in thread_dashboard.items():
            time_spent = "-"
            
            target_str = current_state["target"]
            if len(target_str) > 25:
                target_str = target_str[:22] + "..."

            action_str = current_state["action"]
            
            if current_state["dl_bytes"] > 0 and "DL" in action_str:
                mb_downloaded = current_state["dl_bytes"] / (1024 * 1024)
                
                fill_ratio = min(1.0, current_state["dl_bytes"] / MAX_DOWNLOAD_SIZE_BYTES)
                blocks_filled = int(fill_ratio * 12)
                bar_graphic = "█" * blocks_filled + "░" * (12 - blocks_filled)
                
                action_str = f"[yellow]DL [{bar_graphic}] {mb_downloaded:.1f}MB[/]"

            if current_state["target"] != "Idle":
                if pause_event.is_set() and current_state["clock_start"] > 0:
                    seconds_passed = time.time() - current_state["clock_start"]
                    color_code = "green" if seconds_passed < 5 else "yellow" if seconds_passed < 15 else "red"
                    time_spent = f"[{color_code}]{seconds_passed:.1f}s[/]"
                else:
                    time_spent = "[dim]Paused[/]"

            thread_grid.add_row(thread_tag, target_str, action_str, current_state["active_ip"], time_spent)

        screen_layout = Layout()
        screen_layout.split_column(
            Layout(Panel(top_bar_text, title=f"[bold magenta]XeroDay-API Scanner 1.0 (Hunting {len(API_SIGNATURES)} API Types)[/]", border_style="magenta"), size=3),
            Layout(name="bottom_section")
        )
        
        input_prompt = "[yellow]Type URL and press Enter (Esc to cancel):[/] " if is_typing_url else "[dim]Press 'i' to manually insert a GitHub repo URL[/]"
        display_text = input_prompt + ("[bold white]" + input_buffer + "[/]" if is_typing_url else "")
        input_panel = Panel(display_text, title="[bold green]Manual Target Insertion[/]", border_style="green")

        left_layout = Layout(ratio=5)
        left_layout.split_column(
            Layout(Panel(thread_grid, title="[bold cyan]Active Thread Dashboard[/]", border_style="cyan")),
            Layout(input_panel, size=3)
        )
        
        screen_layout["bottom_section"].split_row(
            left_layout,
            Layout(name="logs_section", ratio=3)
        )
        
        system_feed = Text.from_markup("\n".join(log_history)) if log_history else Text("Awaiting events...", style="dim")
        bounty_feed = Text.from_markup("\n".join(leak_history)) if leak_history else Text("No leaks found yet.", style="dim")
        
        screen_layout["logs_section"].split_column(
            Layout(Panel(bounty_feed, title="[bold red]Recent Leaks Found[/]", border_style="red")),
            Layout(Panel(system_feed, title="[bold yellow]System Events[/]", border_style="yellow"))
        )
        return screen_layout

def thread_runner(repo_data: dict):
    with tag_mutex:
        thread_tag = available_thread_tags.popleft() if available_thread_tags else "Thread-Unknown"

    try:
        return dissect_repo_memory(repo_data, thread_tag)
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
    global exit_prog, active_proxies, new_manual_targets
    
    if not SCAN_HEROKU_KEYS and "Heroku API Key" in API_SIGNATURES:
        del API_SIGNATURES["Heroku API Key"]

    try:
        with open(QUEUE_JSON, "r", encoding="utf-8") as file_ptr:
            queued_targets = json.load(file_ptr)
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/] {QUEUE_JSON} not found. Run the fetcher first.")
        return

    if not queued_targets:
        console.print("[bold yellow]Queue is empty.[/] No new repositories to scan.")
        return

    active_proxies = read_proxies()
    scoreboard["total"] = len(queued_targets)
    scoreboard["remaining"] = len(queued_targets)
    
    threading.Thread(target=keyboard_monitor, daemon=True).start()
    log_msg("[bold green]Scanner initiated. Press SPACE to Pause/Resume.[/]")

    try:
        with Live(get_renderable=paint_dashboard, refresh_per_second=6, screen=True) as live_screen:
            with ThreadPoolExecutor(max_workers=MAX_THREADS) as thread_pool:
                pending_tasks = set()
                for target in queued_targets:
                    pending_tasks.add(thread_pool.submit(thread_runner, target))
                
                while pending_tasks or new_manual_targets:
                    while new_manual_targets:
                        new_t = new_manual_targets.pop(0)
                        pending_tasks.add(thread_pool.submit(thread_runner, new_t))
                        
                    if pending_tasks:
                        done_tasks, pending_tasks = wait(pending_tasks, timeout=0.25, return_when=FIRST_COMPLETED)
                        
                        for finished_task in done_tasks:
                            try:
                                task_outcome = finished_task.result()
                                if task_outcome["status"] == "leaked": dump_json_safely(LEAKS_JSON, task_outcome)
                                elif task_outcome["status"] == "failed": dump_json_safely(DEAD_TARGETS_JSON, task_outcome)
                                elif task_outcome["status"] == "clean": dump_json_safely(BORING_REPOS_JSON, task_outcome)
                                    
                                remove_from_queue(task_outcome.get("repo"))
                                bump_score("remaining", -1)
                            except Exception: pass
                        
                        live_screen.update(paint_dashboard())

        console.print("\n[bold green]Queue Exhausted. Scan Complete.[/]")
        
    finally:
        exit_prog = True

if __name__ == "__main__":
    main()