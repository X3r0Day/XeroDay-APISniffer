# ---------------------------------------------------------------------------------- #
#                            Part of the X3r0Day project.                            #
#              You are free to use, modify, and redistribute this code,              #
#          provided proper credit is given to the original project X3r0Day.          #
# ---------------------------------------------------------------------------------- #

##############################################################################################################################################################
#    So This code basically scrapes the repos and saves them in `recent_repos.json` file, and it uses proxy list if github API blocks/ratelimits your IP.    #
##############################################################################################################################################################

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
# Author:  XeroDay                                                                   #
# ---------------------------------------------------------------------------------- #


#--------------------------------------#
#     Error Codes and its meanings     #
# -------------------------------------#
#   422 = No more results after that   #
#   200 = OKAY/GOOD                    #
#   403 = Access Denied                #
#   404 = Not Found                    #
# ------------------------------------ #




import argparse
import json
import os
import random
import signal
import sys
import tempfile
import time
from pathlib import Path
from typing import List, Optional

from shared.requests_compat import requests

from datetime import (
    datetime,
    timedelta,
    timezone
)



LOOKBACK_MINS = 3     # 3 mins for now is enough unless you need bigger dataset
CHUNK_MINS = 1        # Time-slice per chunk

ROOT_DIR = Path(__file__).resolve().parent.parent
TARGET_QUEUE_FILE = str(ROOT_DIR / "recent_repos.json")
PROXY_FILE = str(ROOT_DIR / "live_proxies.txt")

RESULTS_PER_PAGE = 100   # GH only allows 100
PAGES_TO_SCRAPE = 10     # GH only allows 10
NET_TIMEOUT = 10
PROXY_RETRY_LIMIT = 200

MAX_SPLIT_DEPTH = 10

SCANNED_HISTORY = [
    str(ROOT_DIR/"clean_repos.json"),
    str(ROOT_DIR/"failed_repos.json"),
    str(ROOT_DIR/"leaked_keys.json"),
]

SPOOFED_UA = "XeroDay-APISniffer/1.0"
shutdown_requested = False
MODES = ["new", "trending", "relevant"]


class DiscoveryRequestError(RuntimeError):
    pass


def parse_args():
    parser = argparse.ArgumentParser(description="Discover recent GitHub repositories.")
    parser.add_argument("--lookback-mins", type=int, help="How far back to search for repositories.")
    parser.add_argument("--chunk-mins", type=int, help="Time window per query chunk.")
    parser.add_argument("--pages-to-scrape", type=int, help="Maximum GitHub result pages to fetch per chunk.")
    parser.add_argument("--proxy-retry-limit", type=int, help="Maximum proxies to try before giving up.")
    parser.add_argument("--modes", type=str, help="Comma-separated list of scan modes: new,trending,relevant")
    return parser.parse_args()


def apply_runtime_overrides(args) -> None:
    global LOOKBACK_MINS, CHUNK_MINS, PAGES_TO_SCRAPE, PROXY_RETRY_LIMIT, MODES

    if args.lookback_mins is not None:
        LOOKBACK_MINS = max(1, args.lookback_mins)
    if args.chunk_mins is not None:
        CHUNK_MINS = max(1, args.chunk_mins)
    if args.pages_to_scrape is not None:
        PAGES_TO_SCRAPE = max(1, args.pages_to_scrape)
    if args.proxy_retry_limit is not None:
        PROXY_RETRY_LIMIT = max(1, args.proxy_retry_limit)
    if args.modes is not None:
        valid_modes = {"new", "trending", "relevant"}
        parsed_modes = [m.strip().lower() for m in args.modes.split(",")]
        MODES = [m for m in parsed_modes if m in valid_modes]
        if not MODES:
            MODES = ["new", "trending", "relevant"]


def grab_proxies(filepath: str = PROXY_FILE) -> List[str]:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []


def get_search_query(start_time: datetime, end_time: datetime, page: int = 1, query_type: str = "new") -> dict:
    start_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    if query_type == "trending":
        return {
            "q": f"pushed:{start_str}..{end_str} stars:>50",
            "sort": "stars",
            "order": "desc",
            "per_page": RESULTS_PER_PAGE,
            "page": page,
        }
    elif query_type == "relevant":
        return {
            "q": f"API OR LLM OR key OR secret OR security pushed:{start_str}..{end_str}",
            "per_page": RESULTS_PER_PAGE,
            "page": page,
        }
    else:  # "new"
        return {
            "q": f"created:{start_str}..{end_str}",
            "sort": "created",
            "order": "desc",
            "per_page": RESULTS_PER_PAGE,
            "page": page,
        }


def format_proxy_dict(ip_port: str) -> dict:
    return {"http": f"http://{ip_port}", "https": f"http://{ip_port}"}

# Will remove proxy if bad proxy.
def remove_proxy(proxy_pool: List[str], proxy_ip: str) -> None:
    try:
        proxy_pool.remove(proxy_ip)
    except ValueError:
        pass


def request_shutdown(_signum, _frame) -> None:
    global shutdown_requested
    if shutdown_requested:
        raise KeyboardInterrupt
    shutdown_requested = True
    print(
        "\n[!] Ctrl+C received. Stopping after the current request. "
        "Anything already written to recent_repos.json is safe.",
        flush=True,
    )


def install_signal_handlers() -> None:
    signal.signal(signal.SIGINT, request_shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, request_shutdown)


def interruptible_sleep(seconds: float) -> bool:
    deadline = time.time() + max(0.0, seconds)
    while time.time() < deadline:
        if shutdown_requested:
            return False
        time.sleep(min(0.1, deadline - time.time()))
    return not shutdown_requested


def write_json_snapshot(payload: list, filename: str) -> None:
    directory = os.path.dirname(os.path.abspath(filename)) or "."
    file_prefix = f".{os.path.basename(filename)}."
    file_descriptor, temp_path = tempfile.mkstemp(prefix=file_prefix, suffix=".tmp", dir=directory)

    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as file_ptr:
            json.dump(payload, file_ptr, indent=4)
            file_ptr.flush()
            os.fsync(file_ptr.fileno())
        os.replace(temp_path, filename)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def ensure_json_list_file(filename: str) -> None:
    if os.path.exists(filename):
        return
    write_json_snapshot([], filename)

def get_github_token() -> Optional[str]:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        return None
    token = token.strip()
    return token or None

def build_github_headers() -> dict:
    headers = {"User-Agent": SPOOFED_UA}
    token_value = get_github_token()
    if token_value:
        normalized = token_value.strip()
        lowered = normalized.lower()
        if lowered.startswith("bearer ") or lowered.startswith("token "):
            headers["Authorization"] = normalized
        else:
            headers["Authorization"] = f"Bearer {normalized}"
    return headers




def make_request(
    session_obj: requests.Session, endpoint: str, query: dict, ips: List[str]
) -> requests.Response:
    if shutdown_requested:
        raise KeyboardInterrupt

    browser_headers = build_github_headers()
    direct_error: Optional[Exception] = None

    # Try with our real IP first
    try:
        req = session_obj.get(
            endpoint, params=query, headers=browser_headers, timeout=NET_TIMEOUT
        )
    except requests.RequestException as exc:
        direct_error = exc
        req = None

    if req is not None and req.status_code == 200:
        return req

    # If blocked or failed, then it'll just use proxylist
    if not ips:
        if req is None:
            raise DiscoveryRequestError("Direct connection failed and no proxies loaded.") from direct_error
        return req

    pool = ips[:]
    random.shuffle(pool)

    tried = 0
    last_error: Optional[Exception] = direct_error
    for ip in pool:
        if tried >= PROXY_RETRY_LIMIT:
            break
        tried += 1

        proxies = format_proxy_dict(ip)
        try:
            r = session_obj.get(
                endpoint,
                params=query,
                headers=browser_headers,
                proxies=proxies,
                timeout=NET_TIMEOUT,
            )
            if r.status_code == 200:
                print(f"[+] Success using proxy: {ip}")
                return r
            print(f"[-] Proxy {ip} hit status {r.status_code}. Skipping...")
            if not interruptible_sleep(0.25):
                raise KeyboardInterrupt
        except requests.RequestException as e:
            last_error = e
            remove_proxy(ips, ip)
            print(f"[-] Proxy {ip} failed with {type(e).__name__}. Removing it from the pool.")
            if not interruptible_sleep(0.15):
                raise KeyboardInterrupt
            continue

    if req is not None:
        return req

    if last_error is not None:
        raise DiscoveryRequestError(
            f"Direct request failed and no working proxies remained. Last error: {last_error}"
        ) from last_error
    raise DiscoveryRequestError("Exhausted all options. No response.")


def sync_results_to_disk(raw_json: dict, filename: str = TARGET_QUEUE_FILE):
    incoming_data = raw_json.get("items", [])
    if not incoming_data:
        return 0

    blacklist = set()
    current_queue = []

    if os.path.exists(filename):
        try:
            with open(filename, "r", encoding="utf-8") as f:
                current_queue = json.load(f)
                for item in current_queue:
                    blacklist.add(item.get("name"))
        except json.JSONDecodeError:
            pass

    for log_file in SCANNED_HISTORY:
        if os.path.exists(log_file):
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    done_data = json.load(f)
                    for entry in done_data:
                        repo_id = entry.get("repo") or entry.get("name")
                        if repo_id:
                            blacklist.add(repo_id)
            except json.JSONDecodeError:
                pass

    new_finds = 0
    for entry in incoming_data:
        full_path = entry["full_name"]
        if full_path not in blacklist:
            current_queue.append(
                {
                    "name": full_path,
                    "created_at": entry["created_at"],
                    "url": entry["html_url"],
                    "stars": entry.get("stargazers_count", 0),
                }
            )
            blacklist.add(full_path)
            new_finds += 1

    current_queue.sort(key=lambda x: x["created_at"], reverse=True)
    write_json_snapshot(current_queue, filename)

    return new_finds





def main():
    global shutdown_requested
    shutdown_requested = False
    ensure_json_list_file(TARGET_QUEUE_FILE)

    api_url = "https://api.github.com/search/repositories"
    proxies = grab_proxies()

    print(f"[*] Scouring GitHub for repos from the last {LOOKBACK_MINS} minutes "
          f"(using {CHUNK_MINS}-min chunks with adaptive bisection)...")
    if proxies:
        print(f"[*] Loaded {len(proxies)} proxies as fallback.")
    else:
        print("[*] No proxies loaded. Using direct connection only.")

    http_session = requests.Session()
    total_new_finds = 0
    interrupted = False

    try:
        now = datetime.now(timezone.utc)
        newest = now - timedelta(minutes=LOOKBACK_MINS)

        chunks = []
        cursor = newest
        while cursor < now:
            chunk_end = min(cursor + timedelta(minutes=CHUNK_MINS), now)
            # Add chunks for each query mode defined in MODES
            if "new" in MODES:
                chunks.append((cursor, chunk_end, "new"))
            if "trending" in MODES:
                chunks.append((cursor, chunk_end, "trending"))
            if "relevant" in MODES:
                chunks.append((cursor, chunk_end, "relevant"))
            cursor = chunk_end

        # We process newest first, so reverse to use as a queue/stack
        chunks.reverse()

        print(f"[*] Planning to scan {len(chunks)} chunks")
        print(f"[*] Time range: {newest.strftime('%H:%M:%S')} → {now.strftime('%H:%M:%S')} UTC\n")

        chunk_idx = 0
        while chunks:
            if shutdown_requested:
                interrupted = True
                break

            chunk_item = chunks.pop(0)
            if len(chunk_item) == 2:
                start_time, end_time = chunk_item
                query_type = "new"
            else:
                start_time, end_time, query_type = chunk_item

            chunk_idx += 1
            
            t_start = start_time.strftime('%H:%M:%S')
            t_end = end_time.strftime('%H:%M:%S')

            print(f"{'='*60}")
            print(f"[Chunk {chunk_idx}] {t_start} -> {t_end} UTC | Type: {query_type}")

            api_query = get_search_query(start_time, end_time, page=1, query_type=query_type)
            try:
                req = make_request(http_session, api_url, api_query, proxies)
            except DiscoveryRequestError as exc:
                print(f"  [-] Chunk request failed. Skipping chunk. {exc}")
                continue

            if req.status_code == 422:
                print("  [-] Target chunk rejected (422). Moving on.")
                continue
            elif req.status_code != 200:
                print(f"  [-] Request failed with status {req.status_code}")
                continue

            raw_json = req.json()
            repo_count = raw_json.get("total_count", 0)
            found_repos = raw_json.get("items", [])

            if not found_repos:
                print("  [-] Ghost town. No repos born in this chunk.")
                continue

            print(f"  [i] Sniffer shows {repo_count} newborn repos here")

            # 1k hard cap 
            if repo_count >= 1000:
                mid_point = start_time + (end_time - start_time) / 2
                # Don't split if it's less than a second wide, that's just silly
                if (mid_point - start_time).total_seconds() < 1:
                    print("  [!] Chunk can't be split further. Grabbing what we fetched...")
                else:
                    print(f"  [↓] The {repo_count} hits the 1k cap! Slicing chunk in half...")
                    # Insert the two halves (newer half first)
                    chunks.insert(0, (start_time, mid_point, query_type))
                    chunks.insert(0, (mid_point, end_time, query_type))
                    chunk_idx -= 1
                    continue

            pages_needed = min((repo_count + RESULTS_PER_PAGE - 1) // RESULTS_PER_PAGE, PAGES_TO_SCRAPE)

            saved_this_chunk = sync_results_to_disk(raw_json)
            total_new_finds += saved_this_chunk
            print(f"  -> Siphoned Page 1/{pages_needed}: +{saved_this_chunk} fresh targets")

            for page_num in range(2, pages_needed + 1):
                if shutdown_requested:
                    interrupted = True
                    break
                if not interruptible_sleep(2):
                    interrupted = True
                    break

                api_query = get_search_query(start_time, end_time, page=page_num, query_type=query_type)
                print(f"  -> Fetching Page {page_num}/{pages_needed}...")

                try:
                    req = make_request(http_session, api_url, api_query, proxies)
                except DiscoveryRequestError as exc:
                    print(f"  [-] Page {page_num} request failed. Stopping this chunk. {exc}")
                    break

                if req.status_code == 422:
                    print("  [-] Reached max pagination limit. Bailing out.")
                    break
                elif req.status_code != 200:
                    print(f"  [-] Page {page_num} died with status {req.status_code}.")
                    break

                page_json = req.json()
                current_items = page_json.get("items", [])

                if not current_items:
                    print("  [-] Empty page, breaking out.")
                    break

                loot = sync_results_to_disk(page_json)
                total_new_finds += loot
                print(f"     +{loot} fresh targets")

                if len(current_items) < RESULTS_PER_PAGE and page_num < pages_needed:
                    print(
                        f"  [!] Page {page_num} returned only {len(current_items)} results, "
                        "but GitHub reported more pages. Continuing anyway..."
                    )

    except KeyboardInterrupt:
        interrupted = True
        print("\n[!] Discovery interrupted by user. Recent results already saved to disk.", flush=True)

    finally:
        http_session.close()

    print(f"\n{'='*60}")
    if interrupted or shutdown_requested:
        print(f"[!] Stopped early. Saved {total_new_finds} new targets to the queue so far.")
    else:
        print(f"[+] Done! Successfully added {total_new_finds} total new targets to the queue.")




if __name__ == "__main__":
    install_signal_handlers()
    apply_runtime_overrides(parse_args())
    main()
