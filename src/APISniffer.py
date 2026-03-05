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
# Author: XeroDay                                                                    #
# ---------------------------------------------------------------------------------- #


#--------------------------------------#
#     Error Codes and its meanings     #
# -------------------------------------#
#   422 = No more results after that   #
#   200 = OKAY/GOOD                    #
#   403 = Access Denied                #
#   404 = Not Found                    #
# ------------------------------------ #




import json
import os
import random
import time
import sys
import requests
from typing import List, Optional

from datetime import (
    datetime,
    timedelta,
    timezone
)



LOOKBACK_MINS = 4     # 20 mins for now is enough unless you need bigger dataset
CHUNK_MINS = 1        # Time-slice per chunk
TARGET_QUEUE_FILE = "recent_repos.json"
PROXY_FILE = "live_proxies.txt"
RESULTS_PER_PAGE = 100
PAGES_TO_SCRAPE = 10  # GH only allows 1k
NET_TIMEOUT = 10
PROXY_RETRY_LIMIT = 200

MAX_SPLIT_DEPTH = 10

SCANNED_HISTORY = ["clean_repos.json", "failed_repos.json", "leaked_keys.json"]

SPOOFED_UA = "XeroDay-APISniffer/1.0"


def grab_proxies(filepath: str = PROXY_FILE) -> List[str]:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []


def get_search_query(datetime, end_time: datetime, page: int = 1) -> dict:
    start_str = datetime.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "q": f"created:{start_str}..{end_str}",
        "sort": "created",
        "order": "desc",
        "per_page": RESULTS_PER_PAGE,
        "page": page,
    }


def format_proxy_dict(ip_port: str) -> dict:
    return {"http": f"http://{ip_port}", "https": f"http://{ip_port}"}




def make_request(
    session_obj: requests.Session, endpoint: str, query: dict, ips: List[str]
) -> requests.Response:
    browser_headers = {"User-Agent": SPOOFED_UA}

    # Try with our real IP first
    try:
        req = session_obj.get(
            endpoint, params=query, headers=browser_headers, timeout=NET_TIMEOUT
        )
    except requests.RequestException:
        req = None

    if req is not None and req.status_code == 200:
        return req

    # If blocked or failed, then it'll just use proxylist
    if not ips:
        if req is None:
            raise SystemExit("Direct connection failed and no proxies loaded.")
        return req

    pool = ips[:]
    random.shuffle(pool)

    tried = 0
    last_error = None
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
            time.sleep(0.25)
        except requests.RequestException as e:
            last_error = e
            time.sleep(0.15)
            continue

    if req is not None:
        return req
    if last_error is not None:
        raise SystemExit(f"All proxies died. Last error: {last_error}")
    raise SystemExit("Exhausted all options. No response.")


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

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(current_queue, f, indent=4)

    return new_finds





def main():
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

    try:
        now = datetime.now(timezone.utc)
        newest = now - timedelta(minutes=LOOKBACK_MINS)

        chunks = []
        cursor = newest
        while cursor < now:
            chunk_end = min(cursor + timedelta(minutes=CHUNK_MINS), now)
            chunks.append((cursor, chunk_end))
            cursor = chunk_end

        # We process newest first, so reverse to use as a queue/stack
        chunks.reverse()

        print(f"[*] Planning to scan {len(chunks)} chunks")
        print(f"[*] Time range: {newest.strftime('%H:%M:%S')} → {now.strftime('%H:%M:%S')} UTC\n")

        chunk_idx = 0
        while chunks:
            start_time, end_time = chunks.pop(0)
            chunk_idx += 1
            
            t_start = start_time.strftime('%H:%M:%S')
            t_end = end_time.strftime('%H:%M:%S')

            print(f"{'='*60}")
            print(f"[Chunk {chunk_idx}] {t_start} -> {t_end} UTC")

            api_query = get_search_query(start_time, end_time, page=1)
            req = make_request(http_session, api_url, api_query, proxies)

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
                    chunks.insert(0, (start_time, mid_point))
                    chunks.insert(0, (mid_point, end_time))
                    chunk_idx -= 1
                    continue

            pages_needed = min((repo_count + RESULTS_PER_PAGE - 1) // RESULTS_PER_PAGE, PAGES_TO_SCRAPE)

            saved_this_chunk = sync_results_to_disk(raw_json)
            total_new_finds += saved_this_chunk
            print(f"  -> Siphoned Page 1/{pages_needed}: +{saved_this_chunk} fresh targets")

            if len(found_repos) < RESULTS_PER_PAGE:
                continue

            for page_num in range(2, pages_needed + 1):
                time.sleep(2)

                api_query = get_search_query(start_time, end_time, page=page_num)
                print(f"  -> Fetching Page {page_num}/{pages_needed}...")

                req = make_request(http_session, api_url, api_query, proxies)

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

                if len(current_items) < RESULTS_PER_PAGE:
                    break

    finally:
        http_session.close()

    print(f"\n{'='*60}")
    print(f"[+] Done! Successfully added {total_new_finds} total new targets to the queue.")




if __name__ == "__main__":
    main()