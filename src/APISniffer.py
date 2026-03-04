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





import json
import os
import random
import time
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import requests


LOOKBACK_MINS = 100 # Last 100 mins, this is enough for 1k results [my observations marked its more than enough, and github is not flooded with repo every minute]
TARGET_QUEUE_FILE = "recent_repos.json"
PROXY_FILE = "live_proxies.txt"
RESULTS_PER_PAGE = 100
PAGES_TO_SCRAPE = 10  # gh provides 100 results per page
NET_TIMEOUT = 10
PROXY_RETRY_LIMIT = 200


SCANNED_HISTORY = ["clean_repos.json", "failed_repos.json", "leaked_keys.json"]

SPOOFED_UA = "XeroDay-APISniffer/1.0"


def grab_proxies(filepath: str = PROXY_FILE) -> List[str]:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return []


def get_search_query(minutes: int = LOOKBACK_MINS, page: int = 1) -> dict:
    timestamp = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    return {
        "q": f"created:>{timestamp}",
        "sort": "created",
        "order": "desc",
        "per_page": RESULTS_PER_PAGE,
        "page": page,
    }


def format_proxy_dict(ip_port: str) -> dict:
    return {"http": f"http://{ip_port}", "https": f"http://{ip_port}"}


def robust_request(
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

    print(f"[*] Scouring GitHub for repos from the last {LOOKBACK_MINS} minutes...")

    http_session = requests.Session()
    total_new_finds = 0

    try:
        for current_page in range(1, PAGES_TO_SCRAPE + 1):
            search_params = get_search_query(page=current_page)
            print(f"[*] Fetching Page {current_page}...")

            api_response = robust_request(http_session, api_url, search_params, proxies)

            if api_response.status_code != 200:
                print(f"[-] Attempt failed with status: {api_response.status_code}")
                try:
                    print(api_response.json())
                except Exception:
                    pass
                break

            response_data = api_response.json()

            if not response_data.get("items"):
                print("[-] No more repositories found.")
                break

            finds_on_page = sync_results_to_disk(response_data)
            total_new_finds += finds_on_page

            time.sleep(2)

    finally:
        http_session.close()

    print(
        f"\n[+] Done! Successfully added {total_new_finds} total new targets to the queue."
    )


if __name__ == "__main__":
    main()