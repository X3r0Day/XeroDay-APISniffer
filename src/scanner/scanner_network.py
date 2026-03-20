# ---------------------------------------------------------------------------------- #
#                            Part of the X3r0Day project.                            #
# ---------------------------------------------------------------------------------- #


import os
import random
import time
from typing import List, Optional, Tuple

from . import scanner_state as state
from .scanner_proxy import fmt_proxy, get_active_proxies, mark_proxy_bad, mark_proxy_ok
from shared.requests_compat import requests



def get_github_token() -> Optional[str]:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        return None
    token = token.strip()
    return token or None


def build_github_headers(token: Optional[str] = None) -> dict:
    headers = {"User-Agent": state.SPOOFED_USER_AGENT}
    token_value = token if token is not None else get_github_token()
    if token_value:
        normalized = token_value.strip()
        lowered = normalized.lower()
        if lowered.startswith("bearer ") or lowered.startswith("token "):
            headers["Authorization"] = normalized
        else:
            headers["Authorization"] = f"Bearer {normalized}"
    return headers


class ScanInterrupted(Exception):
    pass


def raise_if_exit_requested() -> None:
    if state.exit_prog:
        raise ScanInterrupted


def interruptible_sleep(seconds: float) -> bool:
    deadline = time.time() + max(0.0, seconds)
    while time.time() < deadline:
        if state.exit_prog:
            return False
        time.sleep(min(0.1, deadline - time.time()))
    return not state.exit_prog


def check_pause(thread_tag: str, current_action: str, current_ip: str) -> None:
    from .scanner_ui import update_thread_board  # local import to avoid cycle
    assert state.pause_event is not None
    while not state.pause_event.is_set():
        raise_if_exit_requested()
        update_thread_board(thread_tag, action="[bold red]⏸ PAUSED[/]", active_ip="-")
        state.pause_event.wait(0.1)
    raise_if_exit_requested()
    update_thread_board(thread_tag, action=current_action, active_ip=current_ip)


def fetch_with_progress(
    url: str,
    headers: dict,
    proxy_dict: Optional[dict],
    thread_tag: str,
    ip_str: str,
    action_label: str,
    tmo: Optional[Tuple[float, float]] = None,
) -> bytes:
    from .scanner_ui import update_thread_board  # local import to avoid cycle
    if tmo is None:
        tmo = state.NET_TIMEOUTS

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
                if not state.pause_event.is_set(): # type: ignore[union-attr]
                    check_pause(thread_tag, action_label, ip_str)
                    last_chunk_time = time.time()

                if time.time() - last_chunk_time > state.IDLE_STALL_TIMEOUT_SEC:
                    return b"TIMEOUT"

                if chunk:
                    last_chunk_time = time.time()
                    content.extend(chunk)
                    total_bytes += len(chunk)

                    if total_bytes > state.MAX_DOWNLOAD_SIZE_BYTES:
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


def is_fail(val: Optional[bytes]) -> bool:
    return isinstance(val, bytes) and (
        val in [b"FAILED", b"TIMEOUT", b"RATE_LIMITED", b"FORBIDDEN",
                b"CONN_DROPPED", b"CONN_ERROR", b"FAILED_EXC"]
        or val.startswith(b"FAILED")
    )


def try_proxies(
    target_url: str,
    http_headers: dict,
    thread_tag: str,
    action_label: str,
) -> Tuple[Optional[bytes], str]:
    from .scanner_ui import update_thread_board  # local import

    mixed = get_active_proxies()
    if not mixed:
        return b"FAILED", "-"
    random.shuffle(mixed)
    for proxy_ip in mixed:
        raise_if_exit_requested()
        check_pause(thread_tag, "[cyan]Testing Proxy...[/]", proxy_ip)
        update_thread_board(thread_tag, action="[cyan]Testing Proxy...[/]", active_ip=proxy_ip, dl_bytes=0)
        proxy_dict = fmt_proxy(proxy_ip)
        out = fetch_with_progress(
            target_url, http_headers, proxy_dict, thread_tag, proxy_ip,
            action_label, state.PROXY_TIMEOUTS,
        )
        if out == b"NOT_FOUND":
            mark_proxy_ok(proxy_ip)
            return None, proxy_ip
        if out == b"TOO_LARGE":
            mark_proxy_ok(proxy_ip)
            return b"TOO_LARGE", proxy_ip
        if not is_fail(out):
            mark_proxy_ok(proxy_ip)
            return out, proxy_ip
        if out in [b"TIMEOUT", b"CONN_DROPPED", b"CONN_ERROR", b"FAILED_EXC"] or \
                (isinstance(out, bytes) and out.startswith(b"FAILED")) or out == b"FORBIDDEN":
            mark_proxy_bad(proxy_ip, out)
    return b"FAILED", "All Proxies Failed"


def download_github_url(
    target_url: str,
    thread_tag: str,
    action_label: str,
) -> Tuple[Optional[bytes], str]:
    from .scanner_ui import update_thread_board  # local import

    raise_if_exit_requested()
    http_headers = build_github_headers()
    res = b"FAILED"
    tried_proxies = False

    # Prefer proxy first when requested (handy for testing).
    if state.PREFER_PROXY and get_active_proxies():
        tried_proxies = True
        res, ip = try_proxies(target_url, http_headers, thread_tag, action_label)
        if res is None or res == b"TOO_LARGE" or not is_fail(res):
            return res, ip

    for attempt in range(6):
        raise_if_exit_requested()
        action_str = "[yellow]Connecting...[/]" if attempt == 0 else f"[yellow]Retrying Direct ({attempt}/5)...[/]"
        check_pause(thread_tag, action_str, "Direct IP")
        update_thread_board(thread_tag, action=action_str, active_ip="Direct IP", dl_bytes=0)

        res = fetch_with_progress(target_url, http_headers, None, thread_tag, "Direct IP", action_label)

        if res == b"NOT_FOUND":
            return None, "Direct IP"
        if res == b"TOO_LARGE":
            return b"TOO_LARGE", "Direct IP"
        if not is_fail(res):
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
    return try_proxies(target_url, http_headers, thread_tag, action_label)
