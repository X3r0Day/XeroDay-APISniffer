# ---------------------------------------------------------------------------------- #
#                            Part of the X3r0Day project.                            #
# ---------------------------------------------------------------------------------- #


from typing import List, Optional

from . import scanner_state as state



def read_proxies(filepath: Optional[str] = None) -> List[str]:
    filepath = filepath or state.PROXY_LIST_TXT
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            return [line.strip() for line in fh if line.strip()]
    except FileNotFoundError:
        return []


def set_active_proxies(proxy_list: List[str]) -> None:
    with state.proxy_lock:
        state.active_proxies.clear()
        state.active_proxies.extend(proxy_list)


def get_active_proxies() -> List[str]:
    with state.proxy_lock:
        return list(state.active_proxies)


def fmt_proxy(p: str) -> dict:
    base = p.strip()
    if "://" not in base:
        base = f"http://{base}"
    return {"http": base, "https": base}


def mark_proxy_ok(proxy_ip: str) -> None:
    # We keep the original string so it writes back exactly as the user provided.
    # Example: "http://1.2.3.4:8080" stays that way in live_proxies.txt.
    if not proxy_ip:
        return
    with state.good_proxy_lock:
        state.good_proxies.add(proxy_ip.strip())
    with state.proxy_lock:
        state.proxy_fail.pop(proxy_ip.strip(), None)


def mark_proxy_bad(proxy_ip: str, reason: bytes) -> None:
    # We only drop it after N fails so one bad hop doesn't nuke the list.
    p = proxy_ip.strip()
    with state.proxy_lock:
        cnt = state.proxy_fail.get(p, 0) + 1
        state.proxy_fail[p] = cnt
        if cnt < state.PROXY_FAIL_LIMIT:
            return
        if p in state.active_proxies:
            state.active_proxies.remove(p)
        state.proxy_fail.pop(p, None)
    with state.good_proxy_lock:
        state.good_proxies.discard(p)
    if state.UPDATE_PROXY_FILE:
        write_proxy_file(get_active_proxies())


def write_proxy_file(lines: List[str]) -> None:
    try:
        with open(state.PROXY_LIST_TXT, "w", encoding="utf-8") as fh:
            for line in lines:
                fh.write(f"{line}\n")
    except Exception:
        pass


def save_good_proxies(console=None) -> None:
    if not state.active_proxies or not state.UPDATE_PROXY_FILE:
        return
    with state.good_proxy_lock:
        kept = sorted(state.good_proxies)
    try:
        write_proxy_file(kept)
        if console:
            if kept:
                console.print(f"[bold green][+] Saved {len(kept)} working proxies to {state.PROXY_LIST_TXT}[/]")
            else:
                console.print(f"[bold yellow][!] No working proxies found. {state.PROXY_LIST_TXT} cleared.[/]")
    except Exception:
        if console:
            console.print(f"[bold red][X] Failed to update {state.PROXY_LIST_TXT}[/]")
