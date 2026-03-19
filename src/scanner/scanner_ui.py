# ---------------------------------------------------------------------------------- #
#                            Part of the X3r0Day project.                            #
# ---------------------------------------------------------------------------------- #

import time
from typing import List, Optional

from . import scanner_state as state


def update_thread_board(
    thread_tag: str,
    target: Optional[str] = None,
    action: Optional[str] = None,
    active_ip: Optional[str] = None,
    reset_timer: bool = False,
    dl_bytes: Optional[int] = None,
) -> None:
    with state.ui_mutex:
        if thread_tag not in state.thread_dashboard:
            return
        slot = state.thread_dashboard[thread_tag]
        if target is not None:
            slot["target"] = target
        if action is not None:
            slot["action"] = action
        if active_ip is not None:
            slot["active_ip"] = active_ip
        if reset_timer:
            slot["clock_start"] = time.time()
        if dl_bytes is not None:
            slot["dl_bytes"] = dl_bytes



def bump_score(metric: str, step: int = 1) -> None:
    with state.ui_mutex:
        state.scoreboard[metric] += step



def log_msg(msg: str) -> None:
    with state.ui_mutex:
        state.log_history.append(msg)


def log_dead_repo(target: str, crash_reason: str, ip: str, elapsed: float) -> None:
    with state.ui_mutex:
        state.fail_history.append(
            f"[red]{target}[/] - [dim]{crash_reason} ({elapsed}s via {ip})[/]"
        )


def log_loot(
    target: str,
    file_list: List[str],
    total_hits: int,
    api_types: set,
    ip: str,
    elapsed: float,
) -> None:
    short_files = ", ".join(file_list[:3]) + ("..." if len(file_list) > 3 else "")
    types_str = ", ".join(list(api_types))
    with state.ui_mutex:
        state.leak_history.append(
            f"[bold red]{target}[/] - {total_hits} secret(s) "
            f"([magenta]{types_str}[/]) in [yellow]{short_files}[/]"
            f"[dim] ({elapsed}s via {ip})[/]"
        )



def toggle_pause() -> None:
    from .scanner_proxy import read_proxies, set_active_proxies  # local import
    assert state.pause_event is not None
    if state.pause_event.is_set(): # type: ignore[union-attr]
        state.pause_event.clear()
        log_msg("[bold yellow][!] ⏸ PAUSE INITIATED: Halting all threads...[/]")
        with state.ui_mutex:
            for tag, slot in state.thread_dashboard.items():
                if slot["target"] != "Idle":
                    slot["action"] = "[bold red]⏸ PAUSED[/]"
    else:
        from . import scanner_proxy as _px
        _px.set_active_proxies(_px.read_proxies())
        log_msg(
            f"[bold green][▶] RESUMED: Reloaded {len(_px.get_active_proxies())} proxies "
            "and unfreezing threads.[/]"
        )
        state.pause_event.set()
