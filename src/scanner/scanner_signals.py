# ---------------------------------------------------------------------------------- #
#                            Part of the X3r0Day project.                            #
# ---------------------------------------------------------------------------------- #


import signal

from . import scanner_state as state
from .scanner_ui import log_msg


def request_shutdown(_signum=None, _frame=None) -> None:
    if state.exit_prog:
        return
    state.exit_prog = True
    if state.pause_event:
        state.pause_event.set()
    log_msg("[bold yellow][!] Stop requested. Finishing active work.[/]")


def install_signal_handlers() -> None:
    signal.signal(signal.SIGINT, request_shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, request_shutdown)