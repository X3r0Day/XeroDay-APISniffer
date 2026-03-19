# ---------------------------------------------------------------------------------- #
#                            Part of the X3r0Day project.                            #
# ---------------------------------------------------------------------------------- #


import os
import sys
import threading

from . import scanner_state as state
from .scanner_network import interruptible_sleep, raise_if_exit_requested
from .scanner_ui import toggle_pause
from .scanner_targets_live import submit_target_prompt
from .scanner_signals import install_signal_handlers, request_shutdown


def keyboard_monitor():
    try:
        import msvcrt
        is_windows = True
    except ImportError:
        import select, tty, termios
        is_windows = False

    if is_windows:
        import msvcrt
        while not state.exit_prog:
            if msvcrt.kbhit():
                char = msvcrt.getch()
                if char == b"\x03":
                    request_shutdown()
                    return
                if state.is_typing_url:
                    if char in[b'\r', b'\n']:
                        submitted_prompt = state.input_buffer
                        state.is_typing_url = False
                        state.input_buffer = ""
                        submit_target_prompt(submitted_prompt)
                    elif char == b'\x08': # Backspace
                        state.input_buffer = state.input_buffer[:-1]
                    elif char == b'\x1b': # Esc
                        state.is_typing_url = False
                        state.input_buffer = ""
                    else:
                        try:
                            state.input_buffer += char.decode('utf-8')
                        except Exception: pass
                else:
                    if char in [b' ', b' ']:
                        toggle_pause()
                        if not interruptible_sleep(0.3):
                            return
                    elif char.lower() == b'i':
                        state.is_typing_url = True
                        state.input_buffer = ""
            if not interruptible_sleep(0.1):
                return
    else:
        import select, tty, termios
        fd = sys.stdin.fileno()
        if not os.isatty(fd): return
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while not state.exit_prog:
                if select.select([sys.stdin],[],[], 0.1)[0]:
                    char = sys.stdin.read(1)
                    if char == "\x03":
                        request_shutdown()
                        return
                    if state.is_typing_url:
                        if char in ['\n', '\r']:
                            submitted_prompt = state.input_buffer
                            state.is_typing_url = False
                            state.input_buffer = ""
                            submit_target_prompt(submitted_prompt)
                        elif char in ['\x7f', '\b']: # Backspace
                            state.input_buffer = state.input_buffer[:-1]
                        elif char == '\x1b': # Esc
                            state.is_typing_url = False
                            state.input_buffer = ""
                        else:
                            state.input_buffer += char
                    else:
                        if char == ' ':
                            toggle_pause()
                            if not interruptible_sleep(0.3):
                                return
                        elif char.lower() == 'i':
                            state.is_typing_url = True
                            state.input_buffer = ""
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
