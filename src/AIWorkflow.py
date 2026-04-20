#!/usr/bin/env python3
# ---------------------------------------------------------------------------------- #
#                            Part of the X3r0Day project.                            #
#              You are free to use, modify, and redistribute this code,              #
#          provided proper credit is given to the original project X3r0Day.          #
# ---------------------------------------------------------------------------------- #


############################################################################################################################
#      So This code basically uses an LLM to To basically handle all the workflow which you had to do manually before      #
############################################################################################################################


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
# Author: XeroDay                                                                    #
# ---------------------------------------------------------------------------------- #




import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table
from shared.ai_client import ask_json, get_key
from shared.ai_policy import fill_tpl, load_pol
from shared.ai_search_runtime import run_single_query


try:
    import termios
except ImportError:
    termios = None


ROOT_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT_DIR / "src"
POL = {}

console = Console()


def capture_terminal_state():
    if os.name == "nt" or termios is None or not sys.stdin.isatty():
        return None
    try:
        return termios.tcgetattr(sys.stdin.fileno())
    except termios.error:
        return None


def restore_terminal_state(state) -> None:
    if state is None or os.name == "nt" or termios is None or not sys.stdin.isatty():
        return
    try:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, state)
    except termios.error:
        pass


def launch_stage(stage_name: str, script_name: str, extra_args: Optional[List[str]] = None) -> bool:
    target_script = SRC_DIR / script_name
    if not target_script.exists():
        console.print(Panel.fit(f"[bold red][X] Missing stage file:[/] {target_script}", border_style="red"))
        return False

    command = [sys.executable, str(target_script), *(extra_args or [])]
    console.print(
        Panel.fit(
            f"[bold cyan]Executing:[/] {stage_name}\n[dim]{' '.join(command)}[/]",
            border_style="cyan",
        )
    )

    terminal_state = capture_terminal_state()
    try:
        completed = subprocess.run(
            command,
            cwd=str(ROOT_DIR),
            check=False,
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr,
        )
    except KeyboardInterrupt:
        console.print("\n[bold yellow][!] Workflow stage interrupted by user.[/]")
        return False
    finally:
        restore_terminal_state(terminal_state)

    if completed.returncode == 0:
        console.print(f"[bold green][+] {stage_name} finished successfully.[/]")
        return True

    console.print(f"[bold red][X] {stage_name} exited with code {completed.returncode}.[/]")
    return False


def clamp_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, number))


def normalize_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "1", "on"}:
            return True
        if lowered in {"false", "no", "0", "off"}:
            return False
    return default


def _acts(pol: Dict[str, Any]) -> Dict[str, Any]:
    wf = pol.get("workflow", {}) if isinstance(pol, dict) else {}
    acts = wf.get("actions", {}) if isinstance(wf, dict) else {}
    return acts if isinstance(acts, dict) else {}


def _act_defaults(pol: Dict[str, Any], act: str) -> Dict[str, Any]:
    acts = _acts(pol)
    params = acts.get(act, {}).get("params", {})
    out = {}
    for key, cfg in (params or {}).items():
        if isinstance(cfg, dict) and "default" in cfg:
            out[key] = cfg.get("default")
        elif isinstance(cfg, dict) and "min" in cfg:
            out[key] = cfg.get("min")
    return out


def normalize_action(action: Any, pol: Dict[str, Any]) -> Optional[str]:
    if not isinstance(action, str):
        return None
    act = action.strip()
    return act if act in _acts(pol) else None


def _norm_param(val: Any, cfg: Dict[str, Any]) -> Any:
    # We clamp ints so a model output like "9999 threads" becomes <=128.
    if "min" in cfg or "max" in cfg:
        return clamp_int(val, cfg.get("default", cfg.get("min", 1)), cfg.get("min", 1), cfg.get("max", 1))
    if isinstance(cfg.get("default"), bool):
        return normalize_bool(val, cfg.get("default"))
    return cfg.get("default") if val is None else val


def normalize_plan(raw_plan: Dict[str, Any], pol: Dict[str, Any]) -> Dict[str, Any]:
    steps_out: List[Dict[str, Any]] = []
    raw_steps = raw_plan.get("steps", [])
    if not isinstance(raw_steps, list):
        raw_steps = []

    for raw_step in raw_steps:
        if not isinstance(raw_step, dict):
            continue
        act = normalize_action(raw_step.get("action"), pol)
        if act is None:
            continue

        params = raw_step.get("params") or {}
        cfg = _acts(pol).get(act, {}).get("params", {}) or {}
        norm_params = {key: _norm_param(params.get(key), cfg[key]) for key in cfg}
        steps_out.append({"action": act, "params": norm_params})

    return {
        "understanding": str(raw_plan.get("understanding", "Generated workflow plan.")).strip() or "Generated workflow plan.",
        "steps": steps_out,
    }


def normalize_route(raw_route: Dict[str, Any], pol: Dict[str, Any]) -> Dict[str, Any]:
    norm = normalize_plan(raw_route, pol)
    mode = str(raw_route.get("mode", "workflow")).strip().lower()
    if mode not in {"query", "workflow", "chat"}:
        mode = "workflow" if norm["steps"] else "query"
    norm["mode"] = mode
    norm["reply"] = str(raw_route.get("reply", "")).strip() if isinstance(raw_route, dict) else ""
    if mode in {"query", "chat"}:
        norm["steps"] = []
    return norm


def ask_ai_for_route(user_request: str, api_key: str, pol: Dict[str, Any]) -> Dict[str, Any]:
    acts = list(_acts(pol).keys())
    rep = {
        "__ALLOWED_ACTIONS__": json.dumps(acts),
        "__DISCOVERY_DEFAULTS__": json.dumps(_act_defaults(pol, "discovery")),
        "__SCANNER_DEFAULTS__": json.dumps(_act_defaults(pol, "scanner")),
    }
    sys_tpl = str(pol.get("router", {}).get("system", "")).strip()
    if not sys_tpl:
        raise RuntimeError("AI router policy missing.")
    sys_txt = fill_tpl(sys_tpl, rep)
    msgs = [
        {"role": "system", "content": sys_txt},
        {"role": "user", "content": user_request},
    ]
    cfg = pol.get("llm", {})
    return ask_json(msgs, api_key, cfg)


def build_stage_invocation(step: Dict[str, Any]) -> Dict[str, Any]:
    action = step["action"]
    params = step["params"]

    if action == "discovery":
        args = [
            "--lookback-mins",
            str(params["lookback_mins"]),
            "--chunk-mins",
            str(params["chunk_mins"]),
            "--pages-to-scrape",
            str(params["pages_to_scrape"]),
            "--proxy-retry-limit",
            str(params["proxy_retry_limit"]),
        ]
        if "modes" in params:
            args.extend(["--modes", str(params["modes"])])

        return {
            "name": "Discovery Engine",
            "script": "APISniffer.py",
            "args": args,
        }

    if action == "scanner":
        args = [
            "--max-threads",
            str(params["max_threads"]),
            "--history-depth",
            str(params["history_depth"]),
        ]
        if not params["scan_commit_history"]:
            args.append("--no-commit-history")
        if params["scan_heroku_keys"]:
            args.append("--scan-heroku-keys")
        return {
            "name": "Leak Scanner",
            "script": "APIScanner.py",
            "args": args,
        }

    if action == "verifier":
        return {
            "name": "API Verifier",
            "script": "APIVerifier.py",
            "args": [],
        }

    return {
        "name": "AI Query Engine",
        "script": "AISearch.py",
        "args": [],
    }


def render_plan(plan: Dict[str, Any]) -> None:
    console.print(Panel.fit(f"[bold green]Workflow Understanding[/]\n{plan['understanding']}", border_style="green"))

    plan_table = Table(expand=True, border_style="magenta", title="[bold magenta]Execution Plan[/]")
    plan_table.add_column("Step", width=6, justify="right")
    plan_table.add_column("Action", style="cyan", width=18)
    plan_table.add_column("Parameters", style="white")

    for idx, step in enumerate(plan["steps"], 1):
        params = step["params"]
        if params:
            rendered_params = ", ".join(f"{key}={value}" for key, value in params.items())
        else:
            rendered_params = "-"
        plan_table.add_row(str(idx), step["action"], rendered_params)

    console.print(plan_table)


def execute_plan(plan: Dict[str, Any]) -> None:
    if not plan["steps"]:
        console.print("[bold yellow][!] No runnable workflow steps were generated.[/]")
        return

    for step in plan["steps"]:
        invocation = build_stage_invocation(step)
        ok = launch_stage(invocation["name"], invocation["script"], invocation["args"])
        if not ok:
            console.print("[bold red][X] Workflow halted because a stage failed or was interrupted.[/]")
            return

    console.print("[bold green][+] Workflow complete.[/]")


def main() -> None:
    global POL
    console.print(
        Panel.fit(
            "[bold magenta]API Sniffer - AI Workflow Orchestrator[/]\n"
            "[dim]Let AI handle discovery, scanning, and query workflows[/]",
            border_style="magenta",
        )
    )
    console.print("[dim]Describe the job you want. Example: start scanning, run discovery for 3 minutes, or show all the API keys.[/]\n")

    POL = load_pol(log_fn=console.print)
    if not POL:
        return

    api_key = None

    while True:
        try:
            user_input = Prompt.ask("[bold cyan]Workflow AI[/]")
            cleaned_input = user_input.strip()
            if not cleaned_input:
                continue
            if cleaned_input.lower() in {"exit", "quit"}:
                console.print("[bold magenta]Shutting down workflow orchestrator...[/]")
                break

            if api_key is None:
                api_key = get_key(console)

            with console.status("[bold yellow]Routing request...[/]", spinner="dots"):
                try:
                    route = normalize_route(ask_ai_for_route(cleaned_input, api_key, POL), POL)
                except Exception as error:
                    console.print(f"[bold yellow][!] AI router error: {error}[/]")
                    continue

            if route.get("reply"):
                console.print(f"[bold green]AI:[/] {route['reply']}")

            if route["mode"] == "chat":
                continue

            if route["mode"] == "query":
                run_single_query(cleaned_input, console=console, api_key=api_key)
                continue

            render_plan(route)
            execute_plan(route)

        except KeyboardInterrupt:
            console.print("\n[bold magenta]Shutting down workflow orchestrator...[/]")
            break
        except Exception as error:
            console.print(f"[bold red][X] Workflow orchestrator error: {error}[/]")


if __name__ == "__main__":
    main()
