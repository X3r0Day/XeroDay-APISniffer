import json
import os
import time
from typing import Any, Dict, List, Optional

from rich.prompt import Prompt
from shared.requests_compat import requests


def get_key(console=None) -> str:
    key = os.environ.get("GROQ_API_KEY")
    if key:
        return key
    if console is None:
        raise RuntimeError("GROQ_API_KEY not set and no console to prompt.")
    console.print("[bold yellow][!] GROQ_API_KEY environment variable not found.[/]")
    key = Prompt.ask("[bold cyan]Please enter your Groq API Key (gsk_...)[/]", password=True, console=console)
    os.environ["GROQ_API_KEY"] = key
    return key


def _json_from_text(txt: str) -> Dict[str, Any]:
    # We salvage JSON when the model wraps it in text.
    # For example, "Sure! {\"mode\":\"query\"}" -> {"mode":"query"}.
    try:
        return json.loads(txt)
    except json.JSONDecodeError:
        start = txt.find("{")
        end = txt.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(txt[start : end + 1])
        raise


def _post(url: str, key: str, pay: Dict[str, Any], tmo: float) -> Dict[str, Any]:
    hdr = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    }
    res = requests.post(url, headers=hdr, json=pay, timeout=tmo)
    res.raise_for_status()
    return res.json()


def ask_text(msgs: List[Dict[str, str]], key: str, cfg: Dict[str, Any]) -> str:
    url = str(cfg.get("api_url", ""))
    mdl = str(cfg.get("model", ""))
    tmo = float(cfg.get("timeout", 20))
    temp = float(cfg.get("temp", 0.1))
    tries = int(cfg.get("max_retries", 1))

    pay = {
        "model": mdl,
        "messages": msgs,
        "temperature": temp,
    }

    err = None
    for _ in range(max(1, tries)):
        try:
            data = _post(url, key, pay, tmo)
            return str(data["choices"][0]["message"]["content"]).strip()
        except Exception as exc:
            err = exc
            time.sleep(0.2)
    raise err


def ask_json(msgs: List[Dict[str, str]], key: str, cfg: Dict[str, Any]) -> Dict[str, Any]:
    url = str(cfg.get("api_url", ""))
    mdl = str(cfg.get("model", ""))
    tmo = float(cfg.get("timeout", 20))
    temp = float(cfg.get("json_temp", 0))
    tries = int(cfg.get("max_retries", 1))

    pay = {
        "model": mdl,
        "response_format": {"type": "json_object"},
        "messages": msgs,
        "temperature": temp,
    }

    err = None
    for _ in range(max(1, tries)):
        try:
            data = _post(url, key, pay, tmo)
            return _json_from_text(str(data["choices"][0]["message"]["content"]))
        except Exception as exc:
            err = exc
            time.sleep(0.2)
    raise err
