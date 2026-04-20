import json
import os
import time
import requests
import concurrent.futures
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
LEAKED_KEYS_FILE = str(ROOT_DIR / "leaked_keys.json")
VERIFIED_KEYS_FILE = str(ROOT_DIR / "verified_keys.json")

def verify_claude(api_key: str) -> bool:
    url = "https://api.anthropic.com/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
    }
    try:
        r = requests.post(url, headers=headers, json={}, timeout=10)
        res = r.json()
        if "authentication_error" in str(res):
            return False
        return True
    except Exception as e:
        print(f"Error testing Claude key: {e}")
        return False

def verify_google(api_key: str) -> bool:
    # tries generative language API first, real keys might be for maps tho
    genai_url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    try:
        r = requests.get(genai_url, timeout=10)
        if r.status_code == 200:
            return True
        js = r.json()
        if "API key not valid" in str(js.get("error", {}).get("message", "")) or r.status_code == 400:
            return False
        return "error" in js
    except Exception as e:
        print(f"Error testing Google key: {e}")
        return False

def verify_generic(api_key: str, provider: str) -> bool:
    configs = {
        "openai": {"url": "https://api.openai.com/v1/models", "prefix": "Bearer", "method": "GET"},
        "groq": {"url": "https://api.groq.com/openai/v1/models", "prefix": "Bearer", "method": "GET"},
        "mistral": {"url": "https://api.mistral.ai/v1/models", "prefix": "Bearer", "method": "GET"},
        "huggingface": {"url": "https://huggingface.co/api/whoami-v2", "prefix": "Bearer", "method": "GET"},
        "replicate": {"url": "https://api.replicate.com/v1/models", "prefix": "Token", "method": "GET"},
        "perplexity": {"url": "https://api.perplexity.ai/chat/completions", "prefix": "Bearer", "method": "POST", "body": {}},
        "cohere": {"url": "https://api.cohere.ai/v1/models", "prefix": "Bearer", "method": "GET"},
        "together": {"url": "https://api.together.xyz/v1/models", "prefix": "Bearer", "method": "GET"},
        "openrouter": {"url": "https://openrouter.ai/api/v1/auth/key", "prefix": "Bearer", "method": "GET"},
        "xai": {"url": "https://api.x.ai/v1/models", "prefix": "Bearer", "method": "GET"},
        "cerebras": {"url": "https://api.cerebras.ai/v1/models", "prefix": "Bearer", "method": "GET"}
    }
    cfg = configs.get(provider)
    if not cfg:
        return False
    
    headers = {"Authorization": f"{cfg['prefix']} {api_key}"}
    try:
        if cfg["method"] == "GET":
            r = requests.get(cfg["url"], headers=headers, timeout=10)
        else:
            r = requests.post(cfg["url"], headers=headers, json=cfg.get("body", {}), timeout=10)
            
        if r.status_code in (401, 403):
            return False
        return True
    except Exception as e:
        print(f"Error testing {provider} key: {e}")
        return False


def process_repo(repo_entry: dict):
    repo_name = repo_entry.get("repo", "Unknown")
    findings = repo_entry.get("findings", [])
    
    verified_findings = []
    valid_count = 0
    discarded_count = 0
    unhandled_count = 0

    for finding in findings:
        secret = finding.get("secret", "").strip()
        category = str(finding.get("type", "")).lower()
        
        is_claude = secret.startswith("sk-ant-api") or "claude" in category or "anthropic" in category
        is_google = secret.startswith("AIzaSy") or "google" in category
        is_openai = secret.startswith("sk-proj") or secret.startswith("sk-svc") or "openai" in category or "chatgpt" in category
        is_groq = secret.startswith("gsk_") or "groq" in category
        is_hf = secret.startswith("hf_") or "huggingface" in category
        is_replicate = secret.startswith("r8_") or "replicate" in category
        is_perplexity = secret.startswith("pplx-") or "perplexity" in category
        is_mistral = "mistral" in category
        is_cohere = "cohere" in category
        is_together = "together" in category
        is_openrouter = secret.startswith("sk-or-v1-") or "openrouter" in category
        is_xai = secret.startswith("xai-") or "xai" in category
        is_cerebras = secret.startswith("cs-") or "cerebras" in category

        is_valid = False
        tested_provider = None
        
        if is_claude:
            tested_provider = "Claude"
            is_valid = verify_claude(secret)
        elif is_google:
            tested_provider = "Google"
            is_valid = verify_google(secret)
        elif is_openai:
            tested_provider = "OpenAI"
            is_valid = verify_generic(secret, "openai")
        elif is_groq:
            tested_provider = "Groq"
            is_valid = verify_generic(secret, "groq")
        elif is_hf:
            tested_provider = "HuggingFace"
            is_valid = verify_generic(secret, "huggingface")
        elif is_replicate:
            tested_provider = "Replicate"
            is_valid = verify_generic(secret, "replicate")
        elif is_perplexity:
            tested_provider = "Perplexity"
            is_valid = verify_generic(secret, "perplexity")
        elif is_mistral:
            tested_provider = "Mistral"
            is_valid = verify_generic(secret, "mistral")
        elif is_cohere:
            tested_provider = "Cohere"
            is_valid = verify_generic(secret, "cohere")
        elif is_together:
            tested_provider = "Together"
            is_valid = verify_generic(secret, "together")
        elif is_openrouter:
            tested_provider = "OpenRouter"
            is_valid = verify_generic(secret, "openrouter")
        elif is_xai:
            tested_provider = "xAI"
            is_valid = verify_generic(secret, "xai")
        elif is_cerebras:
            tested_provider = "Cerebras"
            is_valid = verify_generic(secret, "cerebras")
            
        if tested_provider:
            print(f"[~] Testing {tested_provider} key: {secret[:12]}...")
            if is_valid:
                print(f"[+] => VALID! ({repo_name})")
                finding["status"] = "Verified"
                verified_findings.append(finding)
                valid_count += 1
            else:
                print(f"[-] => INVALID/REVOKED ({repo_name})")
                discarded_count += 1
        else:
            unhandled_count += 1
            
        time.sleep(0.5)
        
    if verified_findings:
        new_repo_entry = dict(repo_entry)
        new_repo_entry["findings"] = verified_findings
        new_repo_entry["total_secrets"] = len(verified_findings)
        return new_repo_entry, valid_count, discarded_count, unhandled_count
    return None, valid_count, discarded_count, unhandled_count

def main():
    if not os.path.exists(LEAKED_KEYS_FILE):
        print(f"[-] No {LEAKED_KEYS_FILE} found.")
        return

    print("[*] Starting API Key Verifier (Universal AI Mode)...")
    with open(LEAKED_KEYS_FILE, "r", encoding="utf-8") as f:
        try:
            leaked_data = json.load(f)
        except json.JSONDecodeError:
            print("[-] Error parsing leaked keys JSON.")
            return

    verified_only = []
    total_findings = sum(len(repo.get("findings", [])) for repo in leaked_data)
    print(f"[*] Found {total_findings} total keys to inspect.\n")

    total_valid = 0
    total_discarded = 0
    total_skipped = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_repo = {executor.submit(process_repo, repo): repo for repo in leaked_data}
        for future in concurrent.futures.as_completed(future_to_repo):
            try:
                res, v_cnt, d_cnt, u_cnt = future.result()
                total_valid += v_cnt
                total_discarded += d_cnt
                total_skipped += u_cnt
                if res:
                    verified_only.append(res)
            except Exception as e:
                print(f"[-] Error processing a repository: {e}")

    print(f"\n[*] Verification complete. Kept {total_valid} valid keys.")
    print(f"[*] Threw away {total_discarded} invalid/revoked keys.")
    print(f"[*] Silently dropped {total_skipped} unhandled keys.")

    with open(LEAKED_KEYS_FILE, "w", encoding="utf-8") as f:
        json.dump(verified_only, f, indent=4)
        
    print(f"[+] Overwrote {LEAKED_KEYS_FILE} with only the strictly verified AI keys.")

if __name__ == "__main__":
    main()
