import base64
import ipaddress
import json
import re
from typing import Dict, List, Optional, Pattern, Tuple
from urllib.parse import SplitResult, urlsplit


def read_url_suffix(text_piece: str, start_idx: int) -> str:
    suffix_chars = []
    for char in text_piece[start_idx:]:
        if char.isspace() or char in "\"'`<>()[]{};,":
            break
        suffix_chars.append(char)
    return "".join(suffix_chars)

PH_LIT = {
    "123456",
    "12345678",
    "abcdef",
    "abcdefg",
    "abcdefgh",
    "abc123",
    "password",
    "passwd",
    "changeme",
    "test",
    "testing",
    "example",
    "sample",
    "demo",
    "pass",
    "host",
    "port",
    "cluster",
    "placeholder",
    "xxxxxx",
    "xxxxxxx",
    "xxxxxxxx",
    "xxxxxxxxx",
    # These are specifically for DB URI false positives.
    "someuser",
    "somepassword",
    "somehost",
    "secure_password",
    "DBuser",
    "localhost",
    "my_user",
    "my_password",
    "rootpassword",
    "user",
    "usuario",
    "internal-db",
}

PLACEHOLDER_TOKENS = {
    "changeme",
    "default",
    "demo",
    "dev",
    "dummy",
    "example",
    "fake",
    "hidden",
    "local",
    "localhost",
    "masked",
    "mock",
    "placeholder",
    "redacted",
    "replace",
    "sample",
    "temp",
    "test",
    "testing",
    "tmp",
    "your",
}

SECRET_DESCRIPTOR_TOKENS = {
    "key",
    "passwd",
    "password",
    "secret",
    "token",
}

FIREBASE_WEB_CONFIG_HINTS = {
    "apikey",
    "appid",
    "authdomain",
    "messagingsenderid",
    "projectid",
    "storagebucket",
}

PK_TYPES = {
    "Private Key (PKCS8)",
    "Private Key (RSA)",
    "Private Key (EC)",
    "Private Key (OPENSSH)",
    "PGP Private Key Block",
}

PK_BLOCK_RE = re.compile(
    r"-----BEGIN (?:(RSA|EC|OPENSSH)\s+)?PRIVATE KEY-----[\s\S]{40,}?-----END (?:(RSA|EC|OPENSSH)\s+)?PRIVATE KEY-----"
)
PGP_BLOCK_RE = re.compile(
    r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]{40,}?-----END PGP PRIVATE KEY BLOCK-----"
)
TEMPLATE_RE = re.compile(
    r"(?:"
    r"\$\{[^}]+\}"
    r"|\$\([^)]+\)"
    r"|\$[A-Za-z_][A-Za-z0-9_]*"
    r"|\{\{[^}]+\}\}"
    r"|\{[^}]+\}"
    r"|<[^>\s]+>"
    r"|\[[A-Za-z0-9_.:-]+\]"
    r"|%\([^)]+\)[a-zA-Z]"
    r"|%[sd]"
    r")"
)


def _looks_like_template(value: str) -> bool:
    val = (value or "").strip()
    if not val:
        return False
    return bool(TEMPLATE_RE.search(val))


def _split_words(value: str) -> List[str]:
    return [part for part in re.split(r"[^a-z0-9]+", value.lower()) if part]


def _looks_masked(value: str) -> bool:
    val = (value or "").strip()
    if len(val) < 3:
        return False

    low = val.lower()
    if low in {"redacted", "masked", "hidden"}:
        return True
    if len(set(val)) == 1 and val[0] in {"*", "x", "X", "#", ".", "_", "-"}:
        return True
    return False


def _looks_descriptive_secret(value: str) -> bool:
    val = (value or "").strip()
    if not val or len(val) > 80:
        return False

    parts = _split_words(val)
    low = val.lower()

    has_secret_word = any(part in SECRET_DESCRIPTOR_TOKENS for part in parts) or any(
        token in low for token in SECRET_DESCRIPTOR_TOKENS
    )
    has_placeholder_word = any(part in PLACEHOLDER_TOKENS for part in parts) or any(
        token in low for token in PLACEHOLDER_TOKENS
    )
    return has_secret_word and has_placeholder_word


def _ph_val(value: str) -> bool:
    val = (value or "").strip()
    if not val:
        return True
    if _looks_like_template(val):
        return True
    if _looks_masked(val):
        return True
    low = val.lower()
    if low in PH_LIT:
        return True
    if _looks_descriptive_secret(val):
        return True
    if len(val) >= 6 and len(set(val)) == 1:
        return True
    if len(val) <= 12 and re.fullmatch(r"(?:abc|def|xyz|123)+", low):
        return True
    if "example" in low and len(val) <= 80:
        return True
    if any(word in low for word in ("changeme", "replace", "your_", "your-", "your ")):
        if len(val) <= 80:
            return True
    return False


def _split_uri_secret(secret: str) -> Optional[SplitResult]:
    try:
        parsed = urlsplit(secret)
    except ValueError:
        return None

    if not parsed.scheme or not parsed.netloc:
        return None
    if parsed.username is None and parsed.password is None:
        return None
    return parsed


def _is_local_uri_host(host: str) -> bool:
    low = (host or "").strip().strip(".").lower()
    if not low:
        return False
    if low in {"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"}:
        return True

    try:
        ip_addr = ipaddress.ip_address(low)
    except ValueError:
        return False
    return ip_addr.is_loopback or ip_addr.is_unspecified


def _host_has_placeholder_segment(host: str) -> bool:
    labels = [label for label in (host or "").strip(".").split(".") if label]
    for label in labels:
        if _ph_val(label):
            return True
    return False


def _uri_looks_placeholder(secret: str) -> bool:
    parsed = _split_uri_secret(secret)
    if not parsed:
        return False

    username = parsed.username or ""
    password = parsed.password or ""
    hostname = parsed.hostname or ""

    if any(_looks_like_template(part) for part in (username, password, hostname)):
        return True
    if _ph_val(username):
        return True
    if _is_local_uri_host(hostname):
        return True
    if _host_has_placeholder_segment(hostname):
        return True
    if _ph_val(password):
        return True
    if _looks_descriptive_secret(password):
        return True
    return False


def _ph_sec(secret: str) -> bool:
    val = (secret or "").strip()
    if _ph_val(val):
        return True
    if "://" in val and "@" in val:
        if _looks_like_template(val):
            return True
        if _uri_looks_placeholder(val):
            return True
    return False


def _jwt_payload(token: str) -> Optional[dict]:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    b64 = parts[1]
    b64 += "=" * (-len(b64) % 4)
    try:
        data_bytes = base64.urlsafe_b64decode(b64.encode("utf-8"))
        data_text = data_bytes.decode("utf-8", errors="ignore")
        data = json.loads(data_text)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _sb_jwt_type(token: str) -> Optional[str]:
    payload = _jwt_payload(token)
    if not payload:
        return None
    iss = str(payload.get("iss", "")).lower()
    ref = payload.get("ref") or payload.get("project_ref")
    if "supabase" not in iss and not ref:
        return None
    role = payload.get("role")
    if role == "anon":
        return None
    if role == "service_role":
        return "Supabase Service Role Key (JWT)"
    return "Supabase JWT (Unknown Role)"


def _looks_like_firebase_web_config(filename: str, line_data: str, raw_text: str) -> bool:
    filename_low = (filename or "").lower()
    line_low = (line_data or "").lower()
    blob_low = (raw_text or "").lower()

    if "firebase" not in filename_low and "firebase" not in line_low and "apikey" not in line_low:
        return False

    hint_count = sum(hint in blob_low for hint in FIREBASE_WEB_CONFIG_HINTS)
    return hint_count >= 3


def _is_false_positive_match(
    api_name: str,
    secret: str,
    filename: str,
    line_data: str,
    raw_text: str,
) -> bool:
    if _ph_sec(secret):
        return True
    if api_name == "Google API/GCP Key" and _looks_like_firebase_web_config(filename, line_data, raw_text):
        return True
    return False


def _pk_ok(block: str) -> bool:
    lines = [line.strip() for line in block.splitlines()]
    if len(lines) < 3:
        return False
    body_lines = [line for line in lines[1:-1] if line and not line.lower().startswith(("version:", "comment:"))]
    if len(body_lines) < 2:
        return False
    body = "".join(body_lines)
    if len(body) < 80:
        return False
    uniq = len(set(body)) / max(1, len(body))
    if uniq < 0.05:
        return False
    if _ph_sec(body):
        return False
    return True


def _pk_blocks(raw_text: str) -> List[Tuple[str, int, str]]:
    hits: List[Tuple[str, int, str]] = []

    for match in PK_BLOCK_RE.finditer(raw_text):
        block = match.group(0)
        if not _pk_ok(block):
            continue
        header = block.splitlines()[0].strip()
        if "RSA PRIVATE KEY" in header:
            key_type = "Private Key (RSA)"
        elif "EC PRIVATE KEY" in header:
            key_type = "Private Key (EC)"
        elif "OPENSSH PRIVATE KEY" in header:
            key_type = "Private Key (OPENSSH)"
        else:
            key_type = "Private Key (PKCS8)"
        start_line = raw_text.count("\n", 0, match.start()) + 1
        hits.append((key_type, start_line, block))

    for match in PGP_BLOCK_RE.finditer(raw_text):
        block = match.group(0)
        if not _pk_ok(block):
            continue
        start_line = raw_text.count("\n", 0, match.start()) + 1
        hits.append(("PGP Private Key Block", start_line, block))

    return hits

# Some providers use URLs where the useful part continues past the regex match.
# For example, Firebase REST endpoints are only valid if the expanded URL includes ".json".
def normalize_match(api_name: str, text_piece: str, hit) -> Optional[str]:
    secret = hit.group(0)
    if api_name != "Firebase Database URL":
        return secret

    expanded_secret = secret + read_url_suffix(text_piece, hit.end())
    if ".json" not in expanded_secret.lower():
        return None
    return expanded_secret

# This scans one decoded text blob and records normalized findings with file and line metadata.
def regex_grep_text(
    raw_text: str,
    filename: str,
    api_signatures: Dict[str, Pattern[str]],
    line_cutoff: int,
) -> List[dict]:
    caught_keys = []
    for key_type, start_line, block in _pk_blocks(raw_text):
        caught_keys.append({
            "file": filename,
            "line": start_line,
            "type": key_type,
            "secret": block,
        })

    for line_idx, line_data in enumerate(raw_text.splitlines(), 1):
        if len(line_data) > line_cutoff:
            split_pieces = [line_data[i:i + line_cutoff] for i in range(0, len(line_data), line_cutoff)]
        else:
            split_pieces = [line_data]

        for piece in split_pieces:
            for api_name, regex_obj in api_signatures.items():
                if api_name in PK_TYPES:
                    continue
                for hit in regex_obj.finditer(piece):
                    normalized_secret = normalize_match(api_name, piece, hit)
                    if not normalized_secret:
                        continue
                    if _is_false_positive_match(api_name, normalized_secret, filename, line_data, raw_text):
                        continue
                    effective_name = api_name
                    if api_name == "Supabase Anon/Service Role JWT":
                        sb_type = _sb_jwt_type(normalized_secret)
                        if not sb_type:
                            continue
                        effective_name = sb_type
                    caught_keys.append({
                        "file": filename,
                        "line": line_idx,
                        "type": effective_name,
                        "secret": normalized_secret,
                    })
    return caught_keys
