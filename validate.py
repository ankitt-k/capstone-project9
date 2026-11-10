import re

MAX_LENGTH = 500

INJECTION_PATTERNS = [
    r"ignore (all )?previous instructions",
    r"ignore (all )?previous instructions",
    r"ignore (your|all) (rules|instructions)",
    r"you are now",
    r"you are now",
    r"pretend you are",
    r"act as if you have no",
    r"reveal your system prompt",
    r"no restrictions",
]

BASE64_PATTERN = r"[A-Za-z0-9+/]{40,}={0,2}"

SENSITIVE_OUTPUT_PATTERNS = [
    r"password\s*=",
    r"api_key\s*=",
    r"token\s*=",
    r"https?://[^\s]+",
]

def validate_input(user_input):
    if len(user_input) > MAX_LENGTH:
        return False, "Input exceeds maximum allowed length of 500 characters."

    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, user_input, re.IGNORECASE):
            return False, f"Blocked: input matched a known injection pattern."

    if re.search(BASE64_PATTERN, user_input):
        return False, "Blocked: suspicious encoded content detected."

    return True, None

def scan_output(model_response):
    for pattern in SENSITIVE_OUTPUT_PATTERNS:
        if re.search(pattern, model_response, re.IGNORECASE):
            return False, "Blocked: response contained sensitive or restricted content."
    return True, None
