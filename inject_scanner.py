import sys
import glob

SYSTEM_PROMPT_PATTERNS = ["SYSTEM_PROMPT =", "system_message ="]
ROLE_SYSTEM_PATTERN = '"role": "system"'
SAFE_MARKER = "os.environ"

INJECTION_PHRASES = [
    "ignore previous instructions",
    "you are now",
    "pretend you are",
    "act as if you have no restrictions",
]

SELF_FILE = "inject_scanner.py"
EXCLUDED_FILES = [SELF_FILE, "validate.py"]  # validate.py defines these phrases as detection patterns, not actual prompts

def scan_file(filepath):
    findings = []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    for line_no, line in enumerate(lines, start=1):
        lower_line = line.lower()

        for pattern in SYSTEM_PROMPT_PATTERNS:
            if pattern.lower() in lower_line and SAFE_MARKER not in line:
                findings.append(filepath + ": line " + str(line_no) + " - found hardcoded pattern '" + pattern + "'")

        if ROLE_SYSTEM_PATTERN in line:
            findings.append(filepath + ": line " + str(line_no) + " - found pattern '" + ROLE_SYSTEM_PATTERN + "'")

        for phrase in INJECTION_PHRASES:
            if phrase in lower_line:
                findings.append(filepath + ": line " + str(line_no) + " - found injection phrase '" + phrase + "'")

    return findings

def main():
    py_files = [f for f in glob.glob("**/*.py", recursive=True) if f not in EXCLUDED_FILES]
    all_findings = []
    for f in py_files:
        all_findings.extend(scan_file(f))

    if all_findings:
        print("Prompt Injection Scanner - Issues Found:")
        for finding in all_findings:
            print("  - " + finding)
        sys.exit(1)
    else:
        print("Prompt Injection Scanner - Clean. No issues found.")
        sys.exit(0)

main()
