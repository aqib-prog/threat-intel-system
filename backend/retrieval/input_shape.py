"""Conservative classification of unsupported bare operational commands.

This module never executes or expands input.  It only recognizes command
*shape* so a pasted terminal invocation can be refused before it consumes an
LLM/graph request.  Requests to explain a command and structured telemetry that
contains command strings deliberately remain outside this classifier.
"""

from __future__ import annotations

import re
import shlex


UNSUPPORTED_OPERATIONAL_COMMAND_MESSAGE = (
    "I can't execute terminal or shell commands pasted into chat. "
    "Ask me to explain or review the command instead."
)


_FENCE_RE = re.compile(
    r"^\s*```(?:bash|console|fish|powershell|pwsh|sh|shell|zsh)?\s*\n"
    r"(?P<body>[\s\S]*?)\n```\s*$",
    re.IGNORECASE,
)
_CONTINUATION_RE = re.compile(r"\\\r?\n[ \t]*")
_REQUEST_FRAMING_RE = re.compile(
    r"(?:^|\n)\s*(?:please\s+)?(?:analy[sz]e|describe|explain|interpret|map|"
    r"tell\s+me|what|which|who|why|how|is|are|can|could|should|would)\b|"
    r"\b(?:write|give|create|show|tell)\s+(?:me|us)\b",
    re.IGNORECASE,
)
_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$", re.DOTALL)
_SHELL_PROMPT_RE = re.compile(
    r"^\s*(?:\([^\n)]*\)\s*)?"
    r"(?:PS\s+[^\n>]{1,100}>|[A-Za-z]:\\[^\n>]{0,100}>|"
    r"[^\n$#%>]{0,120}[$#%>]\s+)",
    re.IGNORECASE,
)
_POWERSHELL_CMDLET_RE = re.compile(r"^[A-Za-z]+-[A-Za-z][A-Za-z0-9]*$")
_LOG_FIELD_RE = re.compile(
    r"^(?:EventID|ProcessName|CommandLine|Image|ParentImage|TargetUserName|"
    r"LogonType|type|msg|comm|exe|auid|uid|gid|eventName|eventSource)\s*=",
    re.IGNORECASE,
)

# Command names are intentionally explicit.  An arbitrary English first word
# must never become a command merely because later tokens look like flags.
_EXECUTABLES = frozenset(
    {
        ".",
        "ansible",
        "apt",
        "apt-get",
        "aws",
        "az",
        "awk",
        "bash",
        "brew",
        "cargo",
        "cat",
        "cd",
        "chmod",
        "chown",
        "cmd",
        "cmd.exe",
        "command",
        "curl",
        "docker",
        "dotnet",
        "echo",
        "env",
        "export",
        "find",
        "git",
        "gcloud",
        "go",
        "grep",
        "helm",
        "id",
        "java",
        "journalctl",
        "jq",
        "kubectl",
        "less",
        "ls",
        "make",
        "msfconsole",
        "mvn",
        "mysql",
        "neo4j",
        "netstat",
        "nc",
        "nmap",
        "node",
        "nohup",
        "npm",
        "npx",
        "ollama",
        "pip",
        "pip3",
        "pnpm",
        "podman",
        "psql",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pytest",
        "python",
        "python3",
        "redis-cli",
        "rg",
        "rm",
        "rsync",
        "scp",
        "sed",
        "sqlmap",
        "sqlite3",
        "sh",
        "ssh",
        "source",
        "sudo",
        "systemctl",
        "tail",
        "tar",
        "terraform",
        "time",
        "touch",
        "unset",
        "uv",
        "uvicorn",
        "vim",
        "wget",
        "whoami",
        "xargs",
        "yarn",
        "yum",
        "zsh",
        "cypher-shell",
        "gradle",
        "hydra",
        "openssl",
        "perl",
        "php",
        "ruby",
    }
)
_WRAPPERS = frozenset({"command", "nohup", "sudo", "time"})


def _strip_fence(value: str) -> str:
    match = _FENCE_RE.match(value)
    return match.group("body") if match else value


def _split_shell_units(line: str) -> list[str]:
    """Split shell control operators while preserving quoted arguments."""
    units: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    index = 0
    while index < len(line):
        char = line[index]
        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            escaped = True
            index += 1
            continue
        if char in {"'", '"'}:
            if quote is None:
                quote = char
            elif quote == char:
                quote = None
            index += 1
            continue
        if quote is None and char in {";", "|", "&"}:
            width = 1
            if index + 1 < len(line) and line[index + 1] == char:
                width = 2
            part = line[start:index].strip()
            if part:
                units.append(part)
            start = index + width
            index += width
            continue
        index += 1
    tail = line[start:].strip()
    if tail:
        units.append(tail)
    return units


def _logical_commands(value: str) -> list[str]:
    """Return shell command units without interpreting shell expressions."""
    collapsed = _CONTINUATION_RE.sub(" ", value)
    units: list[str] = []
    for line in collapsed.splitlines():
        line = _SHELL_PROMPT_RE.sub("", line).strip()
        if not line or line.startswith("#"):
            continue
        # Validate every stage/command rather than only the first executable.
        # The scanner respects quoted separators (python -c 'print("a;b")').
        units.extend(_split_shell_units(line))
    return units


def _basename(token: str) -> str:
    return token.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1].casefold()


def _is_executable_token(token: str) -> bool:
    base = _basename(token)
    if base in _EXECUTABLES:
        return True
    if _POWERSHELL_CMDLET_RE.match(base):
        return True
    # An explicit filesystem executable is operational syntax even when its
    # basename is project-specific. Requiring a path marker prevents an
    # arbitrary English word from being classified as a command.
    if token.startswith(("./", "../", "/", "~/")):
        return bool(base)
    if base.endswith((".bat", ".cmd", ".com", ".exe", ".ps1", ".py", ".sh")):
        return True
    return (
        ("/" in token or "\\" in token)
        and bool(base)
        and (
            base.endswith((".bat", ".cmd", ".ps1", ".py", ".sh"))
            or base.startswith(("python", "node", "uvicorn"))
        )
    )


def _command_unit_is_operational(unit: str) -> bool:
    if _LOG_FIELD_RE.match(unit):
        return False
    try:
        tokens = shlex.split(unit, comments=False, posix=True)
    except ValueError:
        return False
    if not tokens:
        return False

    index = 0
    while index < len(tokens) and _ASSIGNMENT_RE.match(tokens[index]):
        index += 1
    if index >= len(tokens):
        return False

    if tokens[index].casefold() == "env":
        index += 1
        while index < len(tokens):
            token = tokens[index]
            if token in {"-u", "--unset"}:
                index += 2
                continue
            if token.startswith("--unset=") or token in {"-i", "--ignore-environment"}:
                index += 1
                continue
            if _ASSIGNMENT_RE.match(token):
                index += 1
                continue
            break
        if index >= len(tokens):
            return False

    while index < len(tokens) and _basename(tokens[index]) in _WRAPPERS:
        index += 1
        while index < len(tokens) and tokens[index].startswith("-"):
            index += 1
    if index >= len(tokens):
        return False
    if _is_executable_token(tokens[index]):
        return True
    # A project-specific command name followed by an option is a strong CLI
    # shape without requiring an endless executable allow-list. Plain words
    # without flags do not qualify, preserving the natural-language boundary.
    return bool(
        re.fullmatch(r"[A-Za-z0-9_.+-]+", tokens[index])
        and any(token.startswith("-") and token != "-" for token in tokens[index + 1 :])
    )


def is_bare_operational_command(value: str) -> bool:
    """Whether ``value`` is executable syntax with no analysis request.

    This is intentionally narrower than code detection.  It recognizes only
    shell/CLI invocations whose logical units each have an explicit executable.
    JSON, key/value telemetry, questions, and explanatory framing return False.
    """
    text = _strip_fence(str(value or "").strip())
    if not text or text.lstrip().startswith(("{", "[")):
        return False
    if "?" in text or _REQUEST_FRAMING_RE.search(text):
        return False
    units = _logical_commands(text)
    return bool(units) and all(_command_unit_is_operational(unit) for unit in units)
