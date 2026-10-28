#!/usr/bin/env python3
"""Syntax-check the shell embedded in Jenkinsfiles.

Groovy parsing alone cannot catch a broken `sh` block: the block is an opaque string to
Groovy, so a stray `\\(` only fails when Jenkins actually runs it. This extracts every
`sh '''...'''` / `sh \"\"\"...\"\"\"` block and validates it as shell.

ShellCheck is used when available because `bash -n` does not report syntax errors inside
`$( )` command substitutions. Without ShellCheck the script falls back to `bash -n`.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

JENKINSFILES = (
    Path("jenkins-pipeline/Jenkinsfile"),
    Path("jenkins-pipeline/Jenkinsfile.rust"),
)
BLOCK_RE = re.compile(r"sh\s+('''(.*?)'''|\"\"\"(.*?)\"\"\")", re.DOTALL)

# Groovy processes backslash escapes inside single- and double-quoted strings before the
# `sh` step ever sees them, so `\\(` reaches the shell as `\(`.
ESCAPES = {
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "b": "\b",
    "f": "\f",
    "\\": "\\",
    "'": "'",
    '"': '"',
    "$": "$",
}


def groovy_unescape(text: str) -> str:
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char != "\\" or index + 1 >= len(text):
            out.append(char)
            index += 1
            continue
        following = text[index + 1]
        if following == "\n":
            index += 2
        elif following == "\r" and text[index + 2 : index + 3] == "\n":
            index += 3
        elif following in ESCAPES:
            out.append(ESCAPES[following])
            index += 2
        elif following == "u" and index + 6 <= len(text):
            out.append(chr(int(text[index + 2 : index + 6], 16)))
            index += 6
        else:
            # Unknown escapes are Groovy compile errors; keep them so ShellCheck reports them.
            out.append(char)
            index += 1
    return "".join(out)


def shell_blocks(source: str) -> list[str]:
    blocks = []
    for match in BLOCK_RE.finditer(source):
        single, double = match.group(2), match.group(3)
        blocks.append(groovy_unescape(single if single is not None else double))
    return blocks


def syntax_command(shellcheck: str | None, path: str) -> list[str]:
    if shellcheck:
        # Error severity only: the goal is parse failures, not style/lint advice.
        return [shellcheck, "--shell=bash", "--severity=error", path]
    return ["bash", "-n", path]


def check_script(text: str, shellcheck: str | None) -> subprocess.CompletedProcess[str]:
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as handle:
        handle.write(text)
        temp_path = handle.name
    try:
        return subprocess.run(
            syntax_command(shellcheck, temp_path),
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        os.unlink(temp_path)


def check(path: Path, shellcheck: str | None) -> bool:
    if not path.is_file():
        print(f"{path}: missing", file=sys.stderr)
        return False

    blocks = shell_blocks(path.read_text(encoding="utf-8"))
    print(f"{path}: {len(blocks)} sh block(s)")
    ok = True
    for index, block in enumerate(blocks, 1):
        result = check_script(block, shellcheck)
        if result.returncode:
            ok = False
            detail = result.stdout + result.stderr
            print(f"  block {index}: syntax check failed\n{detail}", file=sys.stderr)
    return ok


def main() -> int:
    shellcheck = shutil.which("shellcheck")
    if shellcheck is None:
        print("shellcheck not found; falling back to `bash -n` (weaker inside $( ))")

    results = [check(path, shellcheck) for path in JENKINSFILES]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
