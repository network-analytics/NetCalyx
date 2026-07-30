#!/usr/bin/env python3
"""Check that Rust files start with the required Apache 2.0 license header,
and that pre-existing NetGauze authorship lines are not removed.

Usage: check_license.py --base-ref <git-ref>

Discovers changed .rs files between base-ref and HEAD automatically.
Also verifies that any file which already had a NetGauze Authors copyright
line in the base still has it in the new version.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

HEADER = re.compile(
    r'// Copyright \(C\) \d{4}-present The NetCalyx Authors\.\n'
    r'(?:// Copyright \(C\) \d{4}-present The NetGauze Authors\.\n)?'
    r'//\n'
    r'// Licensed under the Apache License, Version 2\.0 \(the "License"\);\n'
    r'// you may not use this file except in compliance with the License\.\n'
    r'// You may obtain a copy of the License at\n'
    r'//\n'
    r'//    http://www\.apache\.org/licenses/LICENSE-2\.0\n'
    r'//\n'
    r'// Unless required by applicable law or agreed to in writing, software\n'
    r'// distributed under the License is distributed on an "AS IS" BASIS,\n'
    r'// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or\n'
    r'// implied\.\n'
    r'// See the License for the specific language governing permissions and\n'
    r'// limitations under the License\.'
)

NETGAUZE_LINE = re.compile(r'// Copyright \(C\) \d{4}-present The NetGauze Authors\.')


def get_files_and_renames(base_ref: str) -> tuple[list[str], dict[str, str]]:
    """Return changed .rs files and a new_path->old_path rename map since base_ref."""
    result = subprocess.run(
        ['git', 'diff', '--name-status', '-z', '--diff-filter=d',
         '--find-renames=10%', f'{base_ref}...HEAD', '--', '*.rs'],
        capture_output=True, check=True,
    )
    # Format per entry: status\0path\0  or  R<score>\0old\0new\0
    parts = iter(result.stdout.decode().split('\0'))
    files: list[str] = []
    renames: dict[str, str] = {}
    for status in parts:
        if not status:
            continue
        if status.startswith('R'):
            old, new = next(parts), next(parts)
            renames[new] = old
            files.append(new)
        else:
            path = next(parts)
            renames[path] = path
            files.append(path)
    return files, renames


def get_base_blob(base_ref: str, repo_path: str) -> bytes | None:
    """Return the raw bytes of repo_path at base_ref, or None if it didn't exist."""
    result = subprocess.run(
        ['git', 'cat-file', 'blob', f'{base_ref}:{repo_path}'],
        capture_output=True,
    )
    return result.stdout if result.returncode == 0 else None


def check_file(
    path: str, base_ref: str, rename_map: dict[str, str],
) -> str | None:
    """Return an error message if the file fails the license check, else None."""
    try:
        content = Path(path).read_text(encoding='utf-8')
    except OSError as exc:
        return f"could not read file: {exc}"

    if not HEADER.match(content):
        return "missing or incorrect license header"

    base_bytes = get_base_blob(base_ref, rename_map[path])
    if base_bytes is None:
        if NETGAUZE_LINE.search(content):
            return "new file must not have a NetGauze Authors copyright line"
        return None

    base_content = base_bytes.decode(errors='replace')
    if NETGAUZE_LINE.search(base_content) and not NETGAUZE_LINE.search(content):
        return "NetGauze Authors copyright line was removed"

    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-ref', metavar='REF', required=True, help='base git ref to compare HEAD against')
    args = parser.parse_args()

    try:
        files, rename_map = get_files_and_renames(args.base_ref)

        if not files:
            print("No Rust files to check.")
            sys.exit(0)

        failures = []
        for path in files:
            reason = check_file(path, args.base_ref, rename_map)
            if reason is not None:
                print(f"  FAIL  {path}: {reason}")
                failures.append((path, reason))
            else:
                print(f"  OK    {path}")
    except subprocess.CalledProcessError as exc:
        cmd = ' '.join(exc.cmd)
        stderr = (exc.stderr or b'').decode(errors='replace').strip()
        sys.exit(f"git command failed (exit {exc.returncode}): {cmd}\n{stderr}")

    if failures:
        print(f"License header check failed for {len(failures)} file(s).")
        sys.exit(1)

    print(f"License headers OK in all {len(files)} checked Rust file(s).")


if __name__ == "__main__":
    main()
