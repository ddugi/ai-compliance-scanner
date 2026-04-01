#!/usr/bin/env python3
"""
Install the AI Compliance Scanner pre-commit hook into your git repo.

Usage:
    python install_hooks.py              # install in current repo
    python install_hooks.py /path/repo   # install in specific repo
"""

import sys
import shutil
from pathlib import Path


def install(repo_path: Path):
    git_dir = repo_path / ".git"
    if not git_dir.exists():
        print(f"Not a git repository: {repo_path}")
        sys.exit(1)

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)

    src = Path(__file__).parent / "hooks" / "pre-commit"
    dst = hooks_dir / "pre-commit"

    if not src.exists():
        print(f"Hook file not found: {src}")
        sys.exit(1)

    shutil.copy2(src, dst)
    dst.chmod(0o755)

    print(f"Pre-commit hook installed in {dst}")
    print("Every commit will now be checked for HIGH risk compliance issues.")


if __name__ == "__main__":
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    install(path.resolve())
