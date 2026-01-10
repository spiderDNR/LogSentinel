"""Scaffold the LogSentinel project directory structure and boilerplate files.

This module provides utilities for creating a professional Python project
structure with essential root files including .gitignore, README.md, and
pyproject.toml. All operations are idempotent and will not overwrite existing
files.
"""

from pathlib import Path
from typing import Dict, Any


# Base directory = current working directory
BASE_DIR = Path.cwd()


# Root file templates
GITIGNORE_CONTENT = """.venv/
__pycache__/
*.egg-info/
dist/
build/
.mypy_cache/
.ruff_cache/
.pytest_cache/
.DS_Store
Thumbs.db
"""

README_CONTENT = """# Project Title

Project description placeholder.
"""

PYPROJECT_TOML_CONTENT = """[build-system]
requires = ["setuptools>=68", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "project-name-placeholder"
version = "0.1.0"
dependencies = []
"""

STRUCTURE = {
    "logsentinel": {
        "__init__.py": "",
        "cli.py": "",
        "engine.py": "",
        "config.py": "",
        "report.py": "",
        "analysis": {
            "__init__.py": "",
            "events.py": "",
            "parser_ssh.py": "",
            "analyzer.py": "",
        },
        "utils": {
            "__init__.py": "",
        },
    },
    "tests": {
        "__init__.py": "",
        "test_parser_ssh.py": "",
        "test_analyzer.py": "",
    },
    "LICENSE": "MIT License\n",
}


def create_root_file(base: Path, filename: str, content: str) -> bool:
    """Create a root file if it doesn't exist.

    Args:
        base: Base directory path where the file should be created.
        filename: Name of the file to create.
        content: Content to write to the file.

    Returns:
        True if the file was created, False if it already existed.

    Raises:
        OSError: If file creation fails due to filesystem errors.
    """
    file_path = base / filename
    try:
        if not file_path.exists():
            file_path.write_text(content, encoding="utf-8")
            print(f"[CREATED] {file_path}")
            return True
        else:
            print(f"[SKIPPED] {file_path} (already exists)")
            return False
    except OSError as e:
        print(f"[ERROR] Failed to create {file_path}: {e}")
        raise


def create_root_files(base: Path) -> None:
    """Create essential root files for a professional Python project.

    Creates .gitignore, README.md, and pyproject.toml if they don't exist.
    This function is idempotent and will not overwrite existing files.

    Args:
        base: Base directory path where root files should be created.

    Raises:
        OSError: If file creation fails due to filesystem errors.
    """
    root_files = {
        ".gitignore": GITIGNORE_CONTENT,
        "README.md": README_CONTENT,
        "pyproject.toml": PYPROJECT_TOML_CONTENT,
    }

    for filename, content in root_files.items():
        create_root_file(base, filename, content)


def create_structure(base: Path, tree: Dict[str, Any]) -> None:
    """Create the project directory structure.

    Recursively creates directories and files as specified in the tree
    structure. Files are only created if they don't already exist
    (idempotent).

    Args:
        base: Base directory path where the structure should be created.
        tree: Nested dictionary representing the directory structure.
             Dictionary values can be either strings (file content) or
             dictionaries (subdirectories).

    Raises:
        OSError: If directory or file creation fails due to filesystem
                 errors.
    """
    for name, content in tree.items():
        path = base / name

        if isinstance(content, dict):
            try:
                path.mkdir(parents=True, exist_ok=True)
                print(f"[DIR   ] {path}")
                create_structure(path, content)
            except OSError as e:
                print(f"[ERROR] Failed to create directory {path}: {e}")
                raise
        else:
            try:
                if not path.exists():
                    path.write_text(content, encoding="utf-8")
                    print(f"[CREATED] {path}")
                else:
                    print(f"[SKIPPED] {path} (already exists)")
            except OSError as e:
                print(f"[ERROR] Failed to create file {path}: {e}")
                raise


if __name__ == "__main__":
    print("🚀 Scaffolding LogSentinel project structure...\n")

    try:
        print("Creating essential root files...")
        create_root_files(BASE_DIR)
        print()

        print("Creating project directory structure...")
        create_structure(BASE_DIR, STRUCTURE)
        print("\n✅ Project structure ready.")
    except OSError as e:
        print(f"\n❌ Scaffolding failed: {e}")
        exit(1)
