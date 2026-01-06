"""Scaffold the LogSentinel project directory structure and boilerplate files.
"""

from pathlib import Path

# Base directory = current working directory
BASE_DIR = Path.cwd()

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
    "README.md": "# LogSentinel\n\nCLI tool for log-based threat detection.\n",
    "pyproject.toml": "",
    "LICENSE": "MIT License\n",
}


def create_structure(base: Path, tree: dict) -> None:
    """Create the project structure."""
    for name, content in tree.items():
        path = base / name

        if isinstance(content, dict):
            path.mkdir(parents=True, exist_ok=True)
            print(f"[DIR ] {path}")
            create_structure(path, content)
        else:
            if not path.exists():
                path.write_text(content, encoding="utf-8")
                print(f"[FILE] {path}")
            else:
                print(f"[SKIP] {path} already exists")


if __name__ == "__main__":
    print("🚀 Scaffolding LogSentinel project structure...\n")
    create_structure(BASE_DIR, STRUCTURE)
    print("\n✅ Project structure ready.")
