# APKraft

APKraft is a small, Python-based APK editor and inspection tool. It focuses on the
basics you need when auditing or hot‑patching an Android application package:
listing the archive contents, pulling assets out, dropping new files in, dumping
`AndroidManifest.xml`, and even rebuilding an APK from an unpacked directory.

## Features

- Inspect package metadata (package id, version info, SDK targets, SHA-256) and signing certificates
- List archive entries with size/compression statistics and optional glob filtering
- Extract individual files or fully unpack an APK into a working directory
- Replace, delete, or add files with optional in-place editing and automatic backups
- Pretty-print the decoded `AndroidManifest.xml` or emit it as-is for tooling
- Repack a modified directory tree back into a distributable APK

## Prerequisites

- Python 3.10+
- A virtual environment is recommended to keep dependencies isolated

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
```

After installation, the `apkraft` CLI will be on your `$PATH` (inside the
virtual environment).

## Usage

Each command accepts an APK path as its first argument unless noted otherwise.
Use `--help` on any command to view all available switches.

```bash
# Print metadata as a table (or add --json for machine output)
apkraft info samples/app.apk

# List only XML files inside res/ ordered by size
apkraft list samples/app.apk -p "res/**/*.xml" --sort size -n 20

# Extract a single asset into ./scratch
apkraft extract samples/app.apk assets/config.json --dest scratch

# Replace a file in-place (keeps samples/app.apk.bak)
apkraft replace samples/app.apk classes.dex patched.dex --in-place

# Dump the decoded manifest to disk
apkraft manifest samples/app.apk --output manifest.xml

# Unpack the whole archive, edit it, then rebuild a new APK
apkraft unpack samples/app.apk workdir
# ...make changes under workdir...
apkraft repack workdir patched.apk
```

If you rather keep the original APK untouched while editing, pass
`--output new.apk` to the editing commands instead of `--in-place`.

## AI agent (experimental)

APKraft now ships with an optional AI-powered workflow that can help you inspect
and edit APK contents using natural language prompts. The `apkraft agent`
command unpacks an APK into a workspace directory and lets an OpenRouter-hosted
model drive a constrained set of tooling actions (list directories, read text
assets, write files, delete paths). Bring your own OpenRouter API key:

```bash
export OPENROUTER_API_KEY="sk-or-v1-your-key"
apkraft agent samples/app.apk "Remove the debug logging config"
```

Important notes:

- The agent only edits plain-text assets (XML/JSON/smali/etc.). Binary blobs and
  signing are out of scope.
- Every run extracts the APK into a temporary workspace. Pass `--workspace` to
  reuse a folder or `--dry-run` to skip rebuilding so you can inspect changes
  manually.
- Use flags like `--model`, `--temperature`, or `--max-steps` to steer the
  OpenRouter request, and `--referer`/`--title` if your account requires those
  headers.
- Combine `--in-place`/`--backup`/`--output` the same way as the manual editing
  commands once you are ready to repack.

## Development

- Format/linting is intentionally lightweight; focus on readable, well-tested code.
- Add or update tests under a `tests/` package if you implement more functionality.
- When changing dependencies, update `pyproject.toml` accordingly and regenerate your
  virtual environment if needed.

Contributions via pull request are welcome.
