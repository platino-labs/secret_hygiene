#!/bin/sh
set -u

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 2
root=$(git -C "$script_dir" rev-parse --show-toplevel 2>/dev/null) || {
    echo "ERROR: run.sh must be inside a Git repository" >&2
    exit 2
}

if ! command -v gitleaks >/dev/null 2>&1; then
    echo "ERROR: gitleaks is required (install it from https://github.com/gitleaks/gitleaks)" >&2
    exit 2
fi

if gitleaks dir "$root" --no-banner --redact=100; then
    tree_rc=0
else
    tree_rc=$?
fi

if gitleaks git "$root" --no-banner --redact=100; then
    history_rc=0
else
    history_rc=$?
fi

printf 'RESULT tree_rc=%s history_rc=%s\n' "$tree_rc" "$history_rc"

if [ "$tree_rc" -gt 1 ] || [ "$history_rc" -gt 1 ]; then
    exit 2
fi
if [ "$tree_rc" -ne 0 ] || [ "$history_rc" -ne 0 ]; then
    exit 1
fi
exit 0

# HUELLA_SECRET_HYGIENE_RUN_FINAL_20261031
