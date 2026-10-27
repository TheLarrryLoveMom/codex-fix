#!/usr/bin/env bash
# Codex Fix: automatic Linux network diagnosis and targeted repair.
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
    if [[ -t 2 && ! -v NO_COLOR && ${TERM:-} != dumb ]]; then
        printf '\033[31m  ❌ Требуется Python 3.9+. Установите пакет python3.\033[0m\n' >&2
    else
        printf '%s\n' '  [X] Требуется Python 3.9+. Установите пакет python3.' >&2
    fi
    exit 1
fi

script_path=$(readlink -f -- "${BASH_SOURCE[0]}")
script_dir=$(cd -- "$(dirname -- "$script_path")" && pwd)
exec python3 "$script_dir/codex_fix.py" "$@"
