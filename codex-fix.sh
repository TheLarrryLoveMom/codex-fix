#!/usr/bin/env bash
# Codex Fix: automatic Linux network diagnosis and targeted repair.
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'Ошибка: требуется Python 3.9+ (пакет python3).' >&2
    exit 1
fi

script_path=$(readlink -f -- "${BASH_SOURCE[0]}")
script_dir=$(cd -- "$(dirname -- "$script_path")" && pwd)
exec python3 "$script_dir/codex_fix.py" "$@"
