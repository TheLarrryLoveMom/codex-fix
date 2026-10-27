#!/usr/bin/env bash
# Installs Codex Fix from the official GitHub repository.
set -euo pipefail

repository="TheLarrryLoveMom/codex-fix"
branch="main"
data_home=${XDG_DATA_HOME:-"$HOME/.local/share"}
bin_home=${XDG_BIN_HOME:-"$HOME/.local/bin"}
install_dir=${CODEX_FIX_INSTALL_DIR:-"$data_home/codex-fix/app"}
bin_dir=${CODEX_FIX_BIN_DIR:-"$bin_home"}
launcher="$bin_dir/codex-fix"
source_url="https://raw.githubusercontent.com/$repository/$branch"
temporary_dir=$(mktemp -d "${TMPDIR:-/tmp}/codex-fix.XXXXXX")

cleanup() {
    rm -rf -- "$temporary_dir"
}
trap cleanup EXIT HUP INT TERM

if ! command -v curl >/dev/null 2>&1; then
    printf '%s\n' 'Codex Fix installer: curl is required.' >&2
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    printf '%s\n' 'Codex Fix installer: Python 3.9+ is required.' >&2
    exit 1
fi

if [[ -e "$launcher" || -L "$launcher" ]]; then
    current_target=$(readlink -f -- "$launcher" 2>/dev/null || true)
    expected_target="$install_dir/codex-fix.sh"
    if [[ "$current_target" != "$expected_target" ]]; then
        printf 'Codex Fix installer: %s already exists and is not managed by this installer.\n' "$launcher" >&2
        printf 'Choose another location with CODEX_FIX_BIN_DIR, or move the existing file first.\n' >&2
        exit 1
    fi
fi

printf '%s\n' 'Downloading Codex Fix…'
for file in codex-fix.sh codex_fix.py; do
    curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
        "$source_url/$file" --output "$temporary_dir/$file"
    [[ -s "$temporary_dir/$file" ]] || { printf 'Downloaded empty file: %s\n' "$file" >&2; exit 1; }
done

mkdir -p -- "$install_dir" "$bin_dir"
install -m 0700 "$temporary_dir/codex-fix.sh" "$install_dir/codex-fix.sh"
install -m 0600 "$temporary_dir/codex_fix.py" "$install_dir/codex_fix.py"
ln -sfn -- "$install_dir/codex-fix.sh" "$launcher"

printf 'Installed: %s\n' "$launcher"
if [[ ":$PATH:" != *":$bin_dir:"* ]]; then
    printf 'Add this directory to PATH to run codex-fix by name: %s\n' "$bin_dir"
fi

if (($#)); then
    exec "$launcher" "$@"
fi
