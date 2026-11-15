#!/usr/bin/env bash
# Registers (or removes) the Aegis native-messaging host for Firefox-based
# browsers. Run it once after building; no root needed.
#
#   extension/native/install-host.sh              install for browsers found
#   extension/native/install-host.sh --uninstall  remove the registration
set -euo pipefail

HOST_NAME="aegis"
EXTENSION_ID="aegis@pwm.local"
HERE="$(CDPATH= cd -- "$(dirname -- "$(readlink -f -- "$0")")" && pwd)"
LAUNCHER="$HERE/aegis-host"

# Browser data dirs whose native-messaging-hosts folder we may write to.
TARGETS=(
    "$HOME/.mozilla"
    "$HOME/.librewolf"
    "$HOME/.floorp"
    "$HOME/.waterfox"
)

mode="install"
[[ "${1:-}" == "--uninstall" ]] && mode="uninstall"

json_escape() {
    local s="${1//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\t'/\\t}"
    s="${s//$'\r'/\\r}"
    # Any other control character is not valid in JSON strings; drop it.
    printf '%s' "$s" | tr -d '\000-\037'
}

found=0
for base in "${TARGETS[@]}"; do
    [[ -d "$base" ]] || continue
    dir="$base/native-messaging-hosts"
    manifest="$dir/$HOST_NAME.json"
    found=1
    if [[ "$mode" == "uninstall" ]]; then
        rm -f "$manifest"
        printf 'removed %s\n' "$manifest"
        continue
    fi
    mkdir -p "$dir"
    cat > "$manifest" <<JSON
{
  "name": "$HOST_NAME",
  "description": "Aegis password manager native host",
  "path": "$(json_escape "$LAUNCHER")",
  "type": "stdio",
  "allowed_extensions": ["$EXTENSION_ID"]
}
JSON
    printf 'installed %s\n' "$manifest"
done

if [[ $found -eq 0 ]]; then
    printf 'No Firefox-based browser profile directory found (looked in: %s)\n' "${TARGETS[*]}" >&2
    exit 1
fi

if [[ "$mode" == "install" && ! -x "$HERE/../../target/release/aegis" && ! -x "$HERE/../../target/debug/aegis" ]]; then
    printf 'note: Aegis is not built yet; run `cargo build --release` before using the extension.\n' >&2
fi
