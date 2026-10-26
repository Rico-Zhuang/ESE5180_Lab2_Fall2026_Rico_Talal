#!/usr/bin/env bash
set -euo pipefail
tool_root="$HOME/.local/share/ese5180-tools/openocd"
export LD_LIBRARY_PATH="$tool_root/usr/lib/x86_64-linux-gnu"
exec "$tool_root/usr/bin/openocd" -s "$tool_root/usr/share/openocd/scripts" "$@"
