#!/usr/bin/env bash
set -Eeuo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$script_dir/.." && pwd)

required_files=(
  "$script_dir/build.sh"
  "$script_dir/versions.env"
  "$script_dir/config/hooks/live/0900-reiven-appliance.hook.chroot"
  "$script_dir/config/includes.chroot/usr/local/sbin/reiven-ephemeral-guard"
  "$script_dir/config/includes.chroot/usr/local/sbin/reiven-first-boot"
  "$script_dir/config/includes.chroot/usr/local/sbin/reiven-status"
  "$script_dir/config/includes.chroot/etc/systemd/system/reiven-first-boot.service"
  "$script_dir/config/includes.chroot/etc/systemd/system/reiven-ephemeral-guard.service"
  "$script_dir/config/includes.chroot/etc/systemd/system/reiven-direct.service"
  "$script_dir/config/includes.chroot/etc/systemd/system/caddy.service.d/ram-only.conf"
)

for required_file in "${required_files[@]}"; do
  [[ -s $required_file ]] || {
    echo "Missing required appliance file: $required_file" >&2
    exit 1
  }
done

shell_files=()
while IFS= read -r shell_file; do
  shell_files+=("$shell_file")
done < <(find "$script_dir" -type f \( -name '*.sh' -o -name '*.hook.chroot' -o -path '*/usr/local/sbin/*' \) -print | sort)

for shell_file in "${shell_files[@]}"; do
  bash -n "$shell_file"
done

if command -v shellcheck >/dev/null; then
  shellcheck -e SC1091 -x "${shell_files[@]}"
fi

if rg -n --glob '!authorized_keys.example' 'BEGIN [A-Z ]*PRIVATE KEY|ssh-(rsa|ed25519) [A-Za-z0-9+/]{100,}' "$script_dir"; then
  echo "Credential-like material found in appliance sources." >&2
  exit 1
fi

rg -q --fixed-strings 'toram' "$script_dir/build.sh"
rg -q --fixed-strings 'nopersistence' "$script_dir/build.sh"
rg -q --fixed-strings 'XDG_DATA_HOME=/run/caddy-data' "$script_dir/config/includes.chroot/etc/systemd/system/caddy.service.d/ram-only.conf"
rg -q --fixed-strings 'MemorySwapMax=0' "$script_dir/config/includes.chroot/etc/systemd/system/reiven-direct.service"
rg -q --fixed-strings 'Storage=volatile' "$script_dir/config/includes.chroot/etc/systemd/journald.conf.d/volatile.conf"
rg -q '^NODE_SHA256=[0-9a-f]{64}$' "$script_dir/versions.env"

node --check "$repo_dir/direct-server/server.mjs"
node --check "$repo_dir/public/upload.js"
node --check "$repo_dir/public/download.js"
git -C "$repo_dir" diff --check

echo "Appliance framework validation passed."
