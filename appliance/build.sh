#!/usr/bin/env bash
set -Eeuo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd -- "$script_dir/.." && pwd)
source "$script_dir/versions.env"

if [[ $(id -u) -ne 0 ]]; then
  echo "Run this builder as root on Ubuntu 24.04." >&2
  exit 1
fi

if [[ ! -r /etc/os-release ]]; then
  echo "Ubuntu 24.04 is required to build the appliance." >&2
  exit 1
fi

source /etc/os-release
if [[ ${ID:-} != ubuntu || ${VERSION_ID:-} != 24.04 ]]; then
  echo "Ubuntu 24.04 is required to build the appliance." >&2
  exit 1
fi

for command_name in curl git lb rg rsync sha256sum ssh-keygen tar; do
  command -v "$command_name" >/dev/null || {
    echo "Missing build dependency: $command_name" >&2
    exit 1
  }
done

authorized_keys_file=${REIVEN_AUTHORIZED_KEYS_FILE:-}
if [[ -z $authorized_keys_file || ! -s $authorized_keys_file ]]; then
  echo "Set REIVEN_AUTHORIZED_KEYS_FILE to a non-empty administrator public-key file." >&2
  exit 1
fi

if rg -q -- 'PRIVATE KEY|BEGIN [A-Z ]*PRIVATE KEY' "$authorized_keys_file"; then
  echo "The authorized-keys input appears to contain a private key." >&2
  exit 1
fi

if ! ssh-keygen -l -f "$authorized_keys_file" >/dev/null 2>&1; then
  echo "The authorized-keys input does not contain a valid SSH public key." >&2
  exit 1
fi

build_root=$(mktemp -d "${TMPDIR:-/tmp}/reiven-appliance.XXXXXX")
cleanup() {
  if mountpoint -q "$build_root/chroot/dev"; then
    umount -l "$build_root/chroot/dev" || true
  fi
  if mountpoint -q "$build_root/chroot/proc"; then
    umount -l "$build_root/chroot/proc" || true
  fi
  if mountpoint -q "$build_root/chroot/sys"; then
    umount -l "$build_root/chroot/sys" || true
  fi
  rm -rf -- "$build_root"
}
trap cleanup EXIT

cp -a "$script_dir/config" "$build_root/config"
install -d -m 0755 "$build_root/config/includes.chroot/opt/reiven"
rsync -a --delete "$repo_dir/public" "$repo_dir/shared" "$repo_dir/direct-server" "$build_root/config/includes.chroot/opt/reiven/"
install -D -o root -g root -m 0600 "$authorized_keys_file" "$build_root/config/includes.chroot/etc/ssh/authorized_keys/reiven-admin"

node_archive="node-${NODE_VERSION}-linux-${NODE_ARCH}.tar.xz"
node_base_url="https://nodejs.org/dist/${NODE_VERSION}"
curl --fail --location --proto '=https' --tlsv1.2 --output "$build_root/SHASUMS256.txt" "$node_base_url/SHASUMS256.txt"
curl --fail --location --proto '=https' --tlsv1.2 --output "$build_root/$node_archive" "$node_base_url/$node_archive"
actual_node_sha=$(sha256sum "$build_root/$node_archive" | awk '{print $1}')
if [[ $actual_node_sha != "$NODE_SHA256" ]]; then
  echo "Node archive does not match the checksum pinned in appliance/versions.env." >&2
  exit 1
fi
(
  cd "$build_root"
  rg --fixed-strings " $node_archive" SHASUMS256.txt | sha256sum --check --strict
)
install -d -m 0755 "$build_root/config/includes.chroot/opt/node"
tar -xJf "$build_root/$node_archive" --strip-components=1 -C "$build_root/config/includes.chroot/opt/node"

git_commit=$(git -C "$repo_dir" rev-parse HEAD)
git_dirty=false
if [[ -n $(git -C "$repo_dir" status --porcelain --untracked-files=normal) ]]; then
  git_dirty=true
fi
if [[ $git_dirty == true && ${REIVEN_ALLOW_DIRTY:-0} != 1 ]]; then
  echo "Refusing to build from a dirty working tree. Commit the release or set REIVEN_ALLOW_DIRTY=1 for a disposable test image." >&2
  exit 1
fi
build_time=$(date -u +%Y-%m-%dT%H:%M:%SZ)
install -D -m 0644 /dev/null "$build_root/config/includes.chroot/etc/reiven-release"
{
  printf 'BUILD_TIME=%s\n' "$build_time"
  printf 'GIT_COMMIT=%s\n' "$git_commit"
  printf 'GIT_DIRTY=%s\n' "$git_dirty"
  printf 'UBUNTU_CODENAME=%s\n' "$UBUNTU_CODENAME"
  printf 'NODE_VERSION=%s\n' "$NODE_VERSION"
  printf 'NODE_SHA256=%s\n' "$NODE_SHA256"
} > "$build_root/config/includes.chroot/etc/reiven-release"

boot_ip=${REIVEN_BOOT_IP:-dhcp}
if [[ $boot_ip =~ [[:space:]] ]]; then
  echo "REIVEN_BOOT_IP must be one kernel ip= value without whitespace." >&2
  exit 1
fi
cd "$build_root"
lb config \
  --mode ubuntu \
  --architectures "$IMAGE_ARCH" \
  --distribution "$UBUNTU_CODENAME" \
  --archive-areas "main universe" \
  --binary-images iso-hybrid \
  --bootloaders "grub-pc grub-efi" \
  --chroot-filesystem squashfs \
  --initramfs casper \
  --linux-flavours generic \
  --apt-recommends false \
  --apt-secure true \
  --security true \
  --memtest none \
  --source false \
  --iso-application "Reiven RAM Appliance" \
  --iso-publisher "Reiven.io" \
  --iso-volume "REIVEN_RAM" \
  --bootappend-live "boot=casper components toram nopersistence ip=${boot_ip} hostname=reiven"

lb build

image_path="$build_root/live-image-${IMAGE_ARCH}.hybrid.iso"
if [[ ! -s $image_path ]]; then
  echo "live-build did not produce the expected ISO." >&2
  exit 1
fi

output_dir=${REIVEN_OUTPUT_DIR:-$script_dir/dist}
install -d -m 0755 "$output_dir"
release_id="$(date -u +%Y%m%d)-${git_commit:0:12}"
output_image="$output_dir/reiven-appliance-${release_id}-${IMAGE_ARCH}.iso"
install -m 0644 "$image_path" "$output_image"
sha256sum "$output_image" > "$output_image.sha256"
dpkg_query_format="\${binary:Package}\\t\${Version}\\n"
chroot "$build_root/chroot" dpkg-query -W -f="$dpkg_query_format" | sort > "$output_image.packages.tsv"
git -C "$repo_dir" ls-files -s | sort > "$output_image.source-manifest.tsv"
cp "$build_root/SHASUMS256.txt" "$output_image.node-shasums.txt"

printf '%s\n' "$output_image"
