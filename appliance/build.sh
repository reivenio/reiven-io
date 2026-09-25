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

for command_name in curl debootstrap git grub-mkrescue mformat mkfs.vfat mksquashfs rg rsync sha256sum ssh-keygen tar xorriso; do
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

git_commit=$(git -C "$repo_dir" rev-parse HEAD)
git_dirty=false
if [[ -n $(git -C "$repo_dir" status --porcelain --untracked-files=normal) ]]; then
  git_dirty=true
fi
if [[ $git_dirty == true && ${REIVEN_ALLOW_DIRTY:-0} != 1 ]]; then
  echo "Refusing to build from a dirty working tree. Commit the release or set REIVEN_ALLOW_DIRTY=1 for a disposable test image." >&2
  exit 1
fi

boot_ip=${REIVEN_BOOT_IP:-dhcp}
if [[ $boot_ip =~ [[:space:]] ]]; then
  echo "REIVEN_BOOT_IP must be one kernel ip= value without whitespace." >&2
  exit 1
fi

build_root=$(mktemp -d "${TMPDIR:-/tmp}/reiven-appliance.XXXXXX")
rootfs="$build_root/rootfs"
iso_root="$build_root/iso"

unmount_chroot() {
  local mount_path
  for mount_path in "$rootfs/sys" "$rootfs/proc" "$rootfs/dev"; do
    if mountpoint -q "$mount_path"; then
      umount -R "$mount_path" || umount -l "$mount_path" || true
    fi
  done
}

cleanup() {
  unmount_chroot
  rm -rf -- "$build_root"
}
trap cleanup EXIT

debootstrap \
  --arch="$IMAGE_ARCH" \
  --variant=minbase \
  --components=main,universe \
  "$UBUNTU_CODENAME" \
  "$rootfs" \
  https://archive.ubuntu.com/ubuntu

mount --rbind /dev "$rootfs/dev"
mount --make-rslave "$rootfs/dev"
mount -t proc proc "$rootfs/proc"
mount -t sysfs sysfs "$rootfs/sys"

cat > "$rootfs/etc/apt/sources.list" <<EOF
deb http://archive.ubuntu.com/ubuntu ${UBUNTU_CODENAME} main universe
deb http://archive.ubuntu.com/ubuntu ${UBUNTU_CODENAME}-updates main universe
deb http://security.ubuntu.com/ubuntu ${UBUNTU_CODENAME}-security main universe
EOF
rm -f "$rootfs/etc/resolv.conf"
cp -L /etc/resolv.conf "$rootfs/etc/resolv.conf"

mapfile -t image_packages < <(sed -e 's/[[:space:]]*#.*$//' -e '/^[[:space:]]*$/d' "$script_dir/config/package-lists/reiven.list.chroot")
chroot "$rootfs" env DEBIAN_FRONTEND=noninteractive apt-get update
chroot "$rootfs" env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends "${image_packages[@]}"

cp -a "$script_dir/config/includes.chroot/." "$rootfs/"
install -d -m 0755 "$rootfs/opt/reiven"
rsync -a --delete "$repo_dir/public" "$repo_dir/shared" "$repo_dir/direct-server" "$rootfs/opt/reiven/"
install -D -o root -g root -m 0600 "$authorized_keys_file" "$rootfs/etc/ssh/authorized_keys/reiven-admin"

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
install -d -m 0755 "$rootfs/opt/node"
tar -xJf "$build_root/$node_archive" --strip-components=1 -C "$rootfs/opt/node"

build_time=$(date -u +%Y-%m-%dT%H:%M:%SZ)
install -D -m 0644 /dev/null "$rootfs/etc/reiven-release"
{
  printf 'BUILD_TIME=%s\n' "$build_time"
  printf 'GIT_COMMIT=%s\n' "$git_commit"
  printf 'GIT_DIRTY=%s\n' "$git_dirty"
  printf 'UBUNTU_CODENAME=%s\n' "$UBUNTU_CODENAME"
  printf 'NODE_VERSION=%s\n' "$NODE_VERSION"
  printf 'NODE_SHA256=%s\n' "$NODE_SHA256"
} > "$rootfs/etc/reiven-release"

install -D -m 0755 "$script_dir/config/hooks/live/0900-reiven-appliance.hook.chroot" "$rootfs/tmp/reiven-appliance-hook"
chroot "$rootfs" /bin/sh /tmp/reiven-appliance-hook
rm -f "$rootfs/tmp/reiven-appliance-hook"

dpkg_query_format="\${binary:Package}\t\${Version}\n"
chroot "$rootfs" dpkg-query -W -f="$dpkg_query_format" | sort > "$build_root/packages.tsv"

kernel_version=$(find "$rootfs/boot" -maxdepth 1 -type f -name 'vmlinuz-*' -printf '%f\n' | sed 's/^vmlinuz-//' | sort -V | tail -n 1)
if [[ -z $kernel_version || ! -s $rootfs/boot/initrd.img-$kernel_version ]]; then
  echo "The appliance kernel or initramfs is missing." >&2
  exit 1
fi

unmount_chroot
rm -f "$rootfs/etc/resolv.conf"
ln -s /run/systemd/resolve/stub-resolv.conf "$rootfs/etc/resolv.conf"

install -d -m 0755 "$iso_root/boot/grub" "$iso_root/casper"
install -m 0644 "$rootfs/boot/vmlinuz-$kernel_version" "$iso_root/casper/vmlinuz"
install -m 0644 "$rootfs/boot/initrd.img-$kernel_version" "$iso_root/casper/initrd"
printf '%s\n' "$(du -sx --block-size=1 "$rootfs" | cut -f1)" > "$iso_root/casper/filesystem.size"
mksquashfs "$rootfs" "$iso_root/casper/filesystem.squashfs" -comp xz -noappend -e boot

cat > "$iso_root/boot/grub/grub.cfg" <<EOF
set default=0
set timeout=5

menuentry "Reiven RAM Appliance" {
    linux /casper/vmlinuz boot=casper components toram nopersistence ip=${boot_ip} hostname=reiven ---
    initrd /casper/initrd
}
EOF

image_path="$build_root/reiven-appliance-${IMAGE_ARCH}.hybrid.iso"
grub-mkrescue --output="$image_path" "$iso_root"
if [[ ! -s $image_path ]]; then
  echo "The image builder did not produce the expected ISO." >&2
  exit 1
fi

output_dir=${REIVEN_OUTPUT_DIR:-$script_dir/dist}
install -d -m 0755 "$output_dir"
release_id="$(date -u +%Y%m%d)-${git_commit:0:12}"
output_image="$output_dir/reiven-appliance-${release_id}-${IMAGE_ARCH}.iso"
install -m 0644 "$image_path" "$output_image"
(
  cd "$output_dir"
  sha256sum "$(basename "$output_image")" > "$(basename "$output_image").sha256"
)
install -m 0644 "$build_root/packages.tsv" "$output_image.packages.tsv"
git -C "$repo_dir" ls-files -s | sort > "$output_image.source-manifest.tsv"
cp "$build_root/SHASUMS256.txt" "$output_image.node-shasums.txt"

printf '%s\n' "$output_image"
