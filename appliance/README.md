# Reiven RAM-Boot Appliance

This directory builds a minimal Ubuntu 24.04 LTS hybrid ISO for the Reiven service. The image uses a read-only SquashFS base and a volatile writable overlay. The boot command requires `toram` and `nopersistence`; the application and TLS proxy fail closed when the runtime invariants are not met.

The framework is intentionally separate from production rollout. Building or testing an image does not modify or reboot the current Reiven server.

## Cold-Boot Behavior

Every cold boot creates a new empty system state:

- Reiven payload and metadata maps start empty.
- Caddy creates fresh ACME account, certificate and private-key state under `/run`.
- SSH host keys and `/etc/machine-id` are regenerated.
- The journal is volatile and bounded to 64 MiB.
- Swap, hibernation, persistence and crash collection are absent or disabled.
- The firewall exposes only SSH, HTTP and HTTPS.
- Caddy and Reiven start only after the ephemeral guard succeeds.

The administrator public key is injected at build time. Public keys are not secret, but the build requires explicit input to avoid producing an inaccessible image. No TLS, SSH or other private key is included in the image.

## Build Host

Use a disposable Ubuntu 24.04 amd64 builder with at least 16 GiB free disk space. The build needs root privileges because `live-build` uses chroots and mounts.

```bash
sudo apt-get update
sudo apt-get install --yes live-build ripgrep rsync shellcheck xorriso squashfs-tools syslinux-utils
cp appliance/authorized_keys.example appliance/authorized_keys
$EDITOR appliance/authorized_keys
sudo env REIVEN_AUTHORIZED_KEYS_FILE="$PWD/appliance/authorized_keys" \
  REIVEN_OUTPUT_DIR="$PWD/appliance/dist" \
  ./appliance/build.sh
```

The output directory receives:

- the hybrid ISO;
- its SHA-256 checksum;
- the exact Ubuntu package manifest;
- the Git source manifest;
- the upstream Node checksum file used during verification.

The builder downloads Node over HTTPS and verifies the selected archive against both the repository-pinned checksum and Node's published SHA-256 manifest. Ubuntu packages are signature-checked by APT. The image records the Git commit, dirty-tree state, build time, Ubuntu series and Node version in `/etc/reiven-release`.

Release builds require a clean Git working tree. A disposable local experiment can opt in to `REIVEN_ALLOW_DIRTY=1`; such an image must not be promoted to production.

Set `REIVEN_BOOT_IP` to a kernel `ip=` value when DHCP is not suitable. It defaults to `dhcp`. Do not embed DNS-provider credentials, TLS keys or private SSH keys in this variable or anywhere in the image.

## Validation

Run lightweight source validation on any development host:

```bash
npm run appliance:validate
```

Check whether the pinned Node runtime is still the latest LTS and whether its checksum still matches the upstream manifest:

```bash
npm run appliance:updates
```

Before production, boot the ISO on a disposable VM or replacement machine and verify:

1. The ISO boots in both UEFI and legacy modes used by the target hardware.
2. `/proc/cmdline` contains `toram` and `nopersistence`.
3. `/` is `overlay`; `/proc/swaps` has no entries; no block-backed mount is writable.
4. `reiven-ephemeral-guard`, `reiven-direct`, `caddy`, `ssh` and `nftables` are active.
5. Caddy obtains a certificate using the ACME staging endpoint during repeated tests.
6. The browser and CLI pass v6 upload, download, QR, deletion and tamper checks.
7. A cold reboot changes SSH host fingerprints and destroys all synthetic shares.
8. A service restart does not erase Caddy's current-boot ACME state; a cold reboot does.
9. Deliberately removing `toram` or adding a writable block mount prevents Caddy and Reiven from starting.

After boot, run `sudo reiven-status` for the release identity, boot flags, root filesystem, swap count, core policy, fresh SSH fingerprint, service state and local application health. The SSH fingerprint is also written to the physical/remote console during boot so it can be verified before accepting the changed host identity.

Repeated certificate testing must use the ACME staging endpoint. Production certificate issuance is reserved for the final DNS-connected acceptance test.

## Release and Maintenance

The workflow in `.github/workflows/appliance.yml` validates every relevant change and builds a fresh candidate weekly or on manual dispatch. The candidate build is blocked when the pinned Node release is no longer the latest LTS. Dependabot proposes reviewable npm and workflow updates each week. Configure the `REIVEN_ADMIN_AUTHORIZED_KEYS` repository secret with one or more administrator public-key lines before enabling scheduled builds.

The workflow publishes build artifacts and a provenance attestation. A candidate is not automatically deployed. Promotion remains a separate, explicit operation after VM testing and review of:

- application commit and dirty state;
- package and Node versions;
- Ubuntu security findings;
- boot and runtime smoke results;
- checksum and provenance.

Static files may be updated in a running RAM instance without restart. Node/application changes require an application restart and destroy active Reiven shares. Kernel or base-image changes require booting a replacement image and destroy all volatile state. Direct hotfixes must be carried into the next image or they disappear on reboot.

Keep the current approved image and one previous approved image. Rollback means booting a reviewed image, not restoring a legacy cryptographic protocol. Images contain public administrator keys and application source, so their distribution should still be controlled. Review Ubuntu redistribution obligations before publishing images publicly.

## Current Boundaries

This first framework establishes the build, boot invariants, fresh identity model and release artifacts. Production promotion still requires target-specific validation for networking, firmware/UEFI, remote media persistence and the hosting provider's reboot controls. It does not authorize rebooting the current host.
