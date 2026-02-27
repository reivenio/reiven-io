const ARGON2_FIXED_PROFILE = Object.freeze({
  time: 4,
  mem: 65536,
  parallelism: 1,
});

export const ENCRYPTION_CONFIG = Object.freeze({
  magic: 'ESHARE1',
  formatVersion: 4,
  defaultPim: 100,
  defaultSecurityLevel: 1,
  fixedLevelLabel: 'Hardened',
  saltLen: 16,
  ivLen: 12,
  checkIvLen: 12,
  wrapIvLen: 12,
  headerFixedLen: 24,
  headerProbeBytes: 4096,
  checkMarker: 'RAVEN_OK_V2',
  mlKemSeedDomain: 'REIVEN_MLKEM_SEED_V1',
  argon2FixedProfile: ARGON2_FIXED_PROFILE,
});

