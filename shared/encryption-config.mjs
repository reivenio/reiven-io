const ARGON2_PROFILES = Object.freeze({
  standard: Object.freeze({
    label: 'Standard',
    time: 4,
    mem: 65536,
    parallelism: 1,
  }),
  paranoid: Object.freeze({
    label: 'Paranoid',
    time: 6,
    mem: 131072,
    parallelism: 1,
  }),
});

const DEFAULT_ENCRYPTION_TYPE = 'standard';

export const ENCRYPTION_CONFIG = Object.freeze({
  magic: 'ESHARE1',
  formatVersion: 4,
  defaultPim: 100,
  defaultEncryptionType: DEFAULT_ENCRYPTION_TYPE,
  defaultSecurityLevel: 1,
  fixedLevelLabel: ARGON2_PROFILES[DEFAULT_ENCRYPTION_TYPE].label,
  saltLen: 16,
  ivLen: 12,
  checkIvLen: 12,
  wrapIvLen: 12,
  headerFixedLen: 24,
  headerProbeBytes: 4096,
  checkMarker: 'RAVEN_OK_V2',
  mlKemSeedDomain: 'REIVEN_MLKEM_SEED_V1',
  encryptionProfiles: ARGON2_PROFILES,
  argon2FixedProfile: ARGON2_PROFILES[DEFAULT_ENCRYPTION_TYPE],
});
