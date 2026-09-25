import { FORMAT_VERSION, HEADER_FIXED_SIZE, CHUNK_SIZE, ENCRYPTION_PROFILES } from '../public/envelope.mjs';

const ARGON2_PROFILES = Object.freeze({
  standard: Object.freeze({
    label: 'Standard',
    ...ENCRYPTION_PROFILES.standard,
  }),
  paranoid: Object.freeze({
    label: 'Paranoid',
    ...ENCRYPTION_PROFILES.paranoid,
  }),
});

const DEFAULT_ENCRYPTION_TYPE = 'standard';

export const ENCRYPTION_CONFIG = Object.freeze({
  magic: 'ESHARE1',
  formatVersion: FORMAT_VERSION,
  defaultPim: 100,
  defaultEncryptionType: DEFAULT_ENCRYPTION_TYPE,
  defaultSecurityLevel: 1,
  fixedLevelLabel: ARGON2_PROFILES[DEFAULT_ENCRYPTION_TYPE].label,
  saltLen: 16,
  ivLen: 12,
  wrapIvLen: 12,
  headerFixedLen: HEADER_FIXED_SIZE,
  headerProbeBytes: 4096,
  chunkPlainSize: CHUNK_SIZE,
  encryptionProfiles: ARGON2_PROFILES,
  argon2FixedProfile: ARGON2_PROFILES[DEFAULT_ENCRYPTION_TYPE],
});
