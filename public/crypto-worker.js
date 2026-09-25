importScripts('/vendor/argon2-bundled.min.js');

const sessions = new Map();
let codec;
let initError;
const argon = async (password, salt, params) => {
  const result = await self.argon2.hash({
    pass: password, salt, hashLen: 32, time: params.time, mem: params.mem,
    parallelism: params.parallelism, type: self.argon2.ArgonType.Argon2id,
  });
  return new Uint8Array(result.hash);
};
const initialization = (async () => {
  try {
    const [{ createCodec }, { ml_kem768 }] = await Promise.all([import('/envelope.mjs'), import('/vendor/ml-kem.js')]);
    codec = createCodec({ crypto: self.crypto, argon2id: argon, mlKem: ml_kem768 });
  } catch (error) { initError = error.message; }
  self.postMessage({ type: 'ready', ok: !initError, error: initError || null, pqc: 'ML-KEM-768' });
})();

const publicSession = (session, sessionId) => ({
  sessionId, headerBuffer: session.header.slice().buffer, headerSize: session.headerSize,
  chunkPlainSize: session.chunkPlainSize, chunkCount: session.chunkCount, plainSize: session.plainSize,
  encryptedSize: session.encryptedSize, originalName: session.originalName, argonParams: session.argonParams,
});

let handling = false;
self.onmessage = async ({ data }) => {
  const { id, type, payload = {} } = data || {};
  if (typeof id === 'undefined' || !type) return;
  await initialization;
  if (initError || handling) {
    self.postMessage({ id, ok: false, error: initError || 'Crypto worker is busy.' });
    return;
  }
  handling = true;
  try {
    self.postMessage({ type: 'progress', id, stage: type, message: type.startsWith('encrypt') ? 'Encrypting and authenticating file' : 'Verifying encrypted file' });
    let result;
    if (type === 'calibrate') {
      const params = { time: 2, mem: 32768, parallelism: 1 };
      const started = performance.now();
      const key = await argon('calibrate', self.crypto.getRandomValues(new Uint8Array(16)), params);
      key.fill(0);
      result = { params, measuredMs: Math.max(1, Math.round(performance.now() - started)) };
    } else if (type === 'encrypt') {
      const encrypted = await codec.encrypt(new Uint8Array(payload.fileBuffer), payload);
      result = { envelopeBuffer: encrypted.envelopeBytes.buffer, argonParams: encrypted.argonParams };
    } else if (type === 'decrypt') {
      const decrypted = await codec.decrypt(new Uint8Array(payload.encryptedBuffer), payload.password, payload.pim);
      result = { plaintextBuffer: decrypted.plaintext.buffer, originalName: decrypted.originalName, argonParams: decrypted.argonParams };
    } else if (type === 'encrypt-init' || type === 'decrypt-init' || type === 'verify-header') {
      if (sessions.size >= 4) throw new Error('Too many crypto sessions. Reload this page.');
      const session = type === 'encrypt-init'
        ? await codec.createEncryption(payload)
        : await codec.createDecryption(new Uint8Array(payload.headerBuffer), payload.password, payload.pim);
      const sessionId = self.crypto.randomUUID();
      result = publicSession(session, sessionId);
      if (type === 'verify-header') codec.destroy(session);
      else sessions.set(sessionId, { session, mode: type === 'encrypt-init' ? 'encrypt' : 'decrypt' });
    } else {
      const entry = sessions.get(payload.sessionId);
      if (!entry) throw new Error('Crypto session not found.');
      if (type === 'abort') {
        codec.destroy(entry.session);
        sessions.delete(payload.sessionId);
        result = {};
      } else if (type === `${entry.mode}-finish`) {
        sessions.delete(payload.sessionId);
        codec.finish(entry.session);
        result = {};
      } else if (type === `${entry.mode}-chunk`) {
        try {
          const bytes = await codec[`${entry.mode}Chunk`](entry.session, payload.chunkIndex, new Uint8Array(payload.chunkBuffer));
          result = { chunkBuffer: bytes.buffer };
        } catch (error) {
          codec.destroy(entry.session);
          sessions.delete(payload.sessionId);
          throw error;
        }
      } else throw new Error('Unsupported crypto action.');
    }
    self.postMessage({ id, ok: true, result }, Object.values(result).filter(value => value instanceof ArrayBuffer));
  } catch (error) {
    self.postMessage({ id, ok: false, error: error.message || 'Cryptography failed.' });
  } finally { handling = false; }
};
