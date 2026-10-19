// A minimal *software* FIDO2 authenticator for automated tests.
// It produces genuine WebAuthn responses (P-256 / ES256 signatures over real
// authenticator data and clientDataJSON), so the server verifies them with exactly
// the same library code path as a browser passkey. It uses Node's crypto module;
// no cryptographic primitives are implemented here.
import crypto from 'node:crypto';

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest();

// --- tiny CBOR encoder (only what an attestation object / COSE key needs) ---
function cborHead(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 256) return Buffer.from([(major << 5) | 24, n]);
  if (n < 65536) { const b = Buffer.alloc(3); b[0] = (major << 5) | 25; b.writeUInt16BE(n, 1); return b; }
  const b = Buffer.alloc(5); b[0] = (major << 5) | 26; b.writeUInt32BE(n, 1); return b;
}
function cbor(v) {
  if (typeof v === 'number') return v >= 0 ? cborHead(0, v) : cborHead(1, -1 - v);
  if (typeof v === 'string') { const s = Buffer.from(v, 'utf8'); return Buffer.concat([cborHead(3, s.length), s]); }
  if (Buffer.isBuffer(v) || v instanceof Uint8Array) return Buffer.concat([cborHead(2, v.length), Buffer.from(v)]);
  if (v instanceof Map) {
    const parts = [cborHead(5, v.size)];
    for (const [k, val] of v) parts.push(cbor(k), cbor(val));
    return Buffer.concat(parts);
  }
  throw new Error('unsupported CBOR type');
}

export class SoftAuthenticator {
  constructor({ origin, rpId }) {
    this.origin = origin;
    this.rpIdHash = sha256(Buffer.from(rpId));
    this.creds = new Map(); // credId -> { privateKey, userHandle, signCount }
  }

  // navigator.credentials.create() equivalent
  create(options) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' });
    const credId = crypto.randomBytes(32);
    const coseKey = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
    const credIdLen = Buffer.alloc(2); credIdLen.writeUInt16BE(credId.length);
    const authData = Buffer.concat([
      this.rpIdHash,
      Buffer.from([0x45]), // flags: UP | UV | AT
      Buffer.alloc(4), // signCount = 0
      Buffer.alloc(16), // AAGUID (none)
      credIdLen, credId, coseKey,
    ]);
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin: this.origin, crossOrigin: false }));
    const attestationObject = cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]));
    this.creds.set(b64u(credId), { privateKey, userHandle: options.user.id, signCount: 0 });
    return {
      id: b64u(credId), rawId: b64u(credId), type: 'public-key',
      response: { clientDataJSON: b64u(clientDataJSON), attestationObject: b64u(attestationObject), transports: ['internal'] },
      clientExtensionResults: {}, authenticatorAttachment: 'platform',
    };
  }

  // navigator.credentials.get() equivalent
  get(options, { origin } = {}) {
    const allowed = (options.allowCredentials || []).map((c) => c.id);
    const credId = allowed.find((id) => this.creds.has(id));
    if (!credId) throw new Error('no matching credential on this authenticator');
    const c = this.creds.get(credId);
    c.signCount += 1;
    const count = Buffer.alloc(4); count.writeUInt32BE(c.signCount);
    const authData = Buffer.concat([this.rpIdHash, Buffer.from([0x05]) /* UP | UV */, count]);
    const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin: origin || this.origin, crossOrigin: false }));
    const signature = crypto.sign('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), c.privateKey); // DER ECDSA
    return {
      id: credId, rawId: credId, type: 'public-key',
      response: { clientDataJSON: b64u(clientDataJSON), authenticatorData: b64u(authData), signature: b64u(signature), userHandle: c.userHandle },
      clientExtensionResults: {}, authenticatorAttachment: 'platform',
    };
  }
}
