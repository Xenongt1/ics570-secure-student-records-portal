// ICS570 Lab 2, Part B: protect one fictional student-data export with AES-256-GCM.
// Uses Node's built-in crypto module (no AES written by hand). Synthetic data only.
// Run: node partB/crypto-demo.js
import crypto from 'node:crypto';

const ALG = 'aes-256-gcm';
const NONCE_BYTES = 12; // 96-bit nonce, the recommended size for GCM

// Random 256-bit key, generated in memory for this run only and never printed or written to disk.
// In a real deployment it would come from a key-management service, not from code or a config file.
const key = crypto.randomBytes(32);

function encrypt(plaintext) {
  const nonce = crypto.randomBytes(NONCE_BYTES); // fresh nonce for every encryption
  const cipher = crypto.createCipheriv(ALG, key, nonce);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return { nonce, ciphertext, tag: cipher.getAuthTag() };
}

function decrypt({ nonce, ciphertext, tag }) {
  const decipher = crypto.createDecipheriv(ALG, key, nonce);
  decipher.setAuthTag(tag);
  // final() throws if the tag does not verify, so altered data is never returned.
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

const hex = (b) => b.toString('hex');
const short = (b) => `${hex(b).slice(0, 32)}… (${b.length} bytes)`;

// Fictional record (same synthetic data style as the portal seed).
const record = JSON.stringify({
  studentId: 'S001',
  name: 'Ama Owusu (fictional)',
  programme: 'BSc Computer Science',
  grades: [{ courseId: 'C101', grade: 'B+' }, { courseId: 'C102', grade: 'A-' }],
});

console.log('ICS570 Part B: AES-256-GCM demo (Node', process.version + ')');
console.log('Key: 32 random bytes, held in memory only (not printed)\n');

// 1. Encrypt and decrypt
console.log('1. Encrypt and decrypt');
console.log('   plaintext :', record);
const box = encrypt(record);
console.log('   nonce     :', hex(box.nonce), `(${box.nonce.length} bytes)`);
console.log('   ciphertext:', short(box.ciphertext));
console.log('   tag       :', hex(box.tag), `(${box.tag.length} bytes)`);
const restored = decrypt(box);
console.log('   decrypted :', restored);
console.log('   decrypted === original:', restored === record, '\n');

// 2. Fresh nonce per encryption
console.log('2. Same record, same key, encrypted twice');
const a = encrypt(record);
const b = encrypt(record);
console.log('   nonce A:', hex(a.nonce));
console.log('   nonce B:', hex(b.nonce));
console.log('   ciphertext A:', short(a.ciphertext));
console.log('   ciphertext B:', short(b.ciphertext));
console.log('   nonces differ:', !a.nonce.equals(b.nonce), '| ciphertexts differ:', !a.ciphertext.equals(b.ciphertext), '\n');

// 3. Integrity: tamper with separate local copies
console.log('3. Tamper detection (each test uses its own modified copy)');
function tryDecrypt(label, copy) {
  try {
    const out = decrypt(copy);
    console.log(`   ${label}: DECRYPTED (unexpected!) ->`, out);
  } catch (err) {
    console.log(`   ${label}: decryption failed -> ${err.message}`);
  }
}
const ctCopy = { ...box, ciphertext: Buffer.from(box.ciphertext) };
ctCopy.ciphertext[5] ^= 0x01; // flip one bit in one ciphertext byte
tryDecrypt('ciphertext byte 5 flipped', ctCopy);
const tagCopy = { ...box, tag: Buffer.from(box.tag) };
tagCopy.tag[0] ^= 0x01; // flip one bit in one tag byte
tryDecrypt('tag byte 0 flipped       ', tagCopy);
console.log('   original still decrypts :', decrypt(box) === record);
