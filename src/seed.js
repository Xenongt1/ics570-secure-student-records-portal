// Seeds the datastore with SYNTHETIC accounts, a course, a lecturer-course
// assignment and fictional grades. Each account gets a one-time enrollment code
// (only its SHA-256 hash is stored) which is needed to register the first passkey.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { writeFresh, DB_FILE, HOSTED } from './db.js';

// Plain-text codes for whoever runs the lab, next to the datastore (data/ is gitignored).
// Named after the datastore so the test run (test-db.json) never overwrites the real codes.
export const CODES_FILE = path.join(path.dirname(DB_FILE), `${path.basename(DB_FILE, '.json')}-enrollment-codes.txt`);

export const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const newCode = () => crypto.randomBytes(5).toString('hex').toUpperCase(); // e.g. 9F3A1C07B2
const webauthnUserId = () => crypto.randomBytes(16).toString('base64url'); // opaque, not the student ID

export function seed() {
  const accounts = [
    { id: 'S001', role: 'student', displayName: 'Ama Owusu (fictional)' },
    { id: 'S002', role: 'student', displayName: 'Kwame Asante (fictional)' },
    { id: 'S003', role: 'student', displayName: 'Efua Mensah (fictional)' },
    { id: 'L001', role: 'lecturer', displayName: 'Dr. Yaw Boateng (fictional)' },
    { id: 'L002', role: 'lecturer', displayName: 'Dr. Akosua Darko (fictional)' },
  ];

  const codes = {};
  const users = accounts.map((a) => {
    const code = newCode();
    codes[a.id] = code;
    return {
      ...a,
      webauthnUserId: webauthnUserId(),
      enrollmentCodeHash: sha256(code),
      enrollmentUsed: false,
    };
  });

  const data = {
    users,
    credentials: [],
    students: [
      { id: 'S001', name: 'Ama Owusu', programme: 'BSc Computer Science', year: 3, email: 's001@example.edu' },
      { id: 'S002', name: 'Kwame Asante', programme: 'BSc Management Information Systems', year: 3, email: 's002@example.edu' },
      { id: 'S003', name: 'Efua Mensah', programme: 'BSc Computer Engineering', year: 2, email: 's003@example.edu' },
    ],
    courses: [
      { id: 'C101', title: 'Introduction to Secure Systems', lecturerIds: ['L001'] },
      { id: 'C102', title: 'Data Structures', lecturerIds: ['L002'] },
    ],
    enrollments: [
      { studentId: 'S001', courseId: 'C101', grade: 'B+' },
      { studentId: 'S001', courseId: 'C102', grade: 'A-' },
      { studentId: 'S002', courseId: 'C101', grade: 'B' },
      { studentId: 'S003', courseId: 'C102', grade: 'A' },
    ],
    gradeAudit: [],
  };

  if (HOSTED) {
    // Hosted demo: no disk for the codes file, so the plain codes travel with the
    // document for the Register page; the caller awaits the Redis write.
    data.demoCodes = codes;
    return writeFresh(data).then(() => codes);
  }
  writeFresh(data);
  fs.writeFileSync(CODES_FILE, Object.entries(codes).map(([id, code]) => `${id} ${code}`).join('\n') + '\n');
  return codes;
}

// Run directly: `npm run seed` (first time) or `npm run seed -- --reset` (wipe and start over).
// An existing datastore is kept by default so registered passkeys survive.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (fs.existsSync(DB_FILE) && !process.argv.includes('--reset')) {
    console.log(`Datastore already exists at ${DB_FILE}; keeping it, so registered passkeys still work.`);
    console.log('To wipe everything (all passkeys) and print new enrollment codes, run: npm run seed -- --reset');
    process.exit(0);
  }
  const codes = seed();
  console.log(`Seeded synthetic data into ${DB_FILE}`);
  console.log('One-time enrollment codes (synthetic, lab use only):');
  for (const [id, code] of Object.entries(codes)) console.log(`  ${id}  ${code}`);
  console.log(`Also saved to ${CODES_FILE}; "npm start" lists the codes not yet used.`);
  console.log('Each code works once, to register that account\'s first passkey. Run "npm run seed -- --reset" to wipe everything and start over.');
}
