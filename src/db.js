// Minimal local development datastore: a JSON file on disk.
// Synthetic data only. Fine for a lab; not a production database.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const DB_FILE = process.env.DB_FILE || path.join(__dirname, '..', 'data', 'db.json');

let cache = null;

export function load() {
  if (!cache) {
    if (!fs.existsSync(DB_FILE)) {
      throw new Error(`No datastore at ${DB_FILE}. Run "npm run seed" first.`);
    }
    cache = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  }
  return cache;
}

export function save() {
  fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(cache, null, 2));
  fs.renameSync(tmp, DB_FILE);
}

export function writeFresh(data) {
  cache = data;
  save();
}

// ---- query helpers ----
export const findUser = (id) => load().users.find((u) => u.id === id) || null;
export const findStudent = (id) => load().students.find((s) => s.id === id) || null;
export const findCourse = (id) => load().courses.find((c) => c.id === id) || null;
export const credentialsFor = (userId) => load().credentials.filter((c) => c.userId === userId);
export const findCredential = (credId) => load().credentials.find((c) => c.id === credId) || null;
export const enrollmentsFor = (studentId) => load().enrollments.filter((e) => e.studentId === studentId);
export const findEnrollment = (courseId, studentId) =>
  load().enrollments.find((e) => e.courseId === courseId && e.studentId === studentId) || null;
export const coursesTaughtBy = (lecturerId) =>
  load().courses.filter((c) => c.lecturerIds.includes(lecturerId)).map((c) => c.id);
