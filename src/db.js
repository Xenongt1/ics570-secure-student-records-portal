// Minimal local development datastore: a JSON file on disk.
// Synthetic data only. Fine for a lab; not a production database.
//
// Hosted demo (Vercel): serverless functions have no persistent disk, so the same
// JSON document is kept in Upstash Redis instead and re-read at the start of each
// API request (see refresh()). Without the KV_* variables nothing here changes.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Redis } from '@upstash/redis';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const DB_FILE = process.env.DB_FILE || path.join(__dirname, '..', 'data', 'db.json');

export const HOSTED = Boolean(process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN);
export const redis = HOSTED ? new Redis({ url: process.env.KV_REST_API_URL, token: process.env.KV_REST_API_TOKEN }) : null;
const REDIS_KEY = 'portal:db';

let cache = null;

export function load() {
  if (!cache) {
    if (HOSTED) throw new Error('Datastore not loaded: refresh() must run before handling the request.');
    if (!fs.existsSync(DB_FILE)) {
      throw new Error(`No datastore at ${DB_FILE}. Run "npm run seed" first.`);
    }
    cache = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  }
  return cache;
}

// Hosted only: pull the latest document from Redis (another instance may have changed it).
export async function refresh() {
  if (HOSTED) cache = await redis.get(REDIS_KEY);
  return cache;
}

// Locally a synchronous file write. Hosted, a Redis write the caller awaits before responding.
export function save() {
  if (HOSTED) return redis.set(REDIS_KEY, cache);
  fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(cache, null, 2));
  fs.renameSync(tmp, DB_FILE);
}

export function writeFresh(data) {
  cache = data;
  return save();
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
