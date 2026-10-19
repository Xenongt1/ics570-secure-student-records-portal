// Authorization policy. Every protected route calls one of these functions
// on the server; nothing here depends on what the UI shows or hides.
// Deny by default: anything not explicitly allowed below is refused.
import { findStudent, findEnrollment, enrollmentsFor, coursesTaughtBy, findCourse } from './db.js';

const allow = () => ({ allowed: true });
const deny = (reason) => ({ allowed: false, reason });

// Who may read GET /api/students/:studentId ?
//  - student: only their own record (ownership check)
//  - lecturer: only students enrolled in a course assigned to them
export function canReadStudent(user, studentId) {
  if (!findStudent(studentId)) return deny('no such student');
  if (user.role === 'student') {
    return user.id === studentId ? allow() : deny('students may read only their own record');
  }
  if (user.role === 'lecturer') {
    const mine = coursesTaughtBy(user.id);
    const shared = enrollmentsFor(studentId).some((e) => mine.includes(e.courseId));
    return shared ? allow() : deny('student is not in any course assigned to this lecturer');
  }
  return deny('role not permitted');
}

// Who may POST /api/courses/:courseId/grades/:studentId ?
//  - only a lecturer assigned to that course, for a student enrolled in it. Never a student.
export function canUpdateGrade(user, courseId, studentId) {
  if (user.role !== 'lecturer') return deny('only lecturers may update grades');
  const course = findCourse(courseId);
  if (!course) return deny('no such course');
  if (!course.lecturerIds.includes(user.id)) return deny('lecturer is not assigned to this course');
  if (!findEnrollment(courseId, studentId)) return deny('student is not enrolled in this course');
  return allow();
}

// Who may GET /api/courses/:courseId/roster ?
export function canReadRoster(user, courseId) {
  if (user.role !== 'lecturer') return deny('only lecturers may view rosters');
  const course = findCourse(courseId);
  if (!course) return deny('no such course');
  return course.lecturerIds.includes(user.id) ? allow() : deny('lecturer is not assigned to this course');
}

// Least privilege on the data returned: a lecturer only sees the grades
// for their own courses, a student sees all of their own.
export function visibleEnrollments(user, studentId) {
  const all = enrollmentsFor(studentId);
  if (user.role === 'student') return all;
  const mine = coursesTaughtBy(user.id);
  return all.filter((e) => mine.includes(e.courseId));
}
