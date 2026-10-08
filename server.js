require('dotenv').config();
const express = require('express'), mysql = require('mysql2/promise'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), path = require('path');
const ExcelJS = require('exceljs'), PDFDocument = require('pdfkit');

const SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
if (!process.env.JWT_SECRET) console.warn('WARNING: JWT_SECRET is not set; using an insecure default.');
const TYPES = ['mcq', 'tf', 'identification', 'short', 'multi_select', 'essay', 'matching', 'ordering'];
const { cfg, hint } = require('./db');
const pool = mysql.createPool({ ...cfg, connectionLimit: 10, waitForConnections: true, connectTimeout: 10000, dateStrings: true });
const q = async (s, p = []) => (await pool.query(s, p))[0];
const one = async (s, p = []) => (await q(s, p))[0];
const http = (s, m) => Object.assign(new Error(m), { status: s });
const a = fn => (req, res, next) => Promise.resolve(fn(req, res)).catch(next);
const sign = id => jwt.sign({ id }, SECRET, { expiresIn: '12h' });
const log = (uid, action, details, req, attempt) => q('INSERT INTO activity_logs(user_id,attempt_id,action,details,ip) VALUES(?,?,?,?,?)', [uid || null, attempt || null, action, details == null ? null : String(details), req && req.ip || null]).catch(() => { });
const notify = (uid, type, title, msg) => q('INSERT INTO notifications(user_id,type,title,message) VALUES(?,?,?,?)', [uid, type, title, msg]);
const shuffle = arr => { const r = [...arr]; for (let i = r.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [r[i], r[j]] = [r[j], r[i]]; } return r; };
const nz = v => (v === '' || v === undefined ? null : v);

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const auth = (...roles) => async (req, res, next) => {
  try {
    const p = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET);
    const u = await one('SELECT u.id,u.name,u.email,u.active,r.name role FROM users u JOIN roles r ON r.id=u.role_id WHERE u.id=?', [p.id]);
    if (!u || !u.active) return res.status(401).json({ error: 'Unauthorized' });
    if (roles.length && !roles.includes(u.role)) return res.status(403).json({ error: 'Forbidden' });
    req.user = u; next();
  } catch (e) { res.status(401).json({ error: 'Unauthorized' }); }
};
const ANY = auth(), S = auth('student'), T = auth('teacher', 'admin'), ADM = auth('admin');

/* ---------- 1. Auth & profile ---------- */
app.post('/api/register', a(async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || password.length < 6) throw http(400, 'Name, email and a password of 6+ characters are required');
  const r = role === 'teacher' && process.env.ALLOW_TEACHER_SIGNUP !== 'false' ? 'teacher' : 'student';
  if (await one('SELECT id FROM users WHERE email=?', [email])) throw http(409, 'Email already registered');
  const rr = await one('SELECT id FROM roles WHERE name=?', [r]);
  const id = (await q('INSERT INTO users(role_id,name,email,password_hash) VALUES(?,?,?,?)', [rr.id, name, email, await bcrypt.hash(password, 10)])).insertId;
  if (r === 'student') await q('INSERT INTO students(user_id,student_no) VALUES(?,?)', [id, nz(req.body.student_no)]);
  else await q('INSERT INTO teachers(user_id,department) VALUES(?,?)', [id, nz(req.body.department)]);
  await log(id, 'register', r, req); res.json({ token: sign(id) });
}));
const tries = new Map();
app.post('/api/login', a(async (req, res) => {
  const k = req.ip + '|' + String(req.body.email || '').toLowerCase(), t = tries.get(k) || { n: 0, at: Date.now() };
  if (Date.now() - t.at > 15 * 60000) { t.n = 0; t.at = Date.now(); }
  if (t.n >= 10) throw http(429, 'Too many login attempts. Try again in 15 minutes.');
  tries.set(k, t);
  const u = await one('SELECT id,password_hash,active FROM users WHERE email=?', [req.body.email || '']);
  if (!u || !(await bcrypt.compare(req.body.password || '', u.password_hash))) { t.n++; await log(null, 'login_failed', req.body.email, req); throw http(401, 'Invalid email or password'); }
  if (!u.active) throw http(403, 'Account disabled');
  tries.delete(k); await log(u.id, 'login', null, req); res.json({ token: sign(u.id) });
}));
app.post('/api/logout', ANY, a(async (req, res) => { await log(req.user.id, 'logout', null, req); res.json({ ok: true }); }));
app.get('/api/me', ANY, a(async (req, res) => {
  const p = await one('SELECT s.student_no,t.department FROM users u LEFT JOIN students s ON s.user_id=u.id LEFT JOIN teachers t ON t.user_id=u.id WHERE u.id=?', [req.user.id]);
  res.json({ ...req.user, ...p });
}));
app.put('/api/me', ANY, a(async (req, res) => {
  const { name, password, current_password, student_no, department } = req.body;
  if (name) await q('UPDATE users SET name=? WHERE id=?', [name, req.user.id]);
  if (password) {
    const u = await one('SELECT password_hash FROM users WHERE id=?', [req.user.id]);
    if (!(await bcrypt.compare(current_password || '', u.password_hash))) throw http(400, 'Current password is incorrect');
    if (password.length < 6) throw http(400, 'Password too short');
    await q('UPDATE users SET password_hash=? WHERE id=?', [await bcrypt.hash(password, 10), req.user.id]);
  }
  if (req.user.role === 'student' && student_no !== undefined) await q('UPDATE students SET student_no=? WHERE user_id=?', [nz(student_no), req.user.id]);
  if (req.user.role === 'teacher' && department !== undefined) await q('UPDATE teachers SET department=? WHERE user_id=?', [nz(department), req.user.id]);
  await log(req.user.id, 'profile_update', null, req); res.json({ ok: true });
}));

/* ---------- Subjects & users lookup ---------- */
app.get('/api/subjects', ANY, a(async (req, res) => res.json(await q('SELECT * FROM subjects ORDER BY name'))));
app.post('/api/subjects', ADM, a(async (req, res) => { await q('INSERT INTO subjects(name) VALUES(?)', [req.body.name]); await log(req.user.id, 'subject_create', req.body.name, req); res.json({ ok: true }); }));
app.put('/api/subjects/:id', ADM, a(async (req, res) => { await q('UPDATE subjects SET name=? WHERE id=?', [req.body.name, req.params.id]); res.json({ ok: true }); }));
app.delete('/api/subjects/:id', ADM, a(async (req, res) => { await q('DELETE FROM subjects WHERE id=?', [req.params.id]); res.json({ ok: true }); }));
app.get('/api/users', T, a(async (req, res) => res.json(await q('SELECT u.id,u.name,u.email FROM users u JOIN roles r ON r.id=u.role_id WHERE r.name=? AND u.active=1 ORDER BY u.name', [req.user.role === 'admin' ? (req.query.role || 'student') : 'student']))));

/* ---------- 2. Quizzes ---------- */
async function ownQuiz(req) {
  const z = await one('SELECT * FROM quizzes WHERE id=?', [req.params.id]);
  if (!z) throw http(404, 'Quiz not found');
  if (req.user.role !== 'admin' && z.teacher_id !== req.user.id) throw http(403, 'Not your quiz');
  return z;
}
const quizFields = b => [nz(b.subject_id), b.title, nz(b.description), nz(b.topic), +b.time_limit_min || 0, +b.passing_score || 0, nz(b.start_at), nz(b.deadline), +b.max_attempts || 0, b.shuffle_questions ? 1 : 0, b.shuffle_choices ? 1 : 0];
app.get('/api/quizzes', T, a(async (req, res) => {
  const adm = req.user.role === 'admin';
  res.json(await q(`SELECT z.*,s.name subject,u.name teacher,(SELECT COUNT(*) FROM quiz_questions WHERE quiz_id=z.id) questions,(SELECT COUNT(*) FROM attempts WHERE quiz_id=z.id AND status<>'in_progress') attempts
    FROM quizzes z LEFT JOIN subjects s ON s.id=z.subject_id JOIN users u ON u.id=z.teacher_id ${adm ? '' : 'WHERE z.teacher_id=?'} ORDER BY z.id DESC`, adm ? [] : [req.user.id]));
}));
app.get('/api/quizzes/:id', T, a(async (req, res) => res.json(await ownQuiz(req))));
app.post('/api/quizzes', T, a(async (req, res) => {
  if (!req.body.title) throw http(400, 'Title required');
  const id = (await q('INSERT INTO quizzes(subject_id,title,description,topic,time_limit_min,passing_score,start_at,deadline,max_attempts,shuffle_questions,shuffle_choices,teacher_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)', [...quizFields(req.body), req.user.id])).insertId;
  await log(req.user.id, 'quiz_create', id, req); res.json({ id });
}));
app.put('/api/quizzes/:id', T, a(async (req, res) => {
  await ownQuiz(req);
  await q('UPDATE quizzes SET subject_id=?,title=?,description=?,topic=?,time_limit_min=?,passing_score=?,start_at=?,deadline=?,max_attempts=?,shuffle_questions=?,shuffle_choices=? WHERE id=?', [...quizFields(req.body), req.params.id]);
  res.json({ ok: true });
}));
app.delete('/api/quizzes/:id', T, a(async (req, res) => { await ownQuiz(req); await q('DELETE FROM quizzes WHERE id=?', [req.params.id]); await log(req.user.id, 'quiz_delete', req.params.id, req); res.json({ ok: true }); }));
async function assignedStudents(quizId) {
  return (await q(`SELECT DISTINCT u.id FROM users u JOIN students s ON s.user_id=u.id WHERE u.active=1 AND
    (u.id IN (SELECT student_id FROM assignments WHERE quiz_id=? AND student_id IS NOT NULL) OR u.id IN (SELECT cs.student_id FROM class_students cs JOIN assignments x ON x.class_id=cs.class_id WHERE x.quiz_id=?))`, [quizId, quizId])).map(r => r.id);
}
app.post('/api/quizzes/:id/publish', T, a(async (req, res) => {
  const z = await ownQuiz(req), pub = req.body.published ? 1 : 0;
  if (pub && !(await one('SELECT 1 x FROM quiz_questions WHERE quiz_id=?', [z.id]))) throw http(400, 'Add questions before publishing');
  await q('UPDATE quizzes SET published=? WHERE id=?', [pub, z.id]);
  if (pub && !z.published) for (const sid of await assignedStudents(z.id)) await notify(sid, 'new_quiz', 'New quiz available', `"${z.title}" is now available.`);
  res.json({ ok: true });
}));
app.post('/api/quizzes/:id/release', T, a(async (req, res) => {
  const z = await ownQuiz(req), r = req.body.released ? 1 : 0;
  await q('UPDATE quizzes SET results_released=? WHERE id=?', [r, z.id]);
  if (r && !z.results_released) for (const g of await q("SELECT DISTINCT student_id FROM attempts WHERE quiz_id=? AND status='graded'", [z.id])) await notify(g.student_id, 'result', 'Result released', `Your result for "${z.title}" is available.`);
  res.json({ ok: true });
}));
app.get('/api/quizzes/:id/questions', T, a(async (req, res) => { await ownQuiz(req); res.json(await q('SELECT q.id,q.text,q.type,q.points,q.difficulty FROM quiz_questions qq JOIN questions q ON q.id=qq.question_id WHERE qq.quiz_id=? ORDER BY qq.position', [req.params.id])); }));
app.put('/api/quizzes/:id/questions', T, a(async (req, res) => {
  await ownQuiz(req);
  if ((await one('SELECT COUNT(*) n FROM attempts WHERE quiz_id=?', [req.params.id])).n) throw http(409, 'This quiz already has attempts; its questions can no longer be changed. Duplicate the quiz instead.');
  await q('DELETE FROM quiz_questions WHERE quiz_id=?', [req.params.id]);
  for (const [i, qid] of (req.body.question_ids || []).entries()) await q('INSERT INTO quiz_questions(quiz_id,question_id,position) VALUES(?,?,?)', [req.params.id, qid, i]);
  res.json({ ok: true });
}));
app.get('/api/quizzes/:id/assignments', T, a(async (req, res) => { await ownQuiz(req); res.json(await q('SELECT a.id,c.name class_name,c.section,u.name student_name FROM assignments a LEFT JOIN classes c ON c.id=a.class_id LEFT JOIN users u ON u.id=a.student_id WHERE a.quiz_id=?', [req.params.id])); }));
app.post('/api/quizzes/:id/assign', T, a(async (req, res) => {
  const z = await ownQuiz(req), { class_id, student_id } = req.body;
  if (!class_id && !student_id) throw http(400, 'Choose a class or a student');
  await q('INSERT INTO assignments(quiz_id,class_id,student_id) VALUES(?,?,?)', [z.id, nz(class_id), nz(student_id)]);
  if (z.published) {
    const ids = student_id ? [+student_id] : (await q('SELECT student_id FROM class_students WHERE class_id=?', [class_id])).map(r => r.student_id);
    for (const sid of ids) await notify(sid, 'new_quiz', 'New quiz assigned', `"${z.title}" was assigned to you.`);
  }
  res.json({ ok: true });
}));
app.delete('/api/assignments/:id', T, a(async (req, res) => { await q('DELETE FROM assignments WHERE id=?', [req.params.id]); res.json({ ok: true }); }));

/* ---------- 3/4. Question bank ---------- */
async function saveQuestion(req, id) {
  const b = req.body;
  if (!TYPES.includes(b.type) || !b.text) throw http(400, 'Type and question text are required');
  const ch = b.choices || [];
  if (['mcq', 'tf', 'multi_select'].includes(b.type) && !ch.some(c => c.is_correct)) throw http(400, 'Mark at least one correct choice');
  if (['identification', 'short', 'matching', 'ordering'].includes(b.type) && !ch.length) throw http(400, 'This question type needs answers/items');
  const f = [nz(b.subject_id), nz(b.category), nz(b.topic), b.type, b.difficulty || 'medium', b.text, +b.points || 1, nz(b.explanation)];
  if (id) { await q('UPDATE questions SET subject_id=?,category=?,topic=?,type=?,difficulty=?,text=?,points=?,explanation=? WHERE id=?', [...f, id]); await q('DELETE FROM choices WHERE question_id=?', [id]); }
  else id = (await q('INSERT INTO questions(subject_id,category,topic,type,difficulty,text,points,explanation,owner_id) VALUES(?,?,?,?,?,?,?,?,?)', [...f, req.user.id])).insertId;
  for (const [i, c] of ch.entries()) await q('INSERT INTO choices(question_id,text,is_correct,position,match_text) VALUES(?,?,?,?,?)', [id, c.text, c.is_correct ? 1 : 0, i, nz(c.match_text)]);
  return id;
}
app.get('/api/questions', T, a(async (req, res) => {
  const w = [], p = [], f = req.query;
  if (f.search) { w.push('(q.text LIKE ? OR q.topic LIKE ?)'); p.push(`%${f.search}%`, `%${f.search}%`); }
  for (const k of ['type', 'difficulty', 'subject_id', 'category', 'topic']) if (f[k]) { w.push(`q.${k}=?`); p.push(f[k]); }
  const rows = await q(`SELECT q.*,s.name subject FROM questions q LEFT JOIN subjects s ON s.id=q.subject_id ${w.length ? 'WHERE ' + w.join(' AND ') : ''} ORDER BY q.id DESC LIMIT 500`, p);
  if (f.with_choices && rows.length) {
    const chs = await q('SELECT * FROM choices WHERE question_id IN (?) ORDER BY position', [rows.map(r => r.id)]);
    rows.forEach(r => r.choices = chs.filter(c => c.question_id === r.id));
  }
  res.json(rows);
}));
app.post('/api/questions', T, a(async (req, res) => res.json({ id: await saveQuestion(req) })));
app.put('/api/questions/:id', T, a(async (req, res) => {
  const o = await one('SELECT owner_id FROM questions WHERE id=?', [req.params.id]);
  if (!o) throw http(404, 'Not found'); if (req.user.role !== 'admin' && o.owner_id !== req.user.id) throw http(403, 'Not your question');
  await saveQuestion(req, +req.params.id); res.json({ ok: true });
}));
app.delete('/api/questions/:id', T, a(async (req, res) => {
  const o = await one('SELECT owner_id FROM questions WHERE id=?', [req.params.id]);
  if (!o) throw http(404, 'Not found'); if (req.user.role !== 'admin' && o.owner_id !== req.user.id) throw http(403, 'Not your question');
  await q('DELETE FROM questions WHERE id=?', [req.params.id]); res.json({ ok: true });
}));

/* ---------- 9. Classes ---------- */
async function ownClass(req) {
  const c = await one('SELECT * FROM classes WHERE id=?', [req.params.id]);
  if (!c) throw http(404, 'Class not found');
  if (req.user.role !== 'admin' && c.teacher_id !== req.user.id) throw http(403, 'Not your class');
  return c;
}
app.get('/api/classes', ANY, a(async (req, res) => {
  const u = req.user, base = 'SELECT c.*,s.name subject,t.name teacher,(SELECT COUNT(*) FROM class_students WHERE class_id=c.id) students FROM classes c LEFT JOIN subjects s ON s.id=c.subject_id LEFT JOIN users t ON t.id=c.teacher_id';
  if (u.role === 'admin') return res.json(await q(base));
  if (u.role === 'teacher') return res.json(await q(base + ' WHERE c.teacher_id=?', [u.id]));
  res.json(await q(base + ' WHERE c.id IN (SELECT class_id FROM class_students WHERE student_id=?)', [u.id]));
}));
app.post('/api/classes', T, a(async (req, res) => {
  const b = req.body, tid = req.user.role === 'admin' ? nz(b.teacher_id) : req.user.id;
  res.json({ id: (await q('INSERT INTO classes(name,section,subject_id,teacher_id) VALUES(?,?,?,?)', [b.name, nz(b.section), nz(b.subject_id), tid])).insertId });
}));
app.put('/api/classes/:id', T, a(async (req, res) => {
  const c = await ownClass(req), b = req.body, tid = req.user.role === 'admin' ? nz(b.teacher_id) : c.teacher_id;
  await q('UPDATE classes SET name=?,section=?,subject_id=?,teacher_id=? WHERE id=?', [b.name, nz(b.section), nz(b.subject_id), tid, c.id]); res.json({ ok: true });
}));
app.delete('/api/classes/:id', T, a(async (req, res) => { await ownClass(req); await q('DELETE FROM classes WHERE id=?', [req.params.id]); res.json({ ok: true }); }));
app.get('/api/classes/:id/students', T, a(async (req, res) => { await ownClass(req); res.json(await q('SELECT u.id,u.name,u.email,s.student_no FROM class_students cs JOIN users u ON u.id=cs.student_id LEFT JOIN students s ON s.user_id=u.id WHERE cs.class_id=?', [req.params.id])); }));
app.post('/api/classes/:id/students', T, a(async (req, res) => {
  await ownClass(req); const missing = [];
  for (const e of req.body.emails || []) {
    const u = await one("SELECT u.id FROM users u JOIN roles r ON r.id=u.role_id WHERE u.email=? AND r.name='student'", [e.trim()]);
    if (u) await q('INSERT IGNORE INTO class_students(class_id,student_id) VALUES(?,?)', [req.params.id, u.id]); else missing.push(e);
  }
  for (const sid of req.body.student_ids || []) await q('INSERT IGNORE INTO class_students(class_id,student_id) VALUES(?,?)', [req.params.id, sid]);
  res.json({ ok: true, not_found: missing });
}));
app.delete('/api/classes/:id/students/:sid', T, a(async (req, res) => { await ownClass(req); await q('DELETE FROM class_students WHERE class_id=? AND student_id=?', [req.params.id, req.params.sid]); res.json({ ok: true }); }));

/* ---------- 6. Grading ---------- */
const norm = s => String(s == null ? '' : s).trim().toLowerCase().replace(/\s+/g, ' ');
function check(qu, ans) {
  const ch = qu.choices;
  if (ans == null) return false;
  switch (qu.type) {
    case 'mcq': case 'tf': { const c = ch.find(c => c.id == ans); return !!(c && c.is_correct); }
    case 'multi_select': { if (!Array.isArray(ans)) return false; const w = ch.filter(c => c.is_correct).map(c => c.id).sort((x, y) => x - y), g = ans.map(Number).sort((x, y) => x - y); return w.length === g.length && w.every((v, i) => v === g[i]); }
    case 'identification': case 'short': return ch.some(c => norm(c.text) === norm(ans));
    case 'matching': return typeof ans === 'object' && ch.every(c => norm(ans[c.id]) === norm(c.match_text));
    case 'ordering': { if (!Array.isArray(ans)) return false; const w = [...ch].sort((x, y) => x.position - y.position).map(c => c.id); return w.length === ans.length && w.every((v, i) => v === +ans[i]); }
  }
  return false;
}
async function gradeAttempt(id) {
  const at = await one('SELECT a.*,z.passing_score,z.title,z.results_released FROM attempts a JOIN quizzes z ON z.id=a.quiz_id WHERE a.id=?', [id]);
  const qs = await q('SELECT q.id,q.type,q.points FROM quiz_questions qq JOIN questions q ON q.id=qq.question_id WHERE qq.quiz_id=?', [at.quiz_id]);
  const chs = await q('SELECT * FROM choices WHERE question_id IN (SELECT question_id FROM quiz_questions WHERE quiz_id=?)', [at.quiz_id]);
  const ans = await q('SELECT * FROM answers WHERE attempt_id=?', [id]);
  let score = 0, total = 0, pending = false;
  for (const qu of qs) {
    total += +qu.points; qu.choices = chs.filter(c => c.question_id === qu.id);
    const an = ans.find(x => x.question_id === qu.id);
    if (an && an.graded_manual) { score += +an.points; continue; }
    if (qu.type === 'essay') { if (an && norm(an.answer)) pending = true; continue; }
    if (an) { const ok = check(qu, an.answer); const pts = ok ? +qu.points : 0; score += pts; await q('UPDATE answers SET is_correct=?,points=? WHERE id=?', [ok ? 1 : 0, pts, an.id]); }
  }
  const pct = total ? Math.round(score / total * 10000) / 100 : 0, passed = pct >= +at.passing_score ? 1 : 0, status = pending ? 'submitted' : 'graded';
  await q('UPDATE attempts SET score=?,total_points=?,percentage=?,passed=?,status=? WHERE id=?', [score, total, pct, passed, status, id]);
  if (status === 'graded') {
    await q('INSERT INTO grades(attempt_id,quiz_id,student_id,score,total_points,percentage,passed) VALUES(?,?,?,?,?,?,?) ON DUPLICATE KEY UPDATE score=VALUES(score),total_points=VALUES(total_points),percentage=VALUES(percentage),passed=VALUES(passed),graded_at=NOW()', [id, at.quiz_id, at.student_id, score, total, pct, passed]);
    if (at.status !== 'graded' && at.results_released) await notify(at.student_id, 'result', 'Result released', `Your result for "${at.title}" is ready: ${pct}% (${passed ? 'Passed' : 'Failed'}).`);
  }
}
async function finish(id) { const r = await q("UPDATE attempts SET submitted_at=NOW(),status='submitted' WHERE id=? AND status='in_progress'", [id]); if (r.affectedRows) await gradeAttempt(id); }
async function sweep() { for (const r of await q("SELECT a.id FROM attempts a JOIN quizzes z ON z.id=a.quiz_id WHERE a.status='in_progress' AND z.time_limit_min>0 AND NOW()>DATE_ADD(a.started_at,INTERVAL z.time_limit_min*60+10 SECOND)")) await finish(r.id); }

/* ---------- 5. Quiz taking ---------- */
const eligible = async (quizId, sid) => !!(await one('SELECT 1 x FROM assignments WHERE quiz_id=? AND (student_id=? OR class_id IN (SELECT class_id FROM class_students WHERE student_id=?)) LIMIT 1', [quizId, sid, sid]));
app.post('/api/quizzes/:id/start', S, a(async (req, res) => {
  await sweep();
  const z = await one('SELECT *,NOW()<start_at early,NOW()>deadline late FROM quizzes WHERE id=? AND published=1', [req.params.id]);
  if (!z || !(await eligible(z.id, req.user.id))) throw http(404, 'Quiz not available');
  const open = await one("SELECT id FROM attempts WHERE quiz_id=? AND student_id=? AND status='in_progress'", [z.id, req.user.id]);
  if (open) return res.json({ attempt_id: open.id });
  if (z.early) throw http(400, 'This quiz has not started yet'); if (z.late) throw http(400, 'The deadline has passed');
  const used = (await one('SELECT COUNT(*) n FROM attempts WHERE quiz_id=? AND student_id=?', [z.id, req.user.id])).n;
  if (z.max_attempts > 0 && used >= z.max_attempts) throw http(400, 'No attempts left');
  let qs = await q('SELECT q.id,q.type FROM quiz_questions qq JOIN questions q ON q.id=qq.question_id WHERE qq.quiz_id=? ORDER BY qq.position', [z.id]);
  if (!qs.length) throw http(400, 'Quiz has no questions');
  if (z.shuffle_questions) qs = shuffle(qs);
  const layout = { qids: qs.map(x => x.id), choices: {} };
  for (const qu of qs) {
    const ids = (await q('SELECT id FROM choices WHERE question_id=? ORDER BY position', [qu.id])).map(c => c.id);
    layout.choices[qu.id] = (z.shuffle_choices || qu.type === 'ordering') ? shuffle(ids) : ids;
  }
  const id = (await q('INSERT INTO attempts(quiz_id,student_id,started_at,layout) VALUES(?,?,NOW(),?)', [z.id, req.user.id, JSON.stringify(layout)])).insertId;
  await log(req.user.id, 'quiz_start', z.id, req, id); res.json({ attempt_id: id });
}));
async function myAttempt(req) {
  const at = await one('SELECT a.*,z.title,z.time_limit_min,z.results_released,IF(z.time_limit_min>0,TIMESTAMPDIFF(SECOND,NOW(),DATE_ADD(a.started_at,INTERVAL z.time_limit_min MINUTE)),NULL) remaining FROM attempts a JOIN quizzes z ON z.id=a.quiz_id WHERE a.id=? AND a.student_id=?', [req.params.id, req.user.id]);
  if (!at) throw http(404, 'Attempt not found');
  if (at.status === 'in_progress' && at.remaining !== null && at.remaining <= -10) { await finish(at.id); at.status = 'submitted'; }
  return at;
}
app.get('/api/attempts/:id', S, a(async (req, res) => {
  const at = await myAttempt(req);
  if (at.status !== 'in_progress') return res.json({ status: at.status });
  const qs = await q('SELECT id,type,text,points FROM questions WHERE id IN (?)', [at.layout.qids]);
  const chs = await q('SELECT id,question_id,text,match_text FROM choices WHERE question_id IN (?)', [at.layout.qids]);
  const questions = at.layout.qids.map(qid => {
    const qu = qs.find(x => x.id === qid), cs = at.layout.choices[qid].map(cid => chs.find(c => c.id === cid));
    const o = { id: qu.id, type: qu.type, text: qu.text, points: qu.points, choices: cs.map(c => ({ id: c.id, text: c.text })) };
    if (qu.type === 'matching') o.options = [...new Set(cs.map(c => c.match_text))].sort();
    return o;
  });
  const saved = {}; (await q('SELECT question_id,answer FROM answers WHERE attempt_id=?', [at.id])).forEach(r => saved[r.question_id] = r.answer);
  res.json({ status: 'in_progress', title: at.title, remaining: at.remaining, questions, answers: saved });
}));
async function saveAnswers(at, map) {
  for (const [qid, ans] of Object.entries(map || {})) {
    if (!at.layout.qids.includes(+qid)) continue;
    await q('INSERT INTO answers(attempt_id,question_id,answer) VALUES(?,?,?) ON DUPLICATE KEY UPDATE answer=VALUES(answer)', [at.id, qid, JSON.stringify(ans)]);
  }
}
app.put('/api/attempts/:id/answer', S, a(async (req, res) => {
  const at = await myAttempt(req);
  if (at.status !== 'in_progress') throw http(410, 'Attempt already submitted');
  await saveAnswers(at, { [req.body.question_id]: req.body.answer }); res.json({ ok: true });
}));
app.post('/api/attempts/:id/submit', S, a(async (req, res) => {
  const at = await myAttempt(req);
  if (at.status === 'in_progress') { if (at.remaining === null || at.remaining > -10) await saveAnswers(at, req.body.answers); await finish(at.id); await log(req.user.id, 'quiz_submit', at.quiz_id, req, at.id); }
  res.json({ ok: true });
}));
app.post('/api/attempts/:id/event', S, a(async (req, res) => {
  const at = await myAttempt(req);
  const type = String(req.body.type || 'unknown').slice(0, 30);
  if (type === 'tab_switch') await q('UPDATE attempts SET tab_switches=tab_switches+1 WHERE id=?', [at.id]);
  await log(req.user.id, 'cheat:' + type, req.body.detail, req, at.id); res.json({ ok: true });
}));

/* ---------- 7. Student dashboard ---------- */
app.get('/api/student/dashboard', S, a(async (req, res) => {
  await sweep(); const id = req.user.id;
  const rows = await q(`SELECT z.id,z.title,z.description,s.name subject,z.time_limit_min,z.start_at,z.deadline,z.max_attempts,
    (SELECT COUNT(*) FROM attempts WHERE quiz_id=z.id AND student_id=?) used,(SELECT id FROM attempts WHERE quiz_id=z.id AND student_id=? AND status='in_progress' LIMIT 1) open_attempt,
    (z.start_at IS NOT NULL AND z.start_at>NOW()) upcoming,(z.deadline IS NOT NULL AND z.deadline<NOW()) expired
    FROM quizzes z LEFT JOIN subjects s ON s.id=z.subject_id WHERE z.published=1 AND z.id IN (SELECT quiz_id FROM assignments WHERE student_id=? OR class_id IN (SELECT class_id FROM class_students WHERE student_id=?))`, [id, id, id, id]);
  const left = r => r.open_attempt || r.max_attempts === 0 || r.used < r.max_attempts;
  const history = await q(`SELECT a.id,z.title,a.status,a.submitted_at,IF(z.results_released AND a.status='graded',a.score,NULL) score,IF(z.results_released AND a.status='graded',a.total_points,NULL) total,
    IF(z.results_released AND a.status='graded',a.percentage,NULL) percentage,IF(z.results_released AND a.status='graded',a.passed,NULL) passed,z.results_released FROM attempts a JOIN quizzes z ON z.id=a.quiz_id WHERE a.student_id=? AND a.status<>'in_progress' ORDER BY a.id DESC`, [id]);
  const scored = history.filter(h => h.percentage !== null);
  res.json({ available: rows.filter(r => !r.upcoming && !r.expired && left(r)), upcoming: rows.filter(r => r.upcoming), history,
    completed: rows.filter(r => r.used > 0 && !r.open_attempt && !left(r)).length,
    average: scored.length ? Math.round(scored.reduce((s, h) => s + +h.percentage, 0) / scored.length * 100) / 100 : null });
}));

/* ---------- 8/10. Submissions, review, results, export ---------- */
async function resultRows(quizId) {
  return q(`SELECT a.id attempt_id,u.name student,u.email,a.status,a.score,a.total_points,a.percentage,a.passed,a.submitted_at,a.tab_switches FROM attempts a JOIN users u ON u.id=a.student_id WHERE a.quiz_id=? AND a.status<>'in_progress' ORDER BY u.name,a.id`, [quizId]);
}
app.get('/api/quizzes/:id/results', T, a(async (req, res) => {
  const z = await ownQuiz(req), rows = await resultRows(z.id), g = rows.filter(r => r.status === 'graded'), pct = g.map(r => +r.percentage);
  res.json({ quiz: z.title, rows, stats: { attempts: rows.length, graded: g.length, average: pct.length ? +(pct.reduce((s, x) => s + x, 0) / pct.length).toFixed(2) : null, highest: pct.length ? Math.max(...pct) : null, lowest: pct.length ? Math.min(...pct) : null, pass_rate: g.length ? +(g.filter(r => r.passed).length / g.length * 100).toFixed(1) : null, fail_rate: g.length ? +(g.filter(r => !r.passed).length / g.length * 100).toFixed(1) : null } });
}));
app.get('/api/quizzes/:id/export', T, a(async (req, res) => {
  const safe = v => (typeof v === 'string' && /^[=+\-@\t\r]/.test(v) ? "'" + v : v);
  const z = await ownQuiz(req), rows = (await resultRows(z.id)).map(r => ({ Student: safe(r.student), Email: safe(r.email), Status: r.status, Score: r.score, Total: r.total_points, 'Percentage': r.percentage, Result: r.status !== 'graded' ? 'Pending' : r.passed ? 'Passed' : 'Failed', Submitted: r.submitted_at, 'Tab switches': r.tab_switches }));
  const name = z.title.replace(/[^\w-]+/g, '_'), cols = Object.keys(rows[0] || { Student: 1, Email: 1, Status: 1, Score: 1, Total: 1, Percentage: 1, Result: 1, Submitted: 1, 'Tab switches': 1 }), fmt = req.query.format;
  if (fmt === 'xlsx') {
    const wb = new ExcelJS.Workbook(), ws = wb.addWorksheet('Results'); ws.columns = cols.map(c => ({ header: c, key: c, width: 18 })); ws.addRows(rows); ws.getRow(1).font = { bold: true };
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'); res.setHeader('Content-Disposition', `attachment; filename=${name}.xlsx`);
    return res.send(Buffer.from(await wb.xlsx.writeBuffer()));
  }
  if (fmt === 'pdf') {
    res.setHeader('Content-Type', 'application/pdf'); res.setHeader('Content-Disposition', `attachment; filename=${name}.pdf`);
    const d = new PDFDocument({ margin: 40, size: 'A4', layout: 'landscape' }); d.pipe(res);
    d.fontSize(16).text(`Results: ${z.title}`).moveDown(); d.fontSize(9);
    const sel = ['Student', 'Status', 'Score', 'Total', 'Percentage', 'Result', 'Submitted'], w = 105;
    const row = v => { const y = d.y; sel.forEach((c, i) => d.text(String(v[c] ?? ''), 40 + i * w, y, { width: w - 5 })); d.y = y + 16; if (d.y > 520) d.addPage(); };
    row(Object.fromEntries(sel.map(c => [c, c]))); rows.forEach(row); return d.end();
  }
  const esc = v => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`;
  res.setHeader('Content-Type', 'text/csv'); res.setHeader('Content-Disposition', `attachment; filename=${name}.csv`);
  res.send([cols.map(esc).join(','), ...rows.map(r => cols.map(c => esc(r[c])).join(','))].join('\n'));
}));
app.get('/api/attempts/:id/review', ANY, a(async (req, res) => {
  const at = await one('SELECT a.*,z.title,z.teacher_id,z.results_released,u.name student FROM attempts a JOIN quizzes z ON z.id=a.quiz_id JOIN users u ON u.id=a.student_id WHERE a.id=?', [req.params.id]);
  if (!at) throw http(404, 'Not found');
  const staff = req.user.role === 'admin' || at.teacher_id === req.user.id, mine = at.student_id === req.user.id;
  if (!staff && !(mine && at.status === 'graded' && at.results_released)) throw http(403, 'Not available');
  const qs = await q('SELECT q.id,q.type,q.text,q.points,q.explanation FROM quiz_questions qq JOIN questions q ON q.id=qq.question_id WHERE qq.quiz_id=? ORDER BY qq.position', [at.quiz_id]);
  const chs = await q('SELECT * FROM choices WHERE question_id IN (SELECT question_id FROM quiz_questions WHERE quiz_id=?) ORDER BY position', [at.quiz_id]);
  const ans = await q('SELECT * FROM answers WHERE attempt_id=?', [at.id]);
  const events = staff ? await q("SELECT action,details,created_at FROM activity_logs WHERE attempt_id=? AND action LIKE 'cheat:%' ORDER BY id", [at.id]) : [];
  res.json({ attempt: { id: at.id, title: at.title, student: at.student, status: at.status, score: at.score, total: at.total_points, percentage: at.percentage, passed: at.passed, tab_switches: at.tab_switches }, staff, events,
    questions: qs.map(qu => { const an = ans.find(x => x.question_id === qu.id) || {}; return { ...qu, choices: chs.filter(c => c.question_id === qu.id), answer: an.answer ?? null, answer_id: an.id || null, is_correct: an.is_correct, earned: an.points, feedback: an.feedback, graded_manual: an.graded_manual }; }) });
}));
app.put('/api/answers/:id/grade', T, a(async (req, res) => {
  const r = await one("SELECT an.id,an.attempt_id,q.points,z.teacher_id,a.status FROM answers an JOIN attempts a ON a.id=an.attempt_id JOIN quizzes z ON z.id=a.quiz_id JOIN questions q ON q.id=an.question_id WHERE an.id=?", [req.params.id]);
  if (!r) throw http(404, 'Not found'); if (req.user.role !== 'admin' && r.teacher_id !== req.user.id) throw http(403, 'Forbidden');
  if (r.status === 'in_progress') throw http(400, 'Attempt is still in progress');
  const pts = Math.max(0, Math.min(+req.body.points || 0, +r.points));
  await q('UPDATE answers SET points=?,is_correct=?,feedback=?,graded_manual=1 WHERE id=?', [pts, pts >= +r.points ? 1 : 0, nz(req.body.feedback), r.id]);
  await gradeAttempt(r.attempt_id); await log(req.user.id, 'manual_grade', r.id, req); res.json({ ok: true });
}));
app.get('/api/gradebook', T, a(async (req, res) => {
  const c = await ownClass({ params: { id: req.query.class_id }, user: req.user });
  const students = await q('SELECT u.id,u.name FROM class_students cs JOIN users u ON u.id=cs.student_id WHERE cs.class_id=? ORDER BY u.name', [c.id]);
  const quizzes = await q('SELECT DISTINCT z.id,z.title FROM assignments a JOIN quizzes z ON z.id=a.quiz_id WHERE a.class_id=?', [c.id]);
  const grades = {}; if (students.length && quizzes.length) for (const g of await q('SELECT student_id,quiz_id,MAX(percentage) pct FROM grades WHERE student_id IN (?) AND quiz_id IN (?) GROUP BY student_id,quiz_id', [students.map(s => s.id), quizzes.map(z => z.id)])) (grades[g.student_id] = grades[g.student_id] || {})[g.quiz_id] = +g.pct;
  students.forEach(s => { const v = Object.values(grades[s.id] || {}); s.average = v.length ? +(v.reduce((x, y) => x + y, 0) / v.length).toFixed(2) : null; });
  res.json({ class: c.name, students, quizzes, grades });
}));

/* ---------- 11. Analytics ---------- */
app.get('/api/analytics/quiz/:id', T, a(async (req, res) => {
  const z = await ownQuiz(req), rows = await q("SELECT percentage FROM attempts WHERE quiz_id=? AND status='graded'", [z.id]);
  const buckets = Array.from({ length: 10 }, (_, i) => ({ range: `${i * 10}-${i === 9 ? 100 : i * 10 + 9}`, count: 0 }));
  rows.forEach(r => buckets[Math.min(9, Math.floor(+r.percentage / 10))].count++);
  const n = (await one("SELECT COUNT(*) n FROM attempts WHERE quiz_id=? AND status<>'in_progress'", [z.id])).n;
  const qstats = (await q(`SELECT q.id,q.text,q.type,COUNT(an.id) answered,COALESCE(SUM(an.is_correct=1),0) correct FROM quiz_questions qq JOIN questions q ON q.id=qq.question_id
    LEFT JOIN answers an ON an.question_id=q.id AND an.attempt_id IN (SELECT id FROM attempts WHERE quiz_id=? AND status<>'in_progress') WHERE qq.quiz_id=? GROUP BY q.id,q.text,q.type`, [z.id, z.id]))
    .map(r => { const rate = n ? +(r.correct / n * 100).toFixed(1) : null; return { ...r, correct: +r.correct, attempts: n, correct_rate: rate, missed: n - r.correct, difficulty: rate === null ? '-' : rate >= 75 ? 'easy' : rate >= 40 ? 'medium' : 'hard' }; })
    .sort((x, y) => y.missed - x.missed);
  res.json({ title: z.title, attempts: n, distribution: buckets, questions: qstats });
}));
app.get('/api/analytics/class/:id', T, a(async (req, res) => {
  const c = await ownClass(req);
  const students = await q(`SELECT u.id,u.name,COUNT(g.id) quizzes_taken,ROUND(AVG(g.percentage),2) average FROM class_students cs JOIN users u ON u.id=cs.student_id LEFT JOIN grades g ON g.student_id=u.id AND g.quiz_id IN (SELECT quiz_id FROM assignments WHERE class_id=cs.class_id) WHERE cs.class_id=? GROUP BY u.id,u.name ORDER BY average DESC`, [c.id]);
  const quizzes = await q('SELECT z.id,z.title,ROUND(AVG(g.percentage),2) average,ROUND(AVG(g.passed)*100,1) pass_rate FROM assignments a JOIN quizzes z ON z.id=a.quiz_id LEFT JOIN grades g ON g.quiz_id=z.id AND g.student_id IN (SELECT student_id FROM class_students WHERE class_id=?) WHERE a.class_id=? GROUP BY z.id,z.title', [c.id, c.id]);
  res.json({ class: c.name, students, quizzes });
}));

/* ---------- 13. Notifications ---------- */
app.get('/api/notifications', ANY, a(async (req, res) => res.json(await q('SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 100', [req.user.id]))));
app.post('/api/notifications/read', ANY, a(async (req, res) => { await q('UPDATE notifications SET is_read=1 WHERE user_id=?', [req.user.id]); res.json({ ok: true }); }));
async function sendReminders() {
  for (const r of await q('SELECT a.id,a.quiz_id,z.title,z.deadline FROM assignments a JOIN quizzes z ON z.id=a.quiz_id WHERE z.published=1 AND a.reminder_sent=0 AND z.deadline BETWEEN NOW() AND DATE_ADD(NOW(),INTERVAL 24 HOUR)')) {
    for (const sid of await assignedStudents(r.quiz_id)) if (!(await one("SELECT 1 x FROM attempts WHERE quiz_id=? AND student_id=? AND status<>'in_progress'", [r.quiz_id, sid]))) await notify(sid, 'reminder', 'Quiz deadline soon', `"${r.title}" is due ${r.deadline}.`);
    await q('UPDATE assignments SET reminder_sent=1 WHERE id=?', [r.id]);
  }
}

/* ---------- 14. Admin ---------- */
app.get('/api/admin/users', ADM, a(async (req, res) => {
  const w = [], p = [];
  if (req.query.role) { w.push('r.name=?'); p.push(req.query.role); }
  if (req.query.search) { w.push('(u.name LIKE ? OR u.email LIKE ?)'); p.push(`%${req.query.search}%`, `%${req.query.search}%`); }
  res.json(await q(`SELECT u.id,u.name,u.email,u.active,u.created_at,r.name role FROM users u JOIN roles r ON r.id=u.role_id ${w.length ? 'WHERE ' + w.join(' AND ') : ''} ORDER BY u.id DESC LIMIT 500`, p));
}));
async function ensureProfile(id, role) { if (role === 'student') await q('INSERT IGNORE INTO students(user_id) VALUES(?)', [id]); if (role === 'teacher') await q('INSERT IGNORE INTO teachers(user_id) VALUES(?)', [id]); }
app.post('/api/admin/users', ADM, a(async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || !['student', 'teacher', 'admin'].includes(role)) throw http(400, 'Invalid user data');
  if (await one('SELECT id FROM users WHERE email=?', [email])) throw http(409, 'Email already registered');
  const id = (await q('INSERT INTO users(role_id,name,email,password_hash) VALUES((SELECT id FROM roles WHERE name=?),?,?,?)', [role, name, email, await bcrypt.hash(password, 10)])).insertId;
  await ensureProfile(id, role); await log(req.user.id, 'user_create', email, req); res.json({ id });
}));
app.put('/api/admin/users/:id', ADM, a(async (req, res) => {
  const { name, role, active, password } = req.body;
  if (+req.params.id === req.user.id && (active === 0 || active === false || (role && role !== 'admin'))) throw http(400, 'You cannot demote or disable yourself');
  if (name) await q('UPDATE users SET name=? WHERE id=?', [name, req.params.id]);
  if (active !== undefined) await q('UPDATE users SET active=? WHERE id=?', [active ? 1 : 0, req.params.id]);
  if (role) { await q('UPDATE users SET role_id=(SELECT id FROM roles WHERE name=?) WHERE id=?', [role, req.params.id]); await ensureProfile(req.params.id, role); }
  if (password) await q('UPDATE users SET password_hash=? WHERE id=?', [await bcrypt.hash(password, 10), req.params.id]);
  await log(req.user.id, 'user_update', req.params.id, req); res.json({ ok: true });
}));
app.delete('/api/admin/users/:id', ADM, a(async (req, res) => { if (+req.params.id === req.user.id) throw http(400, 'Cannot delete yourself'); await q('DELETE FROM users WHERE id=?', [req.params.id]); await log(req.user.id, 'user_delete', req.params.id, req); res.json({ ok: true }); }));
app.post('/api/admin/notify', ADM, a(async (req, res) => {
  const { title, message, role } = req.body;
  if (!title || !message) throw http(400, 'Title and message required');
  const users = await q(`SELECT u.id FROM users u JOIN roles r ON r.id=u.role_id WHERE u.active=1 ${role ? 'AND r.name=?' : ''}`, role ? [role] : []);
  for (const u of users) await notify(u.id, 'system', title, message);
  await log(req.user.id, 'broadcast', title, req); res.json({ sent: users.length });
}));
app.get('/api/admin/stats', ADM, a(async (req, res) => res.json(await one(`SELECT (SELECT COUNT(*) FROM users u JOIN roles r ON r.id=u.role_id WHERE r.name='student') students,(SELECT COUNT(*) FROM users u JOIN roles r ON r.id=u.role_id WHERE r.name='teacher') teachers,
  (SELECT COUNT(*) FROM subjects) subjects,(SELECT COUNT(*) FROM classes) classes,(SELECT COUNT(*) FROM quizzes) quizzes,(SELECT COUNT(*) FROM quizzes WHERE published=1) published_quizzes,(SELECT COUNT(*) FROM questions) questions,
  (SELECT COUNT(*) FROM attempts WHERE status<>'in_progress') attempts,(SELECT ROUND(AVG(percentage),2) FROM grades) average_score,(SELECT COUNT(*) FROM activity_logs WHERE action LIKE 'cheat:%') suspicious_events`))));
app.get('/api/admin/logs', ADM, a(async (req, res) => res.json(await q(`SELECT l.id,l.action,l.details,l.ip,l.created_at,u.name FROM activity_logs l LEFT JOIN users u ON u.id=l.user_id ${req.query.cheat ? "WHERE l.action LIKE 'cheat:%'" : ''} ORDER BY l.id DESC LIMIT 300`))));

/* ---------- Errors & boot ---------- */
app.use((err, req, res, next) => { if (!err.status) console.error(err); res.status(err.status || 500).json({ error: err.status ? err.message : (err.code === 'ER_DUP_ENTRY' ? 'Duplicate entry' : 'Server error') }); });
(async () => {
  try { await pool.query('SELECT 1'); await pool.query('SELECT 1 FROM users LIMIT 1'); }
  catch (e) { throw new Error(hint(e)); }
  console.log(`Connected to MySQL ${cfg.host}:${cfg.port}/${cfg.database}`);
  if (!(await one("SELECT 1 x FROM users u JOIN roles r ON r.id=u.role_id WHERE r.name='admin' LIMIT 1"))) {
    const email = process.env.ADMIN_EMAIL || 'admin@example.com', pw = process.env.ADMIN_PASSWORD || 'admin123';
    await q("INSERT INTO users(role_id,name,email,password_hash) VALUES((SELECT id FROM roles WHERE name='admin'),?,?,?)", ['Administrator', email, await bcrypt.hash(pw, 10)]);
    console.log(`Default admin created: ${email} / ${pw} (change it!)`);
  }
  setInterval(() => { sweep().catch(console.error); sendReminders().catch(console.error); }, 60000);
  app.listen(process.env.PORT || 3000, () => console.log(`Quiz Maker running on http://localhost:${process.env.PORT || 3000}`));
})().catch(e => { console.error('Startup failed:', e.message); process.exit(1); });
