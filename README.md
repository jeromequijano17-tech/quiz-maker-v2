# Quiz Maker (Node.js + Express + MySQL)

## Setup
1. `npm install`
2. Copy `.env.example` to `.env` and set your MySQL credentials and a strong `JWT_SECRET`.
3. `npm run db:init`  (creates the database and all tables)
4. `npm start`  then open http://localhost:3000

A default admin is created on first start: `admin@example.com` / `admin123` (set ADMIN_EMAIL / ADMIN_PASSWORD in `.env`, and change it after logging in).

## Roles
- **Student**: dashboard, take quizzes (timer, autosave, navigation), history, results.
- **Teacher**: quizzes, question bank (8 types), classes, assignments, submissions, essay grading, gradebook, analytics, CSV/Excel/PDF export.
- **Admin**: everything above plus users, subjects, system stats, activity/suspicious-event logs.

## Question input format (Question Bank form)
- Multiple choice / Multiple select: one choice per line, prefix correct ones with `*`
- True/False: type `true` or `false`
- Identification / Short answer: one accepted answer per line
- Matching: `left => right` per line
- Ordering: items in the correct order, one per line
- Essay: no key; graded manually

## Notes
- Public registration allows student and teacher roles; remove teacher from `/api/register` if you want admin-only teacher creation.
- Passwords are hashed with bcrypt; sessions use JWT (12h).
- Deadline reminders and expired-attempt auto-submission run every minute on the server.

## Troubleshooting the database connection
- `npm run db:init` and `npm start` print the reason a connection fails (wrong host/port, bad credentials, missing database or tables).
- Use `DB_HOST=127.0.0.1` rather than `localhost` if you see `ECONNREFUSED` while MySQL is running (IPv6 lookup issue).
- Requires MySQL 5.7+ or 8 (not MariaDB; JSON columns are used). The DB user needs CREATE/ALTER/INSERT/SELECT/UPDATE/DELETE rights.
