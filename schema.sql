CREATE DATABASE IF NOT EXISTS quiz_maker CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE quiz_maker;

CREATE TABLE IF NOT EXISTS roles (id TINYINT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(20) NOT NULL UNIQUE);
INSERT IGNORE INTO roles(name) VALUES ('student'),('teacher'),('admin');

CREATE TABLE IF NOT EXISTS users (
  id INT PRIMARY KEY AUTO_INCREMENT, role_id TINYINT NOT NULL,
  name VARCHAR(120) NOT NULL, email VARCHAR(160) NOT NULL UNIQUE, password_hash VARCHAR(100) NOT NULL,
  active TINYINT(1) NOT NULL DEFAULT 1, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (role_id) REFERENCES roles(id)
);
CREATE TABLE IF NOT EXISTS students (user_id INT PRIMARY KEY, student_no VARCHAR(40), FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS teachers (user_id INT PRIMARY KEY, department VARCHAR(80), FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS subjects (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(100) NOT NULL UNIQUE);

CREATE TABLE IF NOT EXISTS classes (
  id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(100) NOT NULL, section VARCHAR(50), subject_id INT NULL, teacher_id INT NULL,
  FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE SET NULL, FOREIGN KEY (teacher_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS class_students (
  class_id INT NOT NULL, student_id INT NOT NULL, PRIMARY KEY (class_id, student_id),
  FOREIGN KEY (class_id) REFERENCES classes(id) ON DELETE CASCADE, FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS quizzes (
  id INT PRIMARY KEY AUTO_INCREMENT, teacher_id INT NOT NULL, subject_id INT NULL,
  title VARCHAR(200) NOT NULL, description TEXT, topic VARCHAR(120),
  time_limit_min INT NOT NULL DEFAULT 0, passing_score DECIMAL(5,2) NOT NULL DEFAULT 60,
  start_at DATETIME NULL, deadline DATETIME NULL, max_attempts INT NOT NULL DEFAULT 1,
  shuffle_questions TINYINT(1) NOT NULL DEFAULT 0, shuffle_choices TINYINT(1) NOT NULL DEFAULT 0,
  published TINYINT(1) NOT NULL DEFAULT 0, results_released TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (teacher_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS questions (
  id INT PRIMARY KEY AUTO_INCREMENT, owner_id INT NOT NULL, subject_id INT NULL, category VARCHAR(80), topic VARCHAR(120),
  type ENUM('mcq','tf','identification','short','multi_select','essay','matching','ordering') NOT NULL,
  difficulty ENUM('easy','medium','hard') NOT NULL DEFAULT 'medium',
  text TEXT NOT NULL, points DECIMAL(6,2) NOT NULL DEFAULT 1, explanation TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY (subject_id) REFERENCES subjects(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS choices (
  id INT PRIMARY KEY AUTO_INCREMENT, question_id INT NOT NULL, text VARCHAR(500) NOT NULL,
  is_correct TINYINT(1) NOT NULL DEFAULT 0, position INT NOT NULL DEFAULT 0, match_text VARCHAR(500) NULL,
  FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS quiz_questions (
  quiz_id INT NOT NULL, question_id INT NOT NULL, position INT NOT NULL DEFAULT 0, PRIMARY KEY (quiz_id, question_id),
  FOREIGN KEY (quiz_id) REFERENCES quizzes(id) ON DELETE CASCADE, FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS assignments (
  id INT PRIMARY KEY AUTO_INCREMENT, quiz_id INT NOT NULL, class_id INT NULL, student_id INT NULL,
  reminder_sent TINYINT(1) NOT NULL DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (quiz_id) REFERENCES quizzes(id) ON DELETE CASCADE, FOREIGN KEY (class_id) REFERENCES classes(id) ON DELETE CASCADE,
  FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS attempts (
  id INT PRIMARY KEY AUTO_INCREMENT, quiz_id INT NOT NULL, student_id INT NOT NULL,
  started_at DATETIME NOT NULL, submitted_at DATETIME NULL,
  status ENUM('in_progress','submitted','graded') NOT NULL DEFAULT 'in_progress',
  score DECIMAL(8,2) NULL, total_points DECIMAL(8,2) NULL, percentage DECIMAL(5,2) NULL, passed TINYINT(1) NULL,
  layout JSON NULL, tab_switches INT NOT NULL DEFAULT 0,
  FOREIGN KEY (quiz_id) REFERENCES quizzes(id) ON DELETE CASCADE, FOREIGN KEY (student_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS answers (
  id INT PRIMARY KEY AUTO_INCREMENT, attempt_id INT NOT NULL, question_id INT NOT NULL, answer JSON NULL,
  is_correct TINYINT(1) NULL, points DECIMAL(6,2) NULL, graded_manual TINYINT(1) NOT NULL DEFAULT 0, feedback TEXT,
  UNIQUE KEY uq_attempt_question (attempt_id, question_id),
  FOREIGN KEY (attempt_id) REFERENCES attempts(id) ON DELETE CASCADE, FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS grades (
  id INT PRIMARY KEY AUTO_INCREMENT, attempt_id INT NOT NULL UNIQUE, quiz_id INT NOT NULL, student_id INT NOT NULL,
  score DECIMAL(8,2), total_points DECIMAL(8,2), percentage DECIMAL(5,2), passed TINYINT(1), graded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (attempt_id) REFERENCES attempts(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS notifications (
  id INT PRIMARY KEY AUTO_INCREMENT, user_id INT NOT NULL, type VARCHAR(30), title VARCHAR(200), message TEXT,
  is_read TINYINT(1) NOT NULL DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS activity_logs (
  id INT PRIMARY KEY AUTO_INCREMENT, user_id INT NULL, attempt_id INT NULL, action VARCHAR(60) NOT NULL,
  details TEXT, ip VARCHAR(60), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, INDEX (attempt_id), INDEX (created_at)
);
