require('dotenv').config();
// Shared MySQL settings. 127.0.0.1 (not "localhost") avoids IPv6 (::1) lookup failures on newer Node versions.
const cfg = {
  host: process.env.DB_HOST || '127.0.0.1',
  port: +process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'quiz_maker',
  charset: 'utf8mb4',
};
// Turns low-level driver errors into something actionable.
function hint(e) {
  const code = e.code || (e.errors && e.errors[0] && e.errors[0].code) || '';
  const where = `${cfg.host}:${cfg.port}`;
  const m = {
    ECONNREFUSED: `Cannot reach MySQL at ${where}. Is the server running, and are DB_HOST/DB_PORT correct?`,
    ENOTFOUND: `Host "${cfg.host}" was not found. Check DB_HOST.`,
    ETIMEDOUT: `Connection to ${where} timed out. Check DB_HOST/DB_PORT and any firewall.`,
    ER_ACCESS_DENIED_ERROR: `Access denied for user "${cfg.user}". Check DB_USER and DB_PASSWORD.`,
    ER_BAD_DB_ERROR: `Database "${cfg.database}" does not exist. Run: npm run db:init`,
    ER_NO_SUCH_TABLE: 'Tables are missing. Run: npm run db:init',
  };
  return (m[code] || e.message || String(e)) + (code ? ` [${code}]` : '');
}
module.exports = { cfg, hint };
