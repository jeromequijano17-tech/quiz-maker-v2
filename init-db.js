require('dotenv').config();
const mysql = require('mysql2/promise'), fs = require('fs');
const { cfg, hint } = require('./db');
(async () => {
  const { database, ...server } = cfg;   // connect without a database first; the schema creates it
  const c = await mysql.createConnection({ ...server, multipleStatements: true, connectTimeout: 10000 });
  const sql = fs.readFileSync(__dirname + '/schema.sql', 'utf8').replace(/quiz_maker/g, database);
  await c.query(sql);
  const [t] = await c.query(`SELECT COUNT(*) n FROM information_schema.tables WHERE table_schema=?`, [database]);
  console.log(`Database "${database}" ready on ${cfg.host}:${cfg.port} (${t[0].n} tables).`);
  await c.end();
})().catch(e => { console.error('Database setup failed:', hint(e)); process.exit(1); });
