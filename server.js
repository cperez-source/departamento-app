const express = require('express');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const path = require('path');
const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

const app = express();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

// ─── DB Setup ────────────────────────────────────────────────────────────────
async function setupDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS session (
      sid VARCHAR NOT NULL PRIMARY KEY,
      sess JSON NOT NULL,
      expire TIMESTAMP(6) NOT NULL
    );
    CREATE INDEX IF NOT EXISTS IDX_session_expire ON session (expire);

    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'guest'
    );

    CREATE TABLE IF NOT EXISTS reservations (
      id SERIAL PRIMARY KEY,
      user_id INTEGER,
      username TEXT NOT NULL,
      checkin TEXT NOT NULL,
      checkout TEXT NOT NULL,
      notes TEXT,
      notified INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS config (
      key TEXT PRIMARY KEY,
      value TEXT
    );
  `);

  const { rows } = await pool.query('SELECT COUNT(*) AS n FROM users');
  if (parseInt(rows[0].n) === 0) {
    const hash = (p) => bcrypt.hashSync(p, 10);
    await pool.query('INSERT INTO users (username, password, role) VALUES ($1,$2,$3)', ['admin', hash('admin123'), 'admin']);
    await pool.query('INSERT INTO users (username, password, role) VALUES ($1,$2,$3)', ['usuario1', hash('pass1'), 'guest']);
    await pool.query('INSERT INTO users (username, password, role) VALUES ($1,$2,$3)', ['usuario2', hash('pass2'), 'guest']);
    console.log('Usuarios iniciales creados');
  }
}

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('trust proxy', 1);
app.use(session({
  store: new pgSession({ pool, tableName: 'session' }),
  secret: process.env.SESSION_SECRET || 'depto-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000, secure: !!process.env.DATABASE_URL },
}));

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'No autenticado' });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({ error: 'Sin permiso' });
  next();
}

// ─── WhatsApp ────────────────────────────────────────────────────────────────
async function sendWhatsApp(phone, apikey, message) {
  if (!phone || !apikey) return { ok: false, reason: 'No configurado' };
  const url = `https://api.callmebot.com/whatsapp.php?phone=${phone}&text=${encodeURIComponent(message)}&apikey=${apikey}`;
  try {
    const res = await fetch(url);
    return { ok: res.ok, status: res.status };
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}

async function getConfig() {
  const { rows } = await pool.query('SELECT key, value FROM config');
  return Object.fromEntries(rows.map(r => [r.key, r.value]));
}

function formatDate(str) {
  const [y, m, d] = str.split('-');
  return `${d}/${m}/${y}`;
}

// ─── Auth ─────────────────────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const { rows } = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
  const user = rows[0];
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  req.session.user = { id: user.id, username: user.username, role: user.role };
  res.json({ ok: true, username: user.username, role: user.role });
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ ok: true }); });

app.get('/api/me', (req, res) => {
  res.json({ user: req.session.user || null });
});

// ─── Reservations ─────────────────────────────────────────────────────────────
app.get('/api/reservations', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM reservations ORDER BY checkin ASC');
  res.json(rows);
});

app.post('/api/reservations', requireAuth, async (req, res) => {
  const { checkin, checkout, notes } = req.body;
  if (!checkin || !checkout || checkin >= checkout)
    return res.status(400).json({ error: 'Fechas inválidas' });

  const conflict = await pool.query(
    'SELECT id FROM reservations WHERE NOT (checkout <= $1 OR checkin >= $2)',
    [checkin, checkout]
  );
  if (conflict.rows.length) return res.status(409).json({ error: 'Ya existe una reserva en esas fechas' });

  const result = await pool.query(
    'INSERT INTO reservations (user_id, username, checkin, checkout, notes) VALUES ($1,$2,$3,$4,$5) RETURNING id',
    [req.session.user.id, req.session.user.username, checkin, checkout, notes || '']
  );
  const id = result.rows[0].id;

  const cfg = await getConfig();
  const msg = `🏠 Nueva reserva en el departamento:\n👤 ${req.session.user.username}\n📅 Entrada: ${formatDate(checkin)}\n📅 Salida: ${formatDate(checkout)}${notes ? '\n📝 ' + notes : ''}`;
  const wa = await sendWhatsApp(cfg.cleaning_phone, cfg.cleaning_apikey, msg);
  if (wa.ok) await pool.query('UPDATE reservations SET notified=1 WHERE id=$1', [id]);

  res.json({ ok: true, id, notified: wa.ok });
});

app.put('/api/reservations/:id', requireAdmin, async (req, res) => {
  const { checkin, checkout, notes, user_id } = req.body;
  if (!checkin || !checkout || checkin >= checkout)
    return res.status(400).json({ error: 'Fechas inválidas' });

  const { rows: userRows } = await pool.query('SELECT id, username FROM users WHERE id = $1', [user_id]);
  if (!userRows.length) return res.status(400).json({ error: 'Usuario no encontrado' });
  const assignee = userRows[0];

  const conflict = await pool.query(
    'SELECT id FROM reservations WHERE NOT (checkout <= $1 OR checkin >= $2) AND id != $3',
    [checkin, checkout, req.params.id]
  );
  if (conflict.rows.length) return res.status(409).json({ error: 'Ya existe una reserva en esas fechas' });

  await pool.query(
    'UPDATE reservations SET checkin=$1, checkout=$2, notes=$3, user_id=$4, username=$5, notified=0 WHERE id=$6',
    [checkin, checkout, notes || '', assignee.id, assignee.username, req.params.id]
  );

  const cfg = await getConfig();
  const msg = `✏️ Reserva actualizada:\n👤 ${assignee.username}\n📅 Entrada: ${formatDate(checkin)}\n📅 Salida: ${formatDate(checkout)}${notes ? '\n📝 ' + notes : ''}`;
  const wa = await sendWhatsApp(cfg.cleaning_phone, cfg.cleaning_apikey, msg);
  if (wa.ok) await pool.query('UPDATE reservations SET notified=1 WHERE id=$1', [req.params.id]);

  res.json({ ok: true, notified: wa.ok });
});

app.delete('/api/reservations/:id', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM reservations WHERE id = $1', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'No encontrada' });
  if (rows[0].user_id !== req.session.user.id && req.session.user.role !== 'admin')
    return res.status(403).json({ error: 'Sin permiso' });
  await pool.query('DELETE FROM reservations WHERE id = $1', [req.params.id]);
  res.json({ ok: true });
});

// ─── Admin ────────────────────────────────────────────────────────────────────
app.get('/api/admin/config', requireAdmin, async (req, res) => {
  res.json(await getConfig());
});

app.post('/api/admin/config', requireAdmin, async (req, res) => {
  const allowed = ['cleaning_phone', 'cleaning_apikey', 'cleaning_name', 'apartment_name'];
  for (const key of allowed) {
    if (req.body[key] !== undefined)
      await pool.query('INSERT INTO config (key,value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=$2', [key, req.body[key]]);
  }
  res.json({ ok: true });
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const { rows } = await pool.query('SELECT id, username, role FROM users ORDER BY id');
  res.json(rows);
});

app.post('/api/admin/users', requireAdmin, async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Datos incompletos' });
  try {
    await pool.query('INSERT INTO users (username, password, role) VALUES ($1,$2,$3)', [username, bcrypt.hashSync(password, 10), role || 'guest']);
    res.json({ ok: true });
  } catch (e) {
    res.status(409).json({ error: 'Usuario ya existe' });
  }
});

app.post('/api/admin/users/:id/password', requireAdmin, async (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 4) return res.status(400).json({ error: 'Contraseña muy corta' });
  await pool.query('UPDATE users SET password=$1 WHERE id=$2', [bcrypt.hashSync(password, 10), req.params.id]);
  res.json({ ok: true });
});

app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  const id = parseInt(req.params.id);
  if (id === req.session.user.id) return res.status(400).json({ error: 'No puedes eliminarte a ti mismo' });
  const { rows } = await pool.query('SELECT id FROM users WHERE id=$1', [id]);
  if (!rows.length) return res.status(404).json({ error: 'Usuario no encontrado' });
  await pool.query("UPDATE reservations SET user_id=NULL, username='(eliminado)' WHERE user_id=$1", [id]);
  await pool.query('DELETE FROM users WHERE id=$1', [id]);
  res.json({ ok: true });
});

app.post('/api/admin/test-whatsapp', requireAdmin, async (req, res) => {
  const cfg = await getConfig();
  const result = await sendWhatsApp(cfg.cleaning_phone, cfg.cleaning_apikey, '✅ Prueba desde la app del departamento. ¡Funciona!');
  res.json(result);
});

// ─── SPA ──────────────────────────────────────────────────────────────────────
app.get('/{*path}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, async () => {
  await setupDB();
  console.log(`App corriendo en http://localhost:${PORT}`);
});
