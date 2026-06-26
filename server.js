const express = require('express');
const session = require('express-session');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');
const fetch = (...args) => import('node-fetch').then(({ default: f }) => f(...args));

const app = express();
const db = new Database('departamento.db');

// ─── DB Setup ────────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'guest'
  );
  CREATE TABLE IF NOT EXISTS reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    checkin TEXT NOT NULL,
    checkout TEXT NOT NULL,
    notes TEXT,
    notified INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT
  );
`);

function seedUsers() {
  const count = db.prepare('SELECT COUNT(*) as n FROM users').get().n;
  if (count === 0) {
    const hash = (p) => bcrypt.hashSync(p, 10);
    db.prepare("INSERT INTO users (username, password, role) VALUES (?, ?, ?)").run('admin', hash('admin123'), 'admin');
    db.prepare("INSERT INTO users (username, password, role) VALUES (?, ?, ?)").run('usuario1', hash('pass1'), 'guest');
    db.prepare("INSERT INTO users (username, password, role) VALUES (?, ?, ?)").run('usuario2', hash('pass2'), 'guest');
    console.log('Usuarios iniciales creados. Cambia las contraseñas en /admin');
  }
}
seedUsers();

// ─── Middleware ───────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'depto-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
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
  const encoded = encodeURIComponent(message);
  const url = `https://api.callmebot.com/whatsapp.php?phone=${phone}&text=${encoded}&apikey=${apikey}`;
  try {
    const res = await fetch(url);
    return { ok: res.ok, status: res.status };
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}

function getConfig() {
  const rows = db.prepare('SELECT key, value FROM config').all();
  return Object.fromEntries(rows.map(r => [r.key, r.value]));
}

function formatDate(dateStr) {
  const [y, m, d] = dateStr.split('-');
  return `${d}/${m}/${y}`;
}

// ─── Auth Routes ──────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  req.session.user = { id: user.id, username: user.username, role: user.role };
  res.json({ ok: true, username: user.username, role: user.role });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.json({ user: null });
  res.json({ user: req.session.user });
});

// ─── Reservations ─────────────────────────────────────────────────────────────
app.get('/api/reservations', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM reservations ORDER BY checkin ASC').all();
  res.json(rows);
});

app.post('/api/reservations', requireAuth, async (req, res) => {
  const { checkin, checkout, notes } = req.body;
  if (!checkin || !checkout || checkin >= checkout)
    return res.status(400).json({ error: 'Fechas inválidas' });

  // Detect conflicts
  const conflict = db.prepare(`
    SELECT id FROM reservations
    WHERE NOT (checkout <= ? OR checkin >= ?)
  `).get(checkin, checkout);
  if (conflict) return res.status(409).json({ error: 'Ya existe una reserva en esas fechas' });

  const result = db.prepare(
    'INSERT INTO reservations (user_id, username, checkin, checkout, notes) VALUES (?, ?, ?, ?, ?)'
  ).run(req.session.user.id, req.session.user.username, checkin, checkout, notes || '');

  // Notify cleaning person
  const cfg = getConfig();
  const msg = `🏠 Nueva reserva en el departamento:\n👤 ${req.session.user.username}\n📅 Entrada: ${formatDate(checkin)}\n📅 Salida: ${formatDate(checkout)}\n${notes ? '📝 ' + notes : ''}`;
  const waResult = await sendWhatsApp(cfg.cleaning_phone, cfg.cleaning_apikey, msg);

  if (waResult.ok) {
    db.prepare('UPDATE reservations SET notified = 1 WHERE id = ?').run(result.lastInsertRowid);
  }

  res.json({ ok: true, id: result.lastInsertRowid, notified: waResult.ok });
});

app.put('/api/reservations/:id', requireAdmin, async (req, res) => {
  const { checkin, checkout, notes, user_id } = req.body;
  if (!checkin || !checkout || checkin >= checkout)
    return res.status(400).json({ error: 'Fechas inválidas' });

  const assignee = db.prepare('SELECT id, username FROM users WHERE id = ?').get(user_id);
  if (!assignee) return res.status(400).json({ error: 'Usuario no encontrado' });

  const conflict = db.prepare(`
    SELECT id FROM reservations
    WHERE NOT (checkout <= ? OR checkin >= ?) AND id != ?
  `).get(checkin, checkout, req.params.id);
  if (conflict) return res.status(409).json({ error: 'Ya existe una reserva en esas fechas' });

  db.prepare(`UPDATE reservations SET checkin=?, checkout=?, notes=?, user_id=?, username=?, notified=0 WHERE id=?`)
    .run(checkin, checkout, notes || '', assignee.id, assignee.username, req.params.id);

  const cfg = getConfig();
  const msg = `✏️ Reserva actualizada en el departamento:\n👤 ${assignee.username}\n📅 Entrada: ${formatDate(checkin)}\n📅 Salida: ${formatDate(checkout)}\n${notes ? '📝 ' + notes : ''}`;
  const waResult = await sendWhatsApp(cfg.cleaning_phone, cfg.cleaning_apikey, msg);
  if (waResult.ok) db.prepare('UPDATE reservations SET notified=1 WHERE id=?').run(req.params.id);

  res.json({ ok: true, notified: waResult.ok });
});

app.delete('/api/reservations/:id', requireAuth, (req, res) => {
  const row = db.prepare('SELECT * FROM reservations WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'No encontrada' });
  if (row.user_id !== req.session.user.id && req.session.user.role !== 'admin')
    return res.status(403).json({ error: 'Sin permiso' });
  db.prepare('DELETE FROM reservations WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ─── Admin Routes ─────────────────────────────────────────────────────────────
app.get('/api/admin/config', requireAdmin, (req, res) => {
  res.json(getConfig());
});

app.post('/api/admin/config', requireAdmin, (req, res) => {
  const allowed = ['cleaning_phone', 'cleaning_apikey', 'cleaning_name', 'apartment_name'];
  const upsert = db.prepare('INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value');
  for (const key of allowed) {
    if (req.body[key] !== undefined) upsert.run(key, req.body[key]);
  }
  res.json({ ok: true });
});

app.get('/api/admin/users', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT id, username, role FROM users').all();
  res.json(rows);
});

app.post('/api/admin/users/:id/password', requireAdmin, (req, res) => {
  const { password } = req.body;
  if (!password || password.length < 4) return res.status(400).json({ error: 'Contraseña muy corta' });
  db.prepare('UPDATE users SET password = ? WHERE id = ?').run(bcrypt.hashSync(password, 10), req.params.id);
  res.json({ ok: true });
});

app.post('/api/admin/users', requireAdmin, (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Datos incompletos' });
  try {
    db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)').run(username, bcrypt.hashSync(password, 10), role || 'guest');
    res.json({ ok: true });
  } catch (e) {
    res.status(409).json({ error: 'Usuario ya existe' });
  }
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  if (id === req.session.user.id) return res.status(400).json({ error: 'No puedes eliminarte a ti mismo' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
  db.prepare("UPDATE reservations SET user_id = NULL, username = '(eliminado)' WHERE user_id = ?").run(id);
  db.prepare('DELETE FROM users WHERE id = ?').run(id);
  res.json({ ok: true });
});

app.post('/api/admin/test-whatsapp', requireAdmin, async (req, res) => {
  const cfg = getConfig();
  const result = await sendWhatsApp(cfg.cleaning_phone, cfg.cleaning_apikey, '✅ Prueba de conexión desde la app del departamento. ¡Funciona!');
  res.json(result);
});

// ─── Serve SPA ────────────────────────────────────────────────────────────────
app.get('/{*path}', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`App corriendo en http://localhost:${PORT}`));
