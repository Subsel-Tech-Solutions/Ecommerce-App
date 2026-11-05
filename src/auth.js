const jwt = require('jsonwebtoken');
const { db } = require('./db');
const config = require('./config');

// Shoppers and the back office use separate cookies, so an admin login never
// shows up in the storefront (and a shopper session never unlocks /admin).
const COOKIE = 'session';
const ADMIN_COOKIE = 'admin_session';
const MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const cookieName = (role) => (role === 'admin' ? ADMIN_COOKIE : COOKIE);

function issueSession(res, user) {
  const token = jwt.sign({ uid: user.id, role: user.role }, config.jwtSecret, { expiresIn: '7d' });
  res.cookie(cookieName(user.role), token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: config.isProd,
    maxAge: MAX_AGE_MS,
    path: '/',
  });
}

function clearSession(res, role = 'customer') {
  res.clearCookie(cookieName(role), { path: '/' });
}

function readCookie(req, name) {
  const token = req.cookies?.[name];
  if (!token) return null;
  try {
    const { uid } = jwt.verify(token, config.jwtSecret);
    return db.prepare('SELECT id,name,email,phone,role FROM users WHERE id = ?').get(uid) || null;
  } catch { return null; } // expired or tampered: treat as guest
}

// Attaches req.user (shopper) and req.admin (back office) when valid cookies are present (never blocks).
function attachUser(req, _res, next) {
  const user = readCookie(req, COOKIE);
  if (user && user.role !== 'admin') req.user = user;
  const admin = readCookie(req, ADMIN_COOKIE);
  if (admin && admin.role === 'admin') req.admin = admin;
  next();
}

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Please log in to continue.' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.admin) return res.status(403).json({ error: 'Admin access only.' });
  next();
}

module.exports = { issueSession, clearSession, attachUser, requireAuth, requireAdmin };
