const dns = require('dns');
dns.setServers(['8.8.8.8', '1.1.1.1']);
const express = require('express');
const multer = require('multer');
const QRCode = require('qrcode');
const { Client, LocalAuth } = require('whatsapp-web.js');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const logs = [];
function log(...a) {
  const line = `${new Date().toLocaleTimeString('en-GB', { timeZone: 'Asia/Kolkata' })}  ${a.join(' ')}`;
  logs.push(line); if (logs.length > 150) logs.shift();
  console.log(line);
}
const mb = n => Math.round(n / 1048576);
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 8 * 1024 * 1024 } });
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';

app.use(express.json({ limit: '1mb' }));

// ---------- Authentication (single shared password, signed cookie) ----------
let APP_PASSWORD = process.env.APP_PASSWORD || (() => { try { return require('./config').password; } catch { return ''; } })();
if (!APP_PASSWORD || APP_PASSWORD === 'change-this-password') {
  APP_PASSWORD = crypto.randomBytes(9).toString('base64url');
  console.log('\nPassword not set in config.js. Temporary password for this run: ' + APP_PASSWORD);
  console.log('Open config.js and replace change-this-password with your own.\n');
}
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_HOURS = Number(process.env.SESSION_HOURS || 12);
if (process.env.TRUST_PROXY) app.set('trust proxy', 1);
const sha = v => crypto.createHash('sha256').update(String(v)).digest();
const sign = v => crypto.createHmac('sha256', SESSION_SECRET).update(v).digest('base64url');
function makeToken() {
  const exp = String(Date.now() + SESSION_HOURS * 3600 * 1000);
  return `${exp}.${sign(exp)}`;
}
function validToken(t) {
  if (!t) return false;
  const [exp, sig] = String(t).split('.');
  if (!exp || !sig || sig.length !== sign(exp).length) return false;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(sign(exp)))) return false;
  return Number(exp) > Date.now();
}
function getCookie(req, name) {
  const m = String(req.headers.cookie || '').split(';').map(c => c.trim()).find(c => c.startsWith(name + '='));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : '';
}
const isAuthed = req => validToken(getCookie(req, 'bd_session'));
const attempts = new Map(); // ip -> { n, until }
function cookieFlags(req) {
  const secure = req.secure || process.env.COOKIE_SECURE === '1';
  return `Path=/; HttpOnly; SameSite=Strict${secure ? '; Secure' : ''}`;
}

app.get('/login', (req, res) => isAuthed(req) ? res.redirect('/') : res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.post('/api/login', (req, res) => {
  const ip = req.ip;
  const a = attempts.get(ip) || { n: 0, until: 0 };
  if (a.until > Date.now()) return res.status(429).json({ error: `Too many attempts. Try again in ${Math.ceil((a.until - Date.now()) / 1000)}s.` });
  const ok = crypto.timingSafeEqual(sha(req.body?.password ?? ''), sha(APP_PASSWORD));
  if (!ok) {
    a.n++; if (a.n >= 5) { a.until = Date.now() + 60_000; a.n = 0; }
    attempts.set(ip, a);
    return res.status(401).json({ error: 'Incorrect password.' });
  }
  attempts.delete(ip);
  res.setHeader('Set-Cookie', `bd_session=${encodeURIComponent(makeToken())}; Max-Age=${SESSION_HOURS * 3600}; ${cookieFlags(req)}`);
  res.json({ ok: true });
});
app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', `bd_session=; Max-Age=0; ${cookieFlags(req)}`);
  res.json({ ok: true });
});
// Everything below this line requires login.
app.use((req, res, next) => {
  if (isAuthed(req)) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Not logged in.' });
  res.redirect('/login');
});
app.use(express.static(path.join(__dirname, 'public')));

let client;
let waState = { status: 'starting', qrDataUrl: null, message: 'Starting WhatsApp Web session…' };
let sendBusy = false;
let lastOut = null; // last outgoing message seen by WhatsApp: { id, to, at } (we send one at a time)
const progress = { total: 0, done: 0, current: null };
const report = [];
const MAX_REPORT = 2000;

function addReport(entry) {
  report.push({ id: `${Date.now()}-${Math.random().toString(16).slice(2)}`, at: new Date().toISOString(), ...entry });
  if (report.length > MAX_REPORT) report.splice(0, report.length - MAX_REPORT);
}
function safeText(v, max = 4000) {
  return String(v ?? '').slice(0, max);
}
const DEFAULT_CC = (process.env.DEFAULT_COUNTRY_CODE || '91').replace(/\D/g, '');
function cleanPhone(v) {
  let d = String(v ?? '').replace(/\D/g, '').replace(/^00/, '');
  if (d.length === 11 && d[0] === '0') d = d.slice(1);       // 09876543210 -> 9876543210
  return d.length === 10 ? DEFAULT_CC + d : d;               // local 10-digit -> add country code
}
function normalizeContact(row, index) {
  const keys = {};
  for (const [k, v] of Object.entries(row || {})) keys[String(k).trim().toLowerCase().replace(/[\s_-]+/g, '')] = v;
  const name = keys.name || keys.fullname || keys.contactname || keys.customer || `Contact ${index + 1}`;
  const phone = cleanPhone(keys.phone || keys.phonenumber || keys.mobile || keys.whatsapp || keys.number || '');
  const consent = String(keys.optedin ?? keys.consent ?? keys.whatsappconsent ?? keys.permission ?? '').trim().toLowerCase();
  const optedIn = ['yes', 'y', 'true', '1', 'opted-in', 'optedin', 'consented'].includes(consent);
  return { id: `${Date.now()}-${index}-${phone}`, name: safeText(name, 150).trim(), phone, optedIn };
}
function parseCsv(text) {
  // Small CSV parser supporting quoted commas and escaped quotes.
  const rows = []; let row = [], cell = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { cell += '"'; i++; }
      else if (c === '"') quoted = false;
      else cell += c;
    } else {
      if (c === '"') quoted = true;
      else if (c === ',') { row.push(cell); cell = ''; }
      else if (c === '\n') { row.push(cell.replace(/\r$/, '')); rows.push(row); row = []; cell = ''; }
      else cell += c;
    }
  }
  if (cell.length || row.length) { row.push(cell.replace(/\r$/, '')); rows.push(row); }
  if (!rows.length) return [];
  // Numbers-only file (no header row): first cell of first row looks like a phone number.
  const firstRow = rows[0].map(v => String(v).trim());
  const looksLikeData = firstRow.some(v => cleanPhone(v).length >= 8 && /^[+\d\s().-]+$/.test(v));
  if (looksLikeData) {
    return rows.filter(r => r.some(v => String(v).trim())).map(r => {
      const phoneIdx = r.findIndex(v => cleanPhone(v).length >= 8 && /^[+\d\s().-]+$/.test(String(v).trim()));
      const nameIdx = r.findIndex((v, i) => i !== phoneIdx && String(v).trim());
      return { name: nameIdx >= 0 ? r[nameIdx] : '', phone: r[phoneIdx] ?? '', opted_in: '' };
    });
  }
  if (rows.length < 2) return [];
  const headers = rows.shift().map(h => h.trim());
  return rows.filter(r => r.some(v => String(v).trim())).map(r => Object.fromEntries(headers.map((h, i) => [h, r[i] ?? ''])));
}

// ---------- WhatsApp session (auto-reconnect + optional MongoDB session storage) ----------
const MONGODB_URI = process.env.MONGODB_URI || '';
const health = { storage: MONGODB_URI ? 'mongodb' : 'local-disk', reconnects: 0, startedAt: Date.now(), connectedAt: null, lastCheck: null, lastSessionSave: null };
let restarting = false, retryDelay = 5000, retryTimer = null, mongoReady = false;

async function buildAuth() {
  if (!MONGODB_URI) {
    return new LocalAuth({ clientId: 'broadcast-desk', ...(process.env.WA_DATA_PATH ? { dataPath: process.env.WA_DATA_PATH } : {}) });
  }
  const mongoose = require('mongoose');
  const { MongoStore } = require('wwebjs-mongo');
  const { RemoteAuth } = require('whatsapp-web.js');
  if (!mongoReady) {
    await mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 15000 });
    mongoReady = true;
    log('MongoDB connected — WhatsApp session is stored in the database.');
  }
  return new RemoteAuth({
    clientId: 'broadcast-desk',
    store: new MongoStore({ mongoose }),
    backupSyncIntervalMs: 60 * 1000,
    ...(process.env.WA_DATA_PATH ? { dataPath: process.env.WA_DATA_PATH } : {})
  });
}

function scheduleRestart(why) {
  if (retryTimer) return;
  const delay = retryDelay;
  retryDelay = Math.min(retryDelay * 2, 60000);
  waState = { status: 'reconnecting', qrDataUrl: null, message: `${why} Reconnecting in ${Math.round(delay / 1000)}s…` };
  retryTimer = setTimeout(async () => {
    retryTimer = null;
    health.reconnects++;
    try { if (client) await client.destroy(); } catch {}
    client = null;
    startWhatsApp();
  }, delay);
}

async function startWhatsApp() {
  let authStrategy;
  try { authStrategy = await buildAuth(); }
  catch (err) {
    log('Session storage error:', err.message);
    waState = { status: 'error', qrDataUrl: null, message: `Session storage error: ${safeText(err.message, 200)}` };
    return scheduleRestart('Session storage error.');
  }
  client = new Client({
    authStrategy,
    puppeteer: {
      headless: true,
      ...(process.env.CHROME_PATH ? { executablePath: process.env.CHROME_PATH } : {}),
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage', '--disable-gpu']
    },
    takeoverOnConflict: true,
    takeoverTimeoutMs: 0
  });
  const hooked = new WeakSet();
  const hook = () => {
    try {
      const br = client?.pupBrowser, pg = client?.pupPage;
      if (br && !hooked.has(br)) { hooked.add(br); br.on('disconnected', () => log('CHROME CLOSED/CRASHED (often out of memory). RSS now', mb(process.memoryUsage().rss), 'MB')); }
      if (pg && !hooked.has(pg)) { hooked.add(pg); pg.on('error', e => log('Chrome page crashed:', e.message)); pg.on('pageerror', e => log('Page error:', String(e.message || e).slice(0, 150))); }
    } catch {}
  };
  client.on('loading_screen', (pct, msg) => { hook(); log(`Loading WhatsApp Web ${pct}% ${msg || ''}`); });
  client.on('change_state', st => log('WhatsApp state:', st));
  client.on('qr', async qr => {
    hook(); log('QR code generated — waiting for scan');
    try {
      waState = { status: 'qr', qrDataUrl: await QRCode.toDataURL(qr), message: 'Scan this QR code with WhatsApp on your phone.' };
    } catch {
      waState = { status: 'error', qrDataUrl: null, message: 'Could not generate QR code.' };
    }
  });
  client.on('authenticated', () => {
    hook(); log('Authenticated (QR accepted)');
    waState = { status: 'connecting', qrDataUrl: null, message: 'Authenticated. Connecting…' };
  });
  client.on('remote_session_saved', () => { health.lastSessionSave = Date.now(); log('Session saved to MongoDB.'); });
  client.on('ready', () => {
    waState = { status: 'connected', qrDataUrl: null, message: 'WhatsApp Web session connected.' };
    health.connectedAt = Date.now(); retryDelay = 5000;
    log('WhatsApp client is READY. RSS', mb(process.memoryUsage().rss), 'MB');
  });
  client.on('auth_failure', msg => {
    log('AUTH FAILURE:', safeText(msg, 200));
    waState = { status: 'error', qrDataUrl: null, message: `Authentication failed: ${safeText(msg, 200)}` };
    scheduleRestart('Authentication failed.');
  });
  client.on('disconnected', reason => {
    log('WhatsApp DISCONNECTED:', safeText(reason, 100));
    health.connectedAt = null;
    scheduleRestart(`WhatsApp disconnected (${safeText(reason, 80)}).`);
  });
  // Live delivery status: 1 = sent to server, 2 = delivered, 3 = read, 4 = played
  // Outgoing messages as WhatsApp Web itself sees them (works even when the library's sendMessage return value breaks)
  client.on('message_create', msg => {
    if (!msg?.fromMe || !msg?.to || !msg?.id?.id) return;
    lastOut = { id: msg.id.id, to: msg.to, at: Date.now() };
    const phone = String(msg.to).split('@')[0];
    const late = report.find(r => r.phone === phone && !r.msgId && r.status === 'Sent');
    if (late) late.msgId = msg.id.id;
  });
  client.on('message_ack', (msg, ack) => {
    const id = msg?.id?.id;
    const entry = id && report.find(r => r.msgId === id);
    if (!entry || entry.status === 'Failed') return;
    const label = { 1: 'Sent', 2: 'Delivered', 3: 'Read', 4: 'Read' }[ack];
    if (label) { entry.status = label; entry.detail = `WhatsApp reports: ${label.toLowerCase()}.`; entry.at = new Date().toISOString(); }
  });
  client.initialize().catch(err => {
    log('INIT FAILED:', safeText(err.message, 300));
    waState = { status: 'error', qrDataUrl: null, message: `Could not initialize WhatsApp Web: ${safeText(err.message, 250)}` };
    scheduleRestart('Initialization failed.');
  });
}
startWhatsApp();

setInterval(() => log('Memory RSS', mb(process.memoryUsage().rss), 'MB, status', waState.status), 30000);
// Watchdog: every minute confirm the session is really alive; restart it if not.
setInterval(async () => {
  if (waState.status !== 'connected' || !client || sendBusy) return;
  try {
    const state = await Promise.race([client.getState(), new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 20000))]);
    health.lastCheck = Date.now();
    if (state !== 'CONNECTED') throw new Error(`state ${state}`);
  } catch (err) {
    log('Watchdog: session unhealthy —', err.message);
    scheduleRestart('Session stopped responding.');
  }
}, 60000);

app.get('/api/status', (_req, res) => res.json({
  status: waState.status,
  qrDataUrl: waState.qrDataUrl,
  message: waState.message,
  connected: waState.status === 'connected',
  mode: 'unofficial-whatsapp-web',
  health: { ...health, uptimeSec: Math.round((Date.now() - health.startedAt) / 1000) }
}));
app.get('/api/diag', (_req, res) => {
  const m = process.memoryUsage();
  res.json({
    status: waState.status, message: waState.message,
    rssMB: mb(m.rss), heapMB: mb(m.heapUsed), uptimeSec: Math.round(process.uptime()), node: process.version,
    mongoConfigured: !!MONGODB_URI, mongoConnected: mongoReady, sessionSecretSet: !!process.env.SESSION_SECRET,
    chromePath: process.env.CHROME_PATH || '(default)', logs: logs.slice(-80)
  });
});
app.post('/api/restart', (_req, res) => {
  if (sendBusy) return res.status(409).json({ error: 'A send batch is running. Wait until it finishes.' });
  clearTimeout(retryTimer); retryTimer = null; retryDelay = 1000;
  scheduleRestart('Manual restart.');
  res.json({ ok: true });
});

app.post('/api/contacts/import', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Choose a CSV file.' });
  if (!/\.(csv|txt)$/i.test(req.file.originalname)) return res.status(400).json({ error: 'Upload a .csv or .txt file. Export your Excel sheet as CSV first.' });
  const rows = parseCsv(req.file.buffer.toString('utf8').replace(/^\uFEFF/, ''));
  const seen = new Set();
  const contacts = rows.map(normalizeContact).filter(c => {
    if (!c.phone || seen.has(c.phone)) return false;
    seen.add(c.phone); return true;
  });
  res.json({ contacts, count: contacts.length, unverified: contacts.filter(c => !c.optedIn).length });
});

app.post('/api/send', async (req, res) => {
  if (sendBusy) return res.status(409).json({ error: 'A send batch is already running.' });
  if (waState.status !== 'connected' || !client) return res.status(409).json({ error: 'WhatsApp is not connected. Scan the QR code first.' });
  const { contacts, message, confirmed } = req.body || {};
  if (!confirmed) return res.status(400).json({ error: 'Explicit confirmation is required.' });
  if (!Array.isArray(contacts) || contacts.length < 1 || contacts.length > 200) return res.status(400).json({ error: 'Select between 1 and 200 contacts per batch.' });
  if (typeof message !== 'string' || !message.trim() || message.length > 4000) return res.status(400).json({ error: 'Message must be 1–4000 characters.' });
  const unique = new Set();
  for (const c of contacts) {
    const phone = cleanPhone(c.phone);
    if (phone.length < 8 || phone.length > 15 || unique.has(phone)) return res.status(400).json({ error: 'One or more phone numbers are invalid or duplicated.' });
    unique.add(phone);
  }
  sendBusy = true;
  progress.total = contacts.length; progress.done = 0; progress.current = null;
  res.json({ accepted: true, count: contacts.length, note: 'Batch accepted. Poll /api/report for per-recipient results.' });
  try {
    for (const contact of contacts) {
      const phone = cleanPhone(contact.phone);
      const name = safeText(contact.name || 'there', 150);
      const personalized = message.replace(/\{\{\s*name\s*\}\}/gi, name);
      progress.current = { name, phone };
      try {
        const numberId = await client.getNumberId(phone);
        if (!numberId) {
          addReport({ name, phone, status: 'Failed', detail: 'Number is not registered on WhatsApp.' });
          progress.done++; continue;
        }
        // sendSeen:false avoids the "markedUnread / Cannot read properties of undefined" crash
        // that newer WhatsApp Web builds trigger inside whatsapp-web.js.
        const startedAt = Date.now();
        let sent = null, libError = null;
        try {
          sent = await client.sendMessage(numberId._serialized, personalized, { sendSeen: false });
        } catch (e) {
          // Known whatsapp-web.js bug: the message is sent, but reading WhatsApp's confirmation throws
          // "Cannot read properties of undefined (reading 'id')". Verify via WhatsApp's own event instead.
          if (!/reading '(id|_serialized)'|undefined/i.test(String(e.message))) throw e;
          libError = e;
          for (let i = 0; i < 12; i++) {
            if (lastOut && lastOut.at >= startedAt - 500) break;
            await new Promise(r => setTimeout(r, 300));
          }
        }
        const seen = lastOut && lastOut.at >= startedAt - 500 ? lastOut : null;
        const confirmed = !!sent || !!seen;
        if (!confirmed) throw libError || new Error('WhatsApp did not confirm the message.');
        addReport({
          name, phone, status: 'Sent', msgId: sent?.id?.id || seen?.id,
          detail: libError ? 'Message sent (confirmed by WhatsApp). Delivery ticks will update if available.' : 'Message sent from your WhatsApp. Waiting for delivery confirmation…'
        });
        if (libError) log('Send OK for', phone, '(library error ignored:', safeText(libError.message, 80) + ')');
        // Conservative delay between messages; this is not a guarantee against account restrictions.
        await new Promise(resolve => setTimeout(resolve, 1800));
      } catch (err) {
        addReport({ name, phone, status: 'Failed', detail: safeText(err.message || 'Send failed', 250) });
        await new Promise(resolve => setTimeout(resolve, 800));
      }
      progress.done++;
    }
  } finally {
    sendBusy = false; progress.current = null;
  }
});

app.get('/api/report', (_req, res) => res.json({ sending: sendBusy, progress, report: report.slice(-500).reverse() }));
app.delete('/api/report', (_req, res) => { report.length = 0; res.json({ ok: true }); });

app.listen(PORT, HOST, () => {
  console.log(`Broadcast Desk available at http://${HOST}:${PORT}`);
  console.log('For local use only. Do not expose this unauthenticated app to the public internet.');
});

process.on('SIGINT', async () => {
  console.log('\nClosing WhatsApp session…');
  try { if (client) await client.destroy(); } catch {}
  process.exit(0);
});