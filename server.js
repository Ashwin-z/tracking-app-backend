// backend/server.js
// Express API for car-tracker + Traccar forwarder + live tail + per-device latest
try { require('dotenv').config(); } catch (_) {}

const express  = require('express');
const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');
const cors     = require('cors');

const app = express();

/* ---------- ENV ---------- */
const PORT        = process.env.PORT || 3000;
const MONGO_URL   = process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/carTrackerDB';
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const NODE_ENV    = process.env.NODE_ENV || 'development';

const TRACCAR_SECRET = process.env.TRACCAR_FORWARD_SECRET || '';
const TRACCAR_IPS    = (process.env.TRACCAR_IPS || '').split(',').map(s => s.trim()).filter(Boolean);

// hide fake devices & test data
const IGNORE_DEVICE_IDS = new Set(
  (process.env.IGNORE_DEVICE_IDS || '')
    .split(',').map(s => s.trim()).filter(Boolean)
    .map(n => Number(n)).filter(n => Number.isFinite(n))
);

// live tail (for Render logs)
const ENABLE_RENDER_TAIL = (process.env.ENABLE_RENDER_TAIL || 'false').toLowerCase() === 'true';
const TAIL_EVERY_MS      = Number(process.env.TAIL_EVERY_MS || 10000);

// admin purge
const ADMIN_PURGE_SECRET = process.env.ADMIN_PURGE_SECRET || '';

/* ---------- FALLBACK GEOCODER (only if Traccar omitted address) ---------- */
const USE_FALLBACK_GEOCODER = (process.env.FALLBACK_GEOCODER || 'true').toLowerCase() === 'true';
const GEOCODER_BASE   = process.env.GEOCODER_BASE || 'https://nominatim.openstreetmap.org';
const GEOCODER_LANG   = process.env.GEOCODER_LANG || 'en';
const GEOCODER_EMAIL  = process.env.GEOCODER_EMAIL || 'girachashwin048@gmail.com';

const hasGlobalFetch = typeof fetch === 'function';
async function httpGetJson(url, timeoutMs = 4500) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await (hasGlobalFetch ? fetch : (await import('node-fetch')).default)(url, {
      headers: {
        'User-Agent': `car-tracker/1.0 (${GEOCODER_EMAIL})`,
        'Accept': 'application/json'
      },
      signal: controller.signal
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } finally { clearTimeout(t); }
}

// tiny cache
const geoCache = new Map();
const GEO_TTL_MS = 6 * 60 * 60 * 1000; // 6h
const geoKey = (lat, lon) => `${Number(lat).toFixed(3)},${Number(lon).toFixed(3)}`;

// Build a short area string: e.g. "Latifabad, Sindh, PK"
function composeAreaFromAddress(a = {}) {
  // locality preference
  const locality =
    a.neighbourhood || a.neighborhood ||
    a.suburb ||
    a.city_district ||
    a.town || a.village ||
    a.city || a.county;

  // admin/state fallback chain
  const admin =
    a.state || a.province || a.region || a.state_district || a.county;

  const cc = (a.country_code || '').toUpperCase();

  const parts = [];
  if (locality) parts.push(locality);
  if (admin) parts.push(admin);
  if (cc) parts.push(cc);
  return parts.join(', ');
}

async function reverseGeocodeShort(lat, lon) {
  if (!Number.isFinite(lat) || !Number.isFinite(lon) || (lat === 0 && lon === 0)) return '';
  const key = geoKey(lat, lon);
  const now = Date.now();
  const cached = geoCache.get(key);
  if (cached && now - cached.t < GEO_TTL_MS) return cached.v;

  const url =
    `${GEOCODER_BASE}/reverse?format=jsonv2&lat=${encodeURIComponent(lat)}&lon=${encodeURIComponent(lon)}` +
    `&zoom=13&addressdetails=1&accept-language=${GEOCODER_LANG}&email=${encodeURIComponent(GEOCODER_EMAIL)}`;

  try {
    const j = await httpGetJson(url, 4500);
    const area = composeAreaFromAddress(j?.address);
    const val = area || j?.display_name || `${Number(lat).toFixed(5)}, ${Number(lon).toFixed(5)}`;
    geoCache.set(key, { v: val, t: now });
    if (geoCache.size > 2000) geoCache.clear();
    return val;
  } catch {
    return `${Number(lat).toFixed(5)}, ${Number(lon).toFixed(5)}`;
  }
}

/* ---------- MIDDLEWARE ---------- */
app.set('trust proxy', 1);
app.use(express.json({ limit: '5mb' }));

const corsOptions = {
  origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN.split(',').map(s => s.trim()),
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

/* ---------- MONGODB ---------- */
mongoose.set('strictQuery', true);
mongoose
  .connect(MONGO_URL, { serverSelectionTimeoutMS: 8000 })
  .then(() => console.log('MongoDB connected successfully'))
  .catch(err => console.error('MongoDB connection error:', err.message));

mongoose.connection.on('disconnected', () => console.warn('MongoDB disconnected'));

/* ---------- MODELS ---------- */
const userSchema = new mongoose.Schema(
  { name: String, email: { type: String, unique: true, index: true }, password: String, fuelPrice: { type: Number, default: 0 } },
  { timestamps: true }
);
const User = mongoose.model('User', userSchema);

const positionSchema = new mongoose.Schema(
  {
    deviceId: { type: Number, index: true },
    protocol: String,
    serverTime: Date,
    deviceTime: Date,
    fixTime:    { type: Date, index: true },
    valid: Boolean,
    latitude: Number,
    longitude: Number,
    altitude: Number,
    speed: Number,
    course: Number,
    accuracy: Number,
    address: String,
    attributes: mongoose.Schema.Types.Mixed,
    raw: mongoose.Schema.Types.Mixed,
  },
  { timestamps: true, strict: false }
);
positionSchema.index({ deviceId: 1, fixTime: -1, createdAt: -1 });
const Position = mongoose.model('Position', positionSchema);

const eventSchema = new mongoose.Schema(
  { deviceId: { type: Number, index: true }, type: String, eventTime: Date, positionId: Number, attributes: mongoose.Schema.Types.Mixed, raw: mongoose.Schema.Types.Mixed },
  { timestamps: true, strict: false }
);
eventSchema.index({ deviceId: 1, eventTime: -1, createdAt: -1 });
const Event = mongoose.model('Event', eventSchema);

/* ---------- HELPERS ---------- */
const sanitizeUser = u => ({ name: u.name, email: u.email, fuelPrice: u.fuelPrice ?? 0 });

function clientIp(req) {
  const xf = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return xf || req.ip || req.connection?.remoteAddress || '';
}
function ensureNumber(n) { if (n === null || n === undefined || n === '') return undefined; const x = Number(n); return Number.isNaN(x) ? undefined : x; }
function toDate(v) { if (!v) return undefined; const d = new Date(v); return isNaN(d.getTime()) ? undefined : d; }

const SPEED_RUNNING_KMH = 3;
const truthy = (v) => v === true || v === 'true' || v === 1 || v === '1' || v === 'on' || v === 'ON';
const whenOf = (p) => toDate(p.fixTime || p.deviceTime || p.serverTime || p.createdAt) || new Date(0);
const minutesSince = (d) => (Date.now() - d.getTime()) / 60000;

const shortAddress = (line) => {
  if (!line) return '';
  // keep last 3 parts if string is long, and normalize country name to PK
  const parts = String(line).split(',').map(s => s.trim()).filter(Boolean);
  const s = parts.slice(-3).join(', ').replace(/Pakistan$/i, 'PK');
  return s || line;
};

const readIgnition = (attrs = {}, speed = 0, motion) => {
  const direct = attrs.ignition ?? attrs.acc ?? attrs.engine ?? attrs.Ignition ?? attrs.IGN;
  if (direct !== undefined) return truthy(direct);
  if (motion === true || Number(speed) > SPEED_RUNNING_KMH) return true;
  if (motion === false || Number(speed) <= SPEED_RUNNING_KMH) return false;
  return null;
};

// OFFLINE only for 0/0 (+ speed 0 or missing); else stopped/idle/running
function classifyForUI(pos) {
  const lat = Number(pos.latitude ?? 0);
  const lon = Number(pos.longitude ?? 0);
  const speed = Number(pos.speed ?? 0);
  const a = pos.attributes || {};
  const motion = a.motion;

  const noCoords = !Number.isFinite(lat) || !Number.isFinite(lon) || (lat === 0 && lon === 0);
  const noSpeed  = !Number.isFinite(speed) || speed === 0;

  if ((noCoords && noSpeed) || (lat === 0 && lon === 0 && speed === 0)) return 'offline';
  const ign = readIgnition(a, speed, motion);
  if (speed <= SPEED_RUNNING_KMH && motion !== true) return ign === true ? 'idle' : 'stopped';
  return 'running';
}

/* ---------- HEALTH ---------- */
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'Server is running', env: NODE_ENV, mongo: mongoose.connection.readyState === 1 ? 'connected' : 'not-connected' });
});

/* ---------- AUTH ---------- */
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ message: 'Please fill in all fields' });
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'Email already exists' });
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = await User.create({ name, email, password: hashedPassword });
    res.status(201).json({ message: `Welcome ${name}! Account created successfully.`, ...sanitizeUser(newUser) });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});
app.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ message: 'Please fill in all fields' });
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid email or password' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ message: 'Invalid email or password' });
    res.status(200).json({ message: 'Logged in successfully', userName: user.name, email: user.email, fuelPrice: user.fuelPrice ?? 0 });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

/* ---------- TRACCAR FORWARDER ---------- */
app.post('/traccar/forward', async (req, res) => {
  try {
    const given = req.query.secret || req.headers['x-traccar-secret'] || req.headers['x-forward-secret'];
    if (!TRACCAR_SECRET || given !== TRACCAR_SECRET) return res.status(401).json({ ok: false, error: 'bad-secret' });

    if (TRACCAR_IPS.length) {
      const ip = clientIp(req);
      const allowed = TRACCAR_IPS.includes(ip);
      if (!allowed) return res.status(403).json({ ok: false, error: 'ip-not-allowed', ip });
    }

    const payload = req.body;
    const items = Array.isArray(payload) ? payload : [payload];
    const positions = [];
    const events = [];

    for (const it of items) {
      if (!it || typeof it !== 'object') continue;

      if (it.event) {
        const ev = it.event || {};
        const pos = it.position || {};
        const deviceId = ensureNumber(ev.deviceId ?? pos.deviceId ?? it.deviceId);
        if (deviceId != null && IGNORE_DEVICE_IDS.has(deviceId)) continue;
        events.push({
          deviceId,
          type: ev.type,
          eventTime: toDate(ev.eventTime ?? ev.serverTime ?? pos.serverTime),
          positionId: ensureNumber(ev.positionId),
          attributes: ev.attributes || {},
          raw: it,
        });
        if (pos && pos.latitude !== undefined && pos.longitude !== undefined) {
          positions.push({ ...pos, deviceId, fixTime: pos.fixTime || pos.deviceTime || pos.serverTime || new Date().toISOString() });
        }
        continue;
      }

      const pos = it.position || it;
      const deviceId = ensureNumber(pos.deviceId ?? pos.device?.id ?? it.deviceId);
      if (deviceId != null && IGNORE_DEVICE_IDS.has(deviceId)) continue;
      if (pos && pos.latitude !== undefined && pos.longitude !== undefined) {
        positions.push({ ...pos, deviceId, fixTime: pos.fixTime || pos.deviceTime || pos.serverTime || new Date().toISOString() });
      }
    }

    // Build position docs
    let docs = positions.map(p => ({
      deviceId: ensureNumber(p.deviceId ?? p.device?.id),
      protocol: p.protocol,
      serverTime: toDate(p.serverTime),
      deviceTime: toDate(p.deviceTime),
      fixTime: toDate(p.fixTime) || new Date(),
      valid: !!p.valid,
      latitude: ensureNumber(p.latitude),
      longitude: ensureNumber(p.longitude),
      altitude: ensureNumber(p.altitude),
      speed: ensureNumber(p.speed),
      course: ensureNumber(p.course),
      accuracy: ensureNumber(p.accuracy),
      address: p.address, // may be missing
      attributes: p.attributes || {},
      raw: p,
    }));

    // Fallback geocode if address missing
    if (USE_FALLBACK_GEOCODER && docs.length) {
      for (const d of docs) {
        if ((!d.address || d.address === '') &&
            Number.isFinite(d.latitude) && Number.isFinite(d.longitude) &&
            !(d.latitude === 0 && d.longitude === 0)) {
          try { d.address = await reverseGeocodeShort(d.latitude, d.longitude); } catch {}
        }
      }
    }

    let savedPos = 0, savedEvt = 0;
    if (docs.length) {
      const resIns = await Position.insertMany(docs, { ordered: false });
      savedPos = resIns.length;
    }
    if (events.length) {
      const resEvt = await Event.insertMany(events, { ordered: false });
      savedEvt = resEvt.length;
    }

    const nowIso = new Date().toISOString();
    const s = docs[0];
    console.log(`[TRACCAR] ${nowIso} recv: pos=${docs.length} evt=${events.length}${s ? ` dev=${s.deviceId} lat=${s.latitude} lon=${s.longitude}` : ''}`);
    if (savedPos || savedEvt) console.log(`[TRACCAR] saved: pos=${savedPos} evt=${savedEvt}`);

    return res.json({ ok: true, positions: savedPos, events: savedEvt });
  } catch (e) {
    console.error('traccar/forward error:', e);
    return res.status(500).json({ ok: false });
  }
});

/* ---------- READ APIS ---------- */
app.get('/positions/latest', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || '20', 10), 200);
    const deviceId = req.query.deviceId ? Number(req.query.deviceId) : undefined;
    const q = deviceId ? { deviceId } : {};
    const docs = await Position.find(q).sort({ fixTime: -1, createdAt: -1 }).limit(limit);
    res.json(docs.filter(d => !IGNORE_DEVICE_IDS.has(Number(d.deviceId))));
  } catch (e) {
    console.error('GET /positions/latest error:', e);
    res.status(500).json({ ok: false });
  }
});

app.get('/events/latest', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || '20', 10), 200);
    const deviceId = req.query.deviceId ? Number(req.query.deviceId) : undefined;
    const q = deviceId ? { deviceId } : {};
    const docs = await Event.find(q).sort({ eventTime: -1, createdAt: -1 }).limit(limit);
    res.json(docs.filter(d => !IGNORE_DEVICE_IDS.has(Number(d.deviceId))));
  } catch (e) {
    console.error('GET /events/latest error:', e);
    res.status(500).json({ ok: false });
  }
});

// One-per-device, classified, with area + coords
app.get('/devices/latest', async (req, res) => {
  try {
    const docs = await Position.find({}).sort({ fixTime: -1, createdAt: -1 }).limit(800).lean();

    const latest = new Map();
    for (const p of docs) {
      const id = Number(p.deviceId ?? p.device?.id);
      if (!Number.isFinite(id) || IGNORE_DEVICE_IDS.has(id)) continue;
      const when = whenOf(p);
      const prev = latest.get(id);
      if (!prev || when > whenOf(prev)) latest.set(id, p);
    }

    const items = await Promise.all(
      Array.from(latest.values()).map(async (pos) => {
        const when = whenOf(pos);
        const speed = Number(pos.speed || 0);
        const status = classifyForUI(pos);
        const attrs = pos.attributes || {};
        const ign = readIgnition(attrs, speed, attrs.motion);
        const name = pos.raw?.device?.name || attrs.deviceName || `Device ${pos.deviceId}`;

        let addr = shortAddress(pos.address);
        if (!addr && USE_FALLBACK_GEOCODER &&
            Number.isFinite(pos.latitude) && Number.isFinite(pos.longitude) &&
            !(pos.latitude === 0 && pos.longitude === 0)) {
          try { addr = await reverseGeocodeShort(pos.latitude, pos.longitude); } catch {}
        }
        const coords = (Number(pos.latitude) || Number(pos.longitude))
          ? `${Number(pos.latitude).toFixed(5)}, ${Number(pos.longitude).toFixed(5)}`
          : '';

        return {
          deviceId: pos.deviceId,
          name,
          status,
          speed,
          ignition: ign === true,
          latitude: pos.latitude,
          longitude: pos.longitude,
          address: addr,                 // e.g. "Latifabad, Sindh, PK"
          coords,                        // "25.35037, 68.38416"
          addressLabel: addr && coords ? `${addr} | ${coords}` : (addr || coords),
          when,
          ageMinutes: Math.round(minutesSince(when) * 10) / 10,
        };
      })
    );

    res.json({ ok: true, count: items.length, data: items });
  } catch (e) {
    console.error('GET /devices/latest error:', e);
    res.status(500).json({ ok: false });
  }
});

/* ---------- ADMIN: purge ignored devices ---------- */
app.post('/admin/purge-ignored', async (req, res) => {
  try {
    if (!ADMIN_PURGE_SECRET) return res.status(403).json({ ok: false, error: 'disabled' });
    const given = req.query.secret || req.headers['x-admin-secret'];
    if (given !== ADMIN_PURGE_SECRET) return res.status(401).json({ ok: false, error: 'bad-secret' });
    const ids = Array.from(IGNORE_DEVICE_IDS);
    if (!ids.length) return res.json({ ok: true, message: 'no ignore ids set' });
    const p = await Position.deleteMany({ deviceId: { $in: ids } });
    const e = await Event.deleteMany({ deviceId: { $in: ids } });
    res.json({ ok: true, deleted: { positions: p.deletedCount || 0, events: e.deletedCount || 0 }, ids });
  } catch (err) {
    console.error('purge-ignored error:', err);
    res.status(500).json({ ok: false });
  }
});

/* ---------- 404 & 500 ---------- */
app.use((req, res) => res.status(404).json({ message: `Not found: ${req.method} ${req.originalUrl}` }));
app.use((err, req, res, next) => { console.error('Unhandled error:', err); res.status(500).json({ message: 'Server error' }); });

/* ---------- START ---------- */
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} [${NODE_ENV}]`);
  console.log(`Mongo URL: ${MONGO_URL.includes('mongodb') ? 'atlas/local' : 'local'} (hidden)`);
  if (!TRACCAR_SECRET) console.warn('⚠️  TRACCAR_FORWARD_SECRET is not set — /traccar/forward will reject all posts.');
  if (ENABLE_RENDER_TAIL) console.log(`🔭 Render live tail enabled (every ${TAIL_EVERY_MS}ms)`); else console.log('🔭 Render live tail disabled');
});

/* ---------- LIVE TAILER ---------- */
async function liveTailOnce() {
  try {
    const docs = await Position.find({}).sort({ fixTime: -1, createdAt: -1 }).limit(800).lean();
    const latest = new Map();
    for (const p of docs) {
      const id = Number(p.deviceId ?? p.device?.id);
      if (!Number.isFinite(id) || IGNORE_DEVICE_IDS.has(id)) continue;
      const when = whenOf(p);
      const prev = latest.get(id);
      if (!prev || when > whenOf(prev)) latest.set(id, p);
    }

    const now = new Date();
    const hh = String(now.getHours()).padStart(2,'0');
    const mm = String(now.getMinutes()).padStart(2,'0');
    const ss = String(now.getSeconds()).padStart(2,'0');
    console.log(`[${hh}:${mm}:${ss}] Devices: ${latest.size}`);

    for (const [, pos] of latest) {
      const status = classifyForUI(pos);
      const speed = Number(pos.speed || 0);
      let addr = shortAddress(pos.address);
      if (!addr && USE_FALLBACK_GEOCODER &&
          Number.isFinite(pos.latitude) && Number.isFinite(pos.longitude) &&
          !(pos.latitude === 0 && pos.longitude === 0)) {
        try { addr = await reverseGeocodeShort(pos.latitude, pos.longitude); } catch {}
      }
      const coords = (Number(pos.latitude) || Number(pos.longitude))
        ? `${Number(pos.latitude).toFixed(5)}, ${Number(pos.longitude).toFixed(5)}`
        : '—';
      const when = whenOf(pos);
      const name = pos.raw?.device?.name || pos.attributes?.deviceName || `Device ${pos.deviceId}`;
      console.log(` • ${name} | ${status.toUpperCase()} | ${speed} km/h | ${addr} | ${coords} | last ${when.toLocaleTimeString()}`);
    }
  } catch (e) {
    console.log('live-tail error:', e?.message || e);
  }
}
if (ENABLE_RENDER_TAIL) { setInterval(liveTailOnce, TAIL_EVERY_MS); liveTailOnce(); }
