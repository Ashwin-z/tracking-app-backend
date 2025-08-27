// backend/server.js
// Env-ready Express API for car-tracker + Traccar forwarder

try { require('dotenv').config(); } catch (_) {}

const express  = require('express');
const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');
const cors     = require('cors');

const app = express();

/* ---------- ENV ---------- */
const PORT              = process.env.PORT || 3000;
const MONGO_URL         = process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/carTrackerDB';
const CORS_ORIGIN       = process.env.CORS_ORIGIN || '*';
const NODE_ENV          = process.env.NODE_ENV || 'development';
const TRACCAR_SECRET    = process.env.TRACCAR_FORWARD_SECRET || ''; // REQUIRED in production
const TRACCAR_IPS       = (process.env.TRACCAR_IPS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

// NEW: Traccar API creds (for live device.status + name)
const TRACCAR_BASE_URL  = (process.env.TRACCAR_BASE_URL || '').replace(/\/+$/, '');
const TRACCAR_USER      = process.env.TRACCAR_USER || '';
const TRACCAR_PASS      = process.env.TRACCAR_PASS || '';

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

mongoose.connection.on('disconnected', () =>
  console.warn('MongoDB disconnected')
);

/* ---------- MODELS ---------- */
// Users
const userSchema = new mongoose.Schema(
  {
    name:      { type: String, required: true },
    email:     { type: String, required: true, unique: true, index: true },
    password:  { type: String, required: true },
    fuelPrice: { type: Number, default: 0 },
  },
  { timestamps: true }
);
const User = mongoose.model('User', userSchema);

// Positions
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

// Events
const eventSchema = new mongoose.Schema(
  {
    deviceId: { type: Number, index: true },
    type: String,
    eventTime: Date,
    positionId: Number,
    attributes: mongoose.Schema.Types.Mixed,
    raw: mongoose.Schema.Types.Mixed,
  },
  { timestamps: true, strict: false }
);
eventSchema.index({ deviceId: 1, eventTime: -1, createdAt: -1 });
const Event = mongoose.model('Event', eventSchema);

/* ---------- HELPERS ---------- */
const sanitizeUser = u => ({
  name: u.name,
  email: u.email,
  fuelPrice: u.fuelPrice ?? 0,
});

function clientIp(req) {
  const xf = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return xf || req.ip || req.connection?.remoteAddress || '';
}
function ensureNumber(n) {
  if (n === null || n === undefined || n === '') return undefined;
  const x = Number(n);
  return Number.isNaN(x) ? undefined : x;
}
function toDate(v) {
  if (!v) return undefined;
  const d = new Date(v);
  return isNaN(d.getTime()) ? undefined : d;
}

/* ============ NEW: Traccar API proxy + geocoder ============ */

// build Basic Auth once
function traccarAuthHeader() {
  return 'Basic ' + Buffer.from(`${TRACCAR_USER}:${TRACCAR_PASS}`).toString('base64');
}

/**
 * GET /proxy/traccar/devices
 * Returns [{ id, uniqueId, name, status }]
 * Uses your VPS Traccar API (80.190.80.82/api)
 */
app.get('/proxy/traccar/devices', async (req, res) => {
  try {
    if (!TRACCAR_BASE_URL || !TRACCAR_USER) {
      return res.json({ ok: false, error: 'not-configured', data: [] });
    }
    const r = await fetch(`${TRACCAR_BASE_URL}/devices`, {
      headers: {
        Authorization: traccarAuthHeader(),
        Accept: 'application/json',
      },
    });
    if (!r.ok) {
      const text = await r.text().catch(() => '');
      console.error('Traccar /devices failed', r.status, text);
      return res.status(502).json({ ok: false });
    }
    const data = await r.json();
    const out = (Array.isArray(data) ? data : []).map(d => ({
      id: d.id, uniqueId: d.uniqueId, name: d.name, status: (d.status || '').toLowerCase(),
    }));
    res.json({ ok: true, count: out.length, data: out });
  } catch (e) {
    console.error('proxy devices error:', e);
    res.status(500).json({ ok: false });
  }
});

// very small in-memory cache for geocode
const _geoCache = new Map(); // key -> { label, ts }
function _addrShort(json) {
  const a = json?.address || {};
  const city = a.city || a.town || a.village || a.hamlet || a.suburb || a.neighbourhood;
  const region = a.state || a.county || a.state_district || a.region || a.province;
  const cc = (a.country_code || '').toUpperCase();
  if (city && region && cc) return `${city}, ${region}, ${cc}`;
  if (city && region) return `${city}, ${region}`;
  if (city && cc) return `${city}, ${cc}`;
  if (region && cc) return `${region}, ${cc}`;
  return json?.display_name || null;
}

/**
 * GET /geocode?lat=..&lon=..
 * Returns { ok: true, label: "Latifabad, Sindh, PK" }
 */
app.get('/geocode', async (req, res) => {
  const lat = Number(req.query.lat), lon = Number(req.query.lon);
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
    return res.status(400).json({ ok: false, error: 'bad-params' });
  }
  const key = `${lat.toFixed(4)}:${lon.toFixed(4)}`;
  const cached = _geoCache.get(key);
  const now = Date.now();
  if (cached && (now - cached.ts < 1000 * 60 * 60 * 24 * 7)) { // 7 days
    return res.json({ ok: true, label: cached.label, cached: true });
  }
  try {
    const url = `https://nominatim.openstreetmap.org/reverse?format=json&lat=${encodeURIComponent(lat)}&lon=${encodeURIComponent(lon)}&addressdetails=1`;
    const r = await fetch(url, {
      headers: {
        'User-Agent': 'CarTrackerApp/1.0 (admin@example.com)',
        'Accept-Language': 'en',
      },
    });
    const j = await r.json();
    const label = _addrShort(j) || `${lat.toFixed(5)}, ${lon.toFixed(5)}`;
    _geoCache.set(key, { label, ts: now });
    if (_geoCache.size > 400) _geoCache.delete(_geoCache.keys().next().value);
    res.json({ ok: true, label });
  } catch {
    res.json({ ok: true, label: `${lat.toFixed(5)}, ${lon.toFixed(5)}` });
  }
});

/* -------------------- HEALTH -------------------- */
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'Server is running',
    env: NODE_ENV,
    mongo: mongoose.connection.readyState === 1 ? 'connected' : 'not-connected',
  });
});

/* ---------- AUTH / PROFILE ---------- */
app.post('/register', async (req, res) => {
  console.log('POST /register', req.body?.email);
  const { name, email, password } = req.body || {};
  if (!name || !email || !password)
    return res.status(400).json({ message: 'Please fill in all fields' });

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ message: 'Email already exists' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = await User.create({ name, email, password: hashedPassword });
    res.status(201).json({
      message: `Welcome ${name}! Account created successfully.`,
      ...sanitizeUser(newUser),
    });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/login', async (req, res) => {
  console.log('POST /login', req.body?.email);
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ message: 'Please fill in all fields' });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid email or password' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid email or password' });

    res.status(200).json({
      message: 'Logged in successfully',
      userName: user.name,
      email: user.email,
      fuelPrice: user.fuelPrice ?? 0,
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/user', async (req, res) => {
  const { email } = req.query;
  if (!email) return res.status(400).json({ message: 'Email is required' });
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(sanitizeUser(user));
  } catch (err) {
    console.error('GET /user error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/user/change-email', async (req, res) => {
  console.log('POST /user/change-email', req.body?.currentEmail);
  const { currentEmail, password, newEmail } = req.body || {};
  if (!currentEmail || !password || !newEmail)
    return res.status(400).json({ message: 'currentEmail, password and newEmail are required' });

  try {
    const user = await User.findOne({ email: currentEmail });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ message: 'Incorrect password' });

    if (currentEmail === newEmail)
      return res.status(400).json({ message: 'New email is the same as current' });

    const exists = await User.findOne({ email: newEmail });
    if (exists) return res.status(400).json({ message: 'New email already in use' });

    user.email = newEmail;
    await user.save();

    res.json({ message: 'Email updated', email: user.email });
  } catch (err) {
    console.error('change-email error:', err);
    if (err?.code === 11000)
      return res.status(400).json({ message: 'Email already in use' });
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/user/change-password', async (req, res) => {
  console.log('POST /user/change-password', req.body?.email);
  const { email, currentPassword, newPassword } = req.body || {};
  if (!email || !currentPassword || !newPassword)
    return res.status(400).json({ message: 'email, currentPassword and newPassword are required' });

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const ok = await bcrypt.compare(currentPassword, user.password);
    if (!ok) return res.status(400).json({ message: 'Incorrect current password' });

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();

    res.json({ message: 'Password updated' });
  } catch (err) {
    console.error('change-password error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/user/fuel-price', async (req, res) => {
  console.log('POST /user/fuel-price', req.body?.email, req.body?.fuelPrice);
  const { email, fuelPrice } = req.body || {};
  if (!email || typeof fuelPrice !== 'number')
    return res.status(400).json({ message: 'email and numeric fuelPrice are required' });

  try {
    const user = await User.findOneAndUpdate(
      { email },
      { $set: { fuelPrice } },
      { new: true }
    );
    if (!user) return res.status(404).json({ message: 'User not found' });

    res.json({ message: 'Fuel price saved', fuelPrice: user.fuelPrice });
  } catch (err) {
    console.error('fuel-price error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

/* ---------- TRACCAR FORWARDER ---------- */
app.post('/traccar/forward', async (req, res) => {
  try {
    // 1) Secret check
    const given =
      req.query.secret ||
      req.headers['x-traccar-secret'] ||
      req.headers['x-forward-secret'];

    if (!TRACCAR_SECRET || given !== TRACCAR_SECRET) {
      return res.status(401).json({ ok: false, error: 'bad-secret' });
    }

    // 2) Optional IP allow list
    if (TRACCAR_IPS.length) {
      const ip = clientIp(req);
      const allowed = TRACCAR_IPS.includes(ip);
      if (!allowed) return res.status(403).json({ ok: false, error: 'ip-not-allowed', ip });
    }

    // 3) Normalize payload
    const payload = req.body;
    const items = Array.isArray(payload) ? payload : [payload];

    const positions = [];
    const events = [];

    for (const it of items) {
      if (!it || typeof it !== 'object') continue;

      // Event forward payload format
      if (it.event) {
        const ev = it.event || {};
        const pos = it.position || {};
        events.push({
          deviceId: ensureNumber(ev.deviceId ?? pos.deviceId ?? it.deviceId),
          type: ev.type,
          eventTime: toDate(ev.eventTime ?? ev.serverTime ?? pos.serverTime),
          positionId: ensureNumber(ev.positionId),
          attributes: ev.attributes || {},
          raw: it,
        });

        if (pos && (pos.latitude !== undefined && pos.longitude !== undefined)) {
          positions.push({
            ...pos,
            fixTime: pos.fixTime || pos.deviceTime || pos.serverTime || new Date().toISOString(),
          });
        }
        continue;
      }

      // Position-only payload
      const pos = it.position || it;
      if (pos && pos.latitude !== undefined && pos.longitude !== undefined) {
        positions.push({
          ...pos,
          fixTime: pos.fixTime || pos.deviceTime || pos.serverTime || new Date().toISOString(),
        });
      }
    }

    // Debug: log brief sample
    const now = new Date().toISOString();
    const sample = positions[0] || (events[0]?.position) || null;
    console.log(
      `[TRACCAR] ${now} recv: pos=${positions.length} evt=${events.length}` +
      (sample
        ? ` dev=${sample.deviceId ?? 'n/a'} lat=${sample.latitude ?? 'n/a'} lon=${sample.longitude ?? 'n/a'}`
        : '')
    );

    // 4) Save to DB
    let savedPos = 0;
    let savedEvt = 0;

    if (positions.length) {
      const docs = positions.map(p => ({
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
        address: p.address,
        attributes: p.attributes || {},
        raw: p,
      }));
      const resIns = await Position.insertMany(docs, { ordered: false });
      savedPos = resIns.length;
    }

    if (events.length) {
      const resEvt = await Event.insertMany(events, { ordered: false });
      savedEvt = resEvt.length;
    }

    if (savedPos || savedEvt) {
      console.log(`[TRACCAR] saved: pos=${savedPos} evt=${savedEvt}`);
    }

    return res.json({ ok: true, positions: savedPos, events: savedEvt });
  } catch (e) {
    console.error('traccar/forward error:', e);
    return res.status(500).json({ ok: false });
  }
});

/* ---------- SIMPLE READ APIS FOR APP ---------- */
app.get('/positions/latest', async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || '20', 10), 200);
    const deviceId = req.query.deviceId ? Number(req.query.deviceId) : undefined;
    const q = deviceId ? { deviceId } : {};
    const docs = await Position.find(q).sort({ fixTime: -1, createdAt: -1 }).limit(limit);
    res.json(docs); // raw array (your RN code expects it)
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
    res.json(docs);
  } catch (e) {
    console.error('GET /events/latest error:', e);
    res.status(500).json({ ok: false });
  }
});

/* ---------- 404 & 500 ---------- */
app.use((req, res) => {
  res.status(404).json({ message: `Not found: ${req.method} ${req.originalUrl}` });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Server error' });
});

/* ---------- START ---------- */
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} [${NODE_ENV}]`);
  console.log(`Mongo URL: ${MONGO_URL.includes('mongodb') ? 'atlas/local' : 'local'} (hidden)`);
  if (!TRACCAR_SECRET) {
    console.warn('⚠️  TRACCAR_FORWARD_SECRET is not set — /traccar/forward will reject all posts.');
  }
  if (!TRACCAR_BASE_URL) {
    console.warn('ℹ️  TRACCAR_BASE_URL not set — /proxy/traccar/devices will return not-configured.');
  }
});
