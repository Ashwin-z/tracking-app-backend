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
const TRACCAR_IPS    = (process.env.TRACCAR_IPS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

// Hide fake/test devices (defaults to 123 per your request)
const IGNORE_DEVICE_IDS = new Set(
  (process.env.IGNORE_DEVICE_IDS || '123')
    .split(',').map(s => s.trim()).filter(Boolean)
    .map(n => Number(n)).filter(n => Number.isFinite(n))
);

// Admin purge (optional)
const ADMIN_PURGE_SECRET = process.env.ADMIN_PURGE_SECRET || '';

// Live-tail toggles (for Render logs)
const ENABLE_RENDER_TAIL = (process.env.ENABLE_RENDER_TAIL || 'false').toLowerCase() === 'true';
const TAIL_EVERY_MS      = Number(process.env.TAIL_EVERY_MS || 10000);

/* ---- Movement / status tunables ---- */
const SPEED_RUNNING_KMH = 3;
const MOVED_MIN_METERS  = Number(process.env.MOVED_MIN_METERS || 50);
const ACTIVE_WINDOW_MIN = Number(process.env.ACTIVE_WINDOW_MIN || 10);
const FIX_PAIR_MAX_MIN  = Number(process.env.FIX_PAIR_MAX_MIN || 5);

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
  {
    name:      { type: String, required: true },
    email:     { type: String, required: true, unique: true, index: true },
    password:  { type: String, required: true },
    fuelPrice: { type: Number, default: 0 },
  },
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
const sanitizeUser = u => ({ name: u.name, email: u.email, fuelPrice: u.fuelPrice ?? 0 });

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
const whenOf = (p) => toDate(p.fixTime || p.deviceTime || p.serverTime || p.createdAt) || new Date(0);
const minutesSince = (d) => (Date.now() - d.getTime()) / 60000;
const truthy = (v) => v === true || v === 'true' || v === 1 || v === '1' || v === 'on' || v === 'ON';

const isValidCoords = (p) => {
  const lat = Number(p?.latitude), lon = Number(p?.longitude);
  return Number.isFinite(lat) && Number.isFinite(lon) && !(lat === 0 && lon === 0);
};
function haversine(lat1, lon1, lat2, lon2) {
  const R = 6371000, toRad = d => d * Math.PI / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2
          + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}
const readIgnition = (attrs = {}, speed = 0, motion) => {
  const direct = attrs.ignition ?? attrs.acc ?? attrs.engine ?? attrs.Ignition ?? attrs.IGN;
  if (direct !== undefined) return truthy(direct);
  if (motion === true || Number(speed) > SPEED_RUNNING_KMH) return true;
  if (motion === false || Number(speed) <= SPEED_RUNNING_KMH) return false;
  return null;
};

const shortAddress = (line) => {
  if (!line) return '';
  const parts = String(line).split(',').map(s => s.trim()).filter(Boolean);
  return parts.slice(-3).join(', ').replace(/Pakistan$/i, 'PK');
};

/* ---------- HEALTH ---------- */
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
  console.log('POST /login', req.body?.email);
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
    if (err?.code === 11000) return res.status(400).json({ message: 'Email already in use' });
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
    const user = await User.findOneAndUpdate({ email }, { $set: { fuelPrice } }, { new: true });
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
    const given = req.query.secret || req.headers['x-traccar-secret'] || req.headers['x-forward-secret'];
    if (!TRACCAR_SECRET || given !== TRACCAR_SECRET) return res.status(401).json({ ok: false, error: 'bad-secret' });

    if (TRACCAR_IPS.length) {
      const ip = clientIp(req);
      const allowed = TRACCAR_IPS.includes(ip);
      if (!allowed) return res.status(403).json({ ok: false, error: 'ip-not-allowed', ip });
    }

    const items = Array.isArray(req.body) ? req.body : [req.body];
    const positions = [];
    const events = [];

    for (const it of items) {
      if (!it || typeof it !== 'object') continue;

      if (it.event) {
        const ev  = it.event || {};
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
          positions.push({
            ...pos,
            deviceId,
            fixTime: pos.fixTime || pos.deviceTime || pos.serverTime || new Date().toISOString(),
          });
        }
        continue;
      }

      const pos = it.position || it;
      const deviceId = ensureNumber(pos.deviceId ?? pos.device?.id ?? it.deviceId);
      if (deviceId != null && IGNORE_DEVICE_IDS.has(deviceId)) continue;
      if (pos && pos.latitude !== undefined && pos.longitude !== undefined) {
        positions.push({
          ...pos,
          deviceId,
          fixTime: pos.fixTime || pos.deviceTime || pos.serverTime || new Date().toISOString(),
        });
      }
    }

    const nowIso = new Date().toISOString();
    const sample = positions[0] || null;
    console.log(`[TRACCAR] ${nowIso} recv: pos=${positions.length} evt=${events.length}` +
      (sample ? ` dev=${sample.deviceId ?? 'n/a'} lat=${sample.latitude ?? 'n/a'} lon=${sample.longitude ?? 'n/a'}` : ''));

    let savedPos = 0, savedEvt = 0;

    if (positions.length) {
      const docs = positions.map(p => ({
        deviceId: ensureNumber(p.deviceId ?? p.device?.id),
        protocol: p.protocol,
        serverTime: toDate(p.serverTime),
        deviceTime: toDate(p.deviceTime),
        fixTime:   toDate(p.fixTime) || new Date(),
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

    if (savedPos || savedEvt) console.log(`[TRACCAR] saved: pos=${savedPos} evt=${savedEvt}`);
    return res.json({ ok: true, positions: savedPos, events: savedEvt });
  } catch (e) {
    console.error('traccar/forward error:', e);
    return res.status(500).json({ ok: false });
  }
});

/* ---------- SIMPLE READ APIS ---------- */
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

/* ---------- One-per-device (already classified) ---------- */
app.get('/devices/latest', async (req, res) => {
  try {
    const docs = await Position.find({}).sort({ fixTime: -1, createdAt: -1 }).limit(1000).lean();

    // Build last & prev (best two) per device
    const pairs = new Map(); // id -> { last, prev }
    for (const p of docs) {
      const id = Number(p.deviceId ?? p.device?.id);
      if (!Number.isFinite(id) || IGNORE_DEVICE_IDS.has(id)) continue;
      const entry = pairs.get(id) || {};
      if (!entry.last || whenOf(p) > whenOf(entry.last)) {
        entry.prev = entry.last;
        entry.last = p;
      } else if (!entry.prev || whenOf(p) > whenOf(entry.prev)) {
        entry.prev = p;
      }
      pairs.set(id, entry);
    }

    const data = [];
    for (const [id, { last, prev }] of pairs) {
      if (!last) continue;

      // OFFLINE only when absolutely no usable data
      const noCoords = !isValidCoords(last);
      const speed = Number(last.speed || 0);
      const noSpeed  = !Number.isFinite(speed) || speed === 0;
      if ((noCoords && noSpeed) || (noCoords && !prev)) {
        data.push({
          deviceId: id,
          name: last.raw?.device?.name || last.attributes?.deviceName || `Device ${id}`,
          status: 'offline',
          speed: 0,
          ignition: false,
          latitude: last.latitude,
          longitude: last.longitude,
          address: '',
          when: whenOf(last),
          ageMinutes: Math.round(minutesSince(whenOf(last)) * 10) / 10,
        });
        continue;
      }

      // Movement gating (recency + displacement)
      const lastWhen = whenOf(last);
      const ageMin   = minutesSince(lastWhen);
      let movedMeters = 0, pairAgeMin = Infinity;
      if (prev && isValidCoords(prev) && isValidCoords(last)) {
        movedMeters = haversine(
          Number(prev.latitude), Number(prev.longitude),
          Number(last.latitude), Number(last.longitude)
        );
        pairAgeMin = Math.abs(lastWhen - whenOf(prev)) / 60000;
      }
      const movedOk = pairAgeMin <= FIX_PAIR_MAX_MIN && movedMeters >= MOVED_MIN_METERS;
      const motion  = (last.attributes || {}).motion;
      const ign     = readIgnition(last.attributes || {}, speed, motion);

      const moving = (ageMin <= ACTIVE_WINDOW_MIN) &&
                     (speed > SPEED_RUNNING_KMH || motion === true || movedOk);

      const status = moving ? 'running' : (ign === true ? 'idle' : 'stopped');

      const addr =
        shortAddress(last.address) ||
        (isValidCoords(last)
          ? `${Number(last.latitude).toFixed(5)}, ${Number(last.longitude).toFixed(5)}`
          : '');

      data.push({
        deviceId: id,
        name: last.raw?.device?.name || last.attributes?.deviceName || `Device ${id}`,
        status,
        speed,
        ignition: ign === true,
        latitude: last.latitude,
        longitude: last.longitude,
        address: addr,
        when: lastWhen,
        ageMinutes: Math.round(ageMin * 10) / 10,
      });
    }

    res.json({ ok: true, count: data.length, data });
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
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => { console.error('Unhandled error:', err); res.status(500).json({ message: 'Server error' }); });

/* ---------- START ---------- */
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} [${NODE_ENV}]`);
  console.log(`Mongo URL: ${MONGO_URL.includes('mongodb') ? 'atlas/local' : 'local'} (hidden)`);
  if (!TRACCAR_SECRET) console.warn('⚠️  TRACCAR_FORWARD_SECRET is not set — /traccar/forward will reject all posts.');
  if (ENABLE_RENDER_TAIL) console.log(`🔭 Render live tail enabled (every ${TAIL_EVERY_MS}ms)`); else console.log('🔭 Render live tail disabled (set ENABLE_RENDER_TAIL=true to enable)');
});

/* ---------- LIVE TAILER (logs ~every 10s on Render) ---------- */
async function liveTailOnce() {
  try {
    const docs = await Position.find({}).sort({ fixTime: -1, createdAt: -1 }).limit(1000).lean();

    // Build last & prev per device
    const pairs = new Map();
    for (const p of docs) {
      const id = Number(p.deviceId ?? p.device?.id);
      if (!Number.isFinite(id) || IGNORE_DEVICE_IDS.has(id)) continue;
      const entry = pairs.get(id) || {};
      if (!entry.last || whenOf(p) > whenOf(entry.last)) {
        entry.prev = entry.last;
        entry.last = p;
      } else if (!entry.prev || whenOf(p) > whenOf(entry.prev)) {
        entry.prev = p;
      }
      pairs.set(id, entry);
    }

    const now = new Date();
    const hh = String(now.getHours()).padStart(2,'0');
    const mm = String(now.getMinutes()).padStart(2,'0');
    const ss = String(now.getSeconds()).padStart(2,'0');
    console.log(`[${hh}:${mm}:${ss}] Devices: ${pairs.size}`);

    for (const [id, { last, prev }] of pairs) {
      const lastWhen = whenOf(last);
      const ageMin   = minutesSince(lastWhen);
      const speed    = Number(last.speed || 0);
      const attrs    = last.attributes || {};
      const motion   = attrs.motion;
      const ign      = readIgnition(attrs, speed, motion);

      let movedMeters = 0, pairAgeMin = Infinity;
      if (prev && isValidCoords(prev) && isValidCoords(last)) {
        movedMeters = haversine(
          Number(prev.latitude), Number(prev.longitude),
          Number(last.latitude), Number(last.longitude)
        );
        pairAgeMin = Math.abs(lastWhen - whenOf(prev)) / 60000;
      }
      const movedOk = pairAgeMin <= FIX_PAIR_MAX_MIN && movedMeters >= MOVED_MIN_METERS;

      // OFFLINE only for zero/missing
      const noCoords = !isValidCoords(last);
      const noSpeed  = !Number.isFinite(speed) || speed === 0;
      let status;
      if ((noCoords && noSpeed) || (noCoords && !prev)) status = 'OFFLINE';
      else {
        const moving = (ageMin <= ACTIVE_WINDOW_MIN) &&
                       (speed > SPEED_RUNNING_KMH || motion === true || movedOk);
        status = moving ? 'RUNNING' : (ign === true ? 'IDLE' : 'STOPPED');
      }

      const addr = shortAddress(last.address) ||
        (isValidCoords(last)
          ? `${Number(last.latitude).toFixed(5)}, ${Number(last.longitude).toFixed(5)}`
          : '—');

      const movedTxt = isFinite(movedMeters) && isFinite(pairAgeMin)
        ? ` | moved ${Math.round(movedMeters)}m / ${isFinite(pairAgeMin) ? pairAgeMin.toFixed(1) : '?'}m`
        : '';

      console.log(` • ${last.raw?.device?.name || attrs.deviceName || `Device ${id}`} | ${status} | ${speed} km/h | ${addr} | last ${lastWhen.toLocaleTimeString()}${movedTxt}`);
    }
  } catch (e) {
    console.log('live-tail error:', e?.message || e);
  }
}
if (ENABLE_RENDER_TAIL) {
  setInterval(liveTailOnce, TAIL_EVERY_MS);
  liveTailOnce();
}
