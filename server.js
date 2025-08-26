// backend/server.js
// Env-ready Express API for car-tracker + Traccar forwarder

try { require('dotenv').config(); } catch (_) {}

const express  = require('express');
const mongoose = require('mongoose');
const bcrypt   = require('bcryptjs');
const cors     = require('cors');

const app = express();

/* ---------- ENV ---------- */
const PORT            = process.env.PORT || 3000;
const MONGO_URL       = process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/carTrackerDB';
const CORS_ORIGIN     = process.env.CORS_ORIGIN || '*';
const NODE_ENV        = process.env.NODE_ENV || 'development';
const TRACCAR_SECRET  = process.env.TRACCAR_FORWARD_SECRET || '';
const TRACCAR_IPS     = (process.env.TRACCAR_IPS || '').split(',').map(s => s.trim()).filter(Boolean);

/* ---------- MIDDLEWARE ---------- */
app.set('trust proxy', 1);
app.use(express.json({ limit: '5mb' })); 

app.use(cors({
  origin: CORS_ORIGIN === '*' ? true : CORS_ORIGIN.split(',').map(s => s.trim()),
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

/* ---------- MONGODB ---------- */
mongoose.set('strictQuery', true);
mongoose.connect(MONGO_URL, { serverSelectionTimeoutMS: 8000 })
  .then(() => console.log('✅ MongoDB connected'))
  .catch(err => console.error('❌ MongoDB connection error:', err.message));

/* ---------- MODELS ---------- */
// Users
const userSchema = new mongoose.Schema({
  name:      { type: String, required: true },
  email:     { type: String, required: true, unique: true, index: true },
  password:  { type: String, required: true },
  fuelPrice: { type: Number, default: 0 },
}, { timestamps: true });
const User = mongoose.model('User', userSchema);

// Positions
const positionSchema = new mongoose.Schema({
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
}, { timestamps: true });
positionSchema.index({ deviceId: 1, fixTime: -1 });
const Position = mongoose.model('Position', positionSchema);

// Events
const eventSchema = new mongoose.Schema({
  deviceId: { type: Number, index: true },
  type: String,
  eventTime: Date,
  positionId: Number,
  attributes: mongoose.Schema.Types.Mixed,
  raw: mongoose.Schema.Types.Mixed,
}, { timestamps: true });
eventSchema.index({ deviceId: 1, eventTime: -1 });
const Event = mongoose.model('Event', eventSchema);

/* ---------- HELPERS ---------- */
const sanitizeUser = u => ({
  name: u.name,
  email: u.email,
  fuelPrice: u.fuelPrice ?? 0,
});
function clientIp(req) {
  const xf = (req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return xf || req.ip || '';
}
function ensureNumber(n) {
  const x = Number(n); return Number.isNaN(x) ? undefined : x;
}
function toDate(v) {
  const d = new Date(v); return isNaN(d.getTime()) ? undefined : d;
}

/* ---------- ROUTES ---------- */
// Health
app.get('/health', (req, res) => {
  res.json({
    status: 'Server is running',
    env: NODE_ENV,
    mongo: mongoose.connection.readyState === 1 ? 'connected' : 'not-connected',
  });
});

// Registration
app.post('/register', async (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ message: 'Please fill in all fields' });
  try {
    if (await User.findOne({ email })) return res.status(400).json({ message: 'Email already exists' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({ name, email, password: hashedPassword });
    res.status(201).json({ message: `Welcome ${name}!`, ...sanitizeUser(newUser) });
  } catch (err) { res.status(500).json({ message: 'Server error' }); }
});

// Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid email or password' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ message: 'Invalid email or password' });
    res.json({ message: 'Logged in', userName: user.name, email: user.email, fuelPrice: user.fuelPrice ?? 0 });
  } catch { res.status(500).json({ message: 'Server error' }); }
});

// 🔥 Traccar Forward Endpoint
app.post('/traccar/forward', async (req, res) => {
  try {
    // secret check
    const given = req.query.secret || req.headers['x-traccar-secret'];
    if (given !== TRACCAR_SECRET) return res.status(401).json({ ok: false, error: 'bad-secret' });

    // optional IP restriction
    if (TRACCAR_IPS.length && !TRACCAR_IPS.includes(clientIp(req))) {
      return res.status(403).json({ ok: false, error: 'ip-not-allowed' });
    }

    const payload = Array.isArray(req.body) ? req.body : [req.body];
    const positions = [], events = [];

    for (const it of payload) {
      if (it.event) {
        events.push({
          deviceId: ensureNumber(it.event.deviceId),
          type: it.event.type,
          eventTime: toDate(it.event.eventTime),
          positionId: ensureNumber(it.event.positionId),
          attributes: it.event.attributes || {},
          raw: it,
        });
        if (it.position?.latitude) positions.push(it.position);
      } else if (it.latitude && it.longitude) {
        positions.push(it);
      }
    }

    if (positions.length) await Position.insertMany(positions.map(p => ({
      deviceId: ensureNumber(p.deviceId ?? p.device?.id),
      protocol: p.protocol,
      serverTime: toDate(p.serverTime),
      deviceTime: toDate(p.deviceTime),
      fixTime: toDate(p.fixTime),
      valid: !!p.valid,
      latitude: ensureNumber(p.latitude),
      longitude: ensureNumber(p.longitude),
      speed: ensureNumber(p.speed),
      address: p.address,
      attributes: p.attributes || {},
      raw: p,
    })), { ordered: false });

    if (events.length) await Event.insertMany(events, { ordered: false });

    res.json({ ok: true, positions: positions.length, events: events.length });
  } catch (e) {
    console.error('forward error:', e);
    res.status(500).json({ ok: false });
  }
});

// Latest position
app.get('/positions/latest', async (req, res) => {
  const deviceId = req.query.deviceId ? Number(req.query.deviceId) : undefined;
  const q = deviceId ? { deviceId } : {};
  const docs = await Position.find(q).sort({ fixTime: -1 }).limit(20);
  res.json(docs);
});

// Latest events
app.get('/events/latest', async (req, res) => {
  const docs = await Event.find({}).sort({ eventTime: -1 }).limit(20);
  res.json(docs);
});

/* ---------- ERROR HANDLERS ---------- */
app.use((req, res) => res.status(404).json({ message: `Not found: ${req.method} ${req.originalUrl}` }));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ message: 'Server error' }); });

/* ---------- START ---------- */
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT} [${NODE_ENV}]`);
  if (!TRACCAR_SECRET) console.warn('⚠️  TRACCAR_FORWARD_SECRET not set, will reject Traccar posts.');
});
