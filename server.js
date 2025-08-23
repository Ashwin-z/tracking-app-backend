// backend/server.js
// Env-ready Express API for car-tracker

// 1) Load env (local only—hosted platforms inject env themselves)
try { require('dotenv').config(); } catch (_) {}

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();

// ---- ENV ----
const PORT        = process.env.PORT || 3000;
const MONGO_URL   = process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/carTrackerDB';
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const NODE_ENV    = process.env.NODE_ENV || 'development';

// ---- Middleware ----
app.set('trust proxy', 1); // needed if behind a proxy (Render/Heroku)
app.use(express.json());   // replaces body-parser for JSON

const corsOptions = {
  origin:
    CORS_ORIGIN === '*'
      ? true // allow all (no credentials)
      : CORS_ORIGIN.split(',').map(s => s.trim()),
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions)); // preflight

// ---- MongoDB ----
mongoose.set('strictQuery', true);
mongoose
  .connect(MONGO_URL, {
    // modern mongoose doesn’t require useNewUrlParser/useUnifiedTopology
    serverSelectionTimeoutMS: 8000,
  })
  .then(() => console.log('MongoDB connected successfully'))
  .catch(err => {
    console.error('MongoDB connection error:', err.message);
    // don’t exit; app can still serve health/errors to aid debugging
  });

mongoose.connection.on('disconnected', () =>
  console.warn('MongoDB disconnected')
);

// ---- Models ----
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

// ---- Helpers ----
const sanitizeUser = u => ({
  name: u.name,
  email: u.email,
  fuelPrice: u.fuelPrice ?? 0,
});

// ---- Routes ----

// Health + meta
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'Server is running',
    env: NODE_ENV,
    mongo: mongoose.connection.readyState === 1 ? 'connected' : 'not-connected',
  });
});

// Registration
app.post('/register', async (req, res) => {
  console.log('POST /register', req.body?.email);
  const { name, email, password } = req.body || {};
  if (!name || !email || !password)
    return res.status(400).json({ message: 'Please fill in all fields' });

  try {
    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: 'Email already exists' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = await User.create({ name, email, password: hashedPassword });
    res
      .status(201)
      .json({ message: `Welcome ${name}! Account created successfully.`, ...sanitizeUser(newUser) });
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login
app.post('/login', async (req, res) => {
  console.log('POST /login', req.body?.email);
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ message: 'Please fill in all fields' });

  try {
    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ message: 'Invalid email or password' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(400).json({ message: 'Invalid email or password' });

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

// Fetch basic profile
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

// Change email (requires current password)
app.post('/user/change-email', async (req, res) => {
  console.log('POST /user/change-email', req.body?.currentEmail);
  const { currentEmail, password, newEmail } = req.body || {};
  if (!currentEmail || !password || !newEmail)
    return res
      .status(400)
      .json({ message: 'currentEmail, password and newEmail are required' });

  try {
    const user = await User.findOne({ email: currentEmail });
    if (!user) return res.status(404).json({ message: 'User not found' });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ message: 'Incorrect password' });

    if (currentEmail === newEmail)
      return res
        .status(400)
        .json({ message: 'New email is the same as current' });

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

// Change password
app.post('/user/change-password', async (req, res) => {
  console.log('POST /user/change-password', req.body?.email);
  const { email, currentPassword, newPassword } = req.body || {};
  if (!email || !currentPassword || !newPassword)
    return res
      .status(400)
      .json({ message: 'email, currentPassword and newPassword are required' });

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

// Set fuel price
app.post('/user/fuel-price', async (req, res) => {
  console.log('POST /user/fuel-price', req.body?.email, req.body?.fuelPrice);
  const { email, fuelPrice } = req.body || {};
  if (!email || typeof fuelPrice !== 'number')
    return res
      .status(400)
      .json({ message: 'email and numeric fuelPrice are required' });

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

// 404
app.use((req, res) => {
  res.status(404).json({ message: `Not found: ${req.method} ${req.originalUrl}` });
});

// 500
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Server error' });
});

// ---- Start ----
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT} [${NODE_ENV}]`);
  console.log(`Mongo URL: ${MONGO_URL.includes('mongodb') ? 'atlas/local' : 'local'} (hidden)`);
});
