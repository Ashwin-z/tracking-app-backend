// scripts/live-tail-traccar.js
const axios = require('axios');

const TRACCAR_BASE_URL = process.env.TRACCAR_BASE_URL || 'http://80.190.80.82';
const TRACCAR_USER = process.env.TRACCAR_USER;
const TRACCAR_PASS = process.env.TRACCAR_PASS;

// thresholds (minutes)
const OFFLINE_MIN = Number(process.env.OFFLINE_MIN || 30);
const EXPIRED_MIN = Number(process.env.EXPIRED_MIN || 180);
const SPEED_RUNNING_KMH = 3;

// Nominatim reverse geocoder (fallback when Traccar address is empty)
const NOMINATIM_URL = process.env.NOMINATIM_URL || 'https://nominatim.openstreetmap.org/reverse';
const NOMINATIM_EMAIL = process.env.NOMINATIM_EMAIL || 'you@example.com'; // used in User-Agent per Nominatim policy

function authCfg() {
  if (!TRACCAR_USER || !TRACCAR_PASS) {
    throw new Error('Set TRACCAR_USER and TRACCAR_PASS env vars');
  }
  return { auth: { username: TRACCAR_USER, password: TRACCAR_PASS }, timeout: 10000 };
}

function minAgo(iso) {
  if (!iso) return null;
  const t = new Date(iso);
  if (Number.isNaN(t.getTime())) return null;
  return (Date.now() - t.getTime()) / 60000;
}

function truthy(v) {
  return v === true || v === 'true' || v === 1 || v === '1' || v === 'on' || v === 'ON';
}

function shortAddress(line) {
  if (!line) return '';
  const parts = line.split(',').map(s => s.trim()).filter(Boolean);
  return parts.slice(-3).join(', ').replace(/Pakistan$/i, 'PK');
}

// simple cache for reverse geocoding (round to ~100m to improve hit rate)
const geoCache = new Map(); // key: "lat,lon" e.g., "25.352,68.385"
function gridKey(lat, lon) {
  const r3 = n => Number(n).toFixed(3);
  return `${r3(lat)},${r3(lon)}`;
}
async function reverseGeocode(lat, lon) {
  if (lat == null || lon == null) return null;
  const key = gridKey(lat, lon);
  if (geoCache.has(key)) return geoCache.get(key);

  try {
    const res = await axios.get(NOMINATIM_URL, {
      params: { format: 'jsonv2', lat, lon, zoom: 14, addressdetails: 1 },
      headers: { 'User-Agent': `car-tracker/1.0 (${NOMINATIM_EMAIL})` },
      timeout: 10000,
    });
    const line = res.data?.display_name || '';
    const nice = shortAddress(line);
    geoCache.set(key, nice || null);
    return nice || null;
  } catch {
    geoCache.set(key, null);
    return null;
  }
}

function classify({ online, agePos, speed, motion, ignition }) {
  if (online) {
    if (speed > SPEED_RUNNING_KMH || motion === true) return 'running';
    if (ignition === true) return 'idle';
    return 'stopped';
  }
  if (agePos != null && agePos > EXPIRED_MIN) return 'expired';
  if (agePos != null && agePos > OFFLINE_MIN) return 'offline';
  if (speed <= SPEED_RUNNING_KMH && motion !== true) return 'stopped';
  return 'running';
}

async function tick() {
  try {
    const [devRes, posRes] = await Promise.all([
      axios.get(`${TRACCAR_BASE_URL}/api/devices`, authCfg()),
      axios.get(`${TRACCAR_BASE_URL}/api/positions`, authCfg()),
    ]);

    const devices = Array.isArray(devRes.data) ? devRes.data : [];
    const positions = Array.isArray(posRes.data) ? posRes.data : [];
    const posByDevice = new Map(positions.map(p => [p.deviceId, p]));

    // Build rows, including reverse geocode fallback if needed
    const rows = [];
    for (const d of devices) {
      const p = posByDevice.get(d.id) || {};
      const attrs = p.attributes || {};

      const agePos = minAgo(p.fixTime || p.deviceTime || p.serverTime);
      const ageConn = minAgo(d.lastUpdate);
      const online = (d.status === 'online') || (ageConn != null && ageConn <= 5);

      const speed = Number(p.speed || 0);
      const motion = attrs.motion;
      const ignRaw = attrs.ignition ?? attrs.acc ?? attrs.engine ?? attrs.Ignition;
      const ignition = ignRaw == null ? null : truthy(ignRaw);

      const status = classify({ online, agePos, speed, motion, ignition });

      const name = d.name || d.uniqueId || String(d.id);
      const lastPos = p.fixTime || p.deviceTime || p.serverTime || d.lastUpdate || null;
      const lastPosStr = lastPos
        ? new Date(lastPos).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
        : '—';

      let addr = shortAddress(p.address);
      const hasCoords = (p.latitude != null && p.longitude != null);
      const coords = hasCoords ? `${Number(p.latitude).toFixed(5)},${Number(p.longitude).toFixed(5)}` : '—';

      if (!addr && hasCoords) {
        // fallback geocode
        addr = await reverseGeocode(p.latitude, p.longitude);
      }

      rows.push({
        id: d.id,
        name,
        status,
        devStatus: d.status || 'unknown',
        speed: Math.round(speed),
        addr: addr || coords,
        coords: hasCoords ? coords : '—',
        agePos: (agePos != null) ? agePos.toFixed(1) : '—',
        ageConn: (ageConn != null) ? ageConn.toFixed(1) : '—',
        lastPosStr,
      });
    }

    const stamp = new Date().toLocaleTimeString();
    console.log(`\n[${stamp}] Devices: ${rows.length}`);
    for (const r of rows) {
      console.log(
        ` • ${r.name} | ${r.status.toUpperCase()} (dev:${r.devStatus}, agePos:${r.agePos}m, ageConn:${r.ageConn}m) `
        + `| ${r.speed} km/h | ${r.addr} | last ${r.lastPosStr}`
      );
    }
  } catch (e) {
    console.error(`[live-tail] error:`, e?.response?.status || '', e?.message || e);
  }
}

(async () => {
  await tick();
  setInterval(tick, 10_000);
})();
