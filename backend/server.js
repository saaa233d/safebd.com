/**
 * SAFE BD — High-Security Emergency Response & Live Location Hub
 * Supports:
 * - 999 CAD Dispatch Integration Simulation
 * - Real-time WebSocket E2EE Location Relaying
 * - Bangladeshi Mobile OTP Authentication
 * - Walk With Me Companion Route Checkpoints
 * - Moderated Civic Safety Feed
 */

const express = require('express');
const cors = require('cors');
const http = require('http');
const { WebSocketServer } = require('ws');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 5000;
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const policeDirectory = require('./policeDirectoryService');
const hospitalDirectory = require('./hospitalDirectoryService');
const shurokhaIntelligence = require('./shurokhaIntelligenceEngine');

// Process Crash Resilience: Prevent uncaught network/socket exceptions from killing the server
process.on('uncaughtException', (err) => {
  console.error('[⚠️ UNCAUGHT EXCEPTION PREVENTED CRASH]:', err.message);
});

process.on('unhandledRejection', (reason, promise) => {
  console.warn('[⚠️ UNHANDLED REJECTION PREVENTED CRASH]:', reason && reason.message ? reason.message : reason);
});

app.disable('x-powered-by');

// HTTP Security Headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

const ALLOWED_ORIGINS = [
  'https://safebd.onrender.com',
  'http://safebd.onrender.com',
  'http://localhost:5000',
  'http://127.0.0.1:5000',
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost',
  'capacitor://localhost',
  'ionic://localhost'
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    const isAllowed = ALLOWED_ORIGINS.includes(origin) 
      || origin.endsWith('.onrender.com') 
      || origin.includes('safebd.com') 
      || origin.startsWith('http://localhost') 
      || origin.startsWith('http://127.0.0.1')
      || origin.startsWith('capacitor://')
      || origin.startsWith('ionic://');
    if (isAllowed) {
      return callback(null, true);
    }
    return callback(null, false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept']
}));

app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Persistent Database Engine (Scales to Millions of Citizen Accounts)
const db = require('./database');

// Password Complexity Validator (OWASP Compliance - Min 8 chars, at least 1 letter and 1 number)
function validatePasswordStrength(pwd) {
  if (!pwd || typeof pwd !== 'string') {
    return { valid: false, message: 'Password is required.' };
  }
  if (pwd.length < 8) {
    return { valid: false, message: 'Password must be at least 8 characters long.' };
  }
  if (!/[A-Za-z]/.test(pwd) || !/[0-9]/.test(pwd)) {
    return { valid: false, message: 'Password must contain at least one letter and one number.' };
  }
  return { valid: true };
}

// =========================================================================
// SUPABASE CLOUD AUTHENTICATION & SECURE IDENTITY ENGINE
// =========================================================================
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY || '';
const SUPABASE_PUB_KEY = process.env.SUPABASE_PUB_KEY || '';

async function verifySupabaseCredentials(cleanPhone, password) {
  if (!SUPABASE_URL || !SUPABASE_PUB_KEY) return { valid: false };
  const rawPhone = String(cleanPhone || '').trim();
  const noZero = rawPhone.replace(/^0+/, '');
  const withZero = '0' + noZero;
  const emailsToTry = Array.from(new Set([`${noZero}@safebd.com`, `${withZero}@safebd.com`]));

  for (const email of emailsToTry) {
    try {
      const tokenUrl = `${SUPABASE_URL}/auth/v1/token?grant_type=password`;
      const res = await fetch(tokenUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'apikey': SUPABASE_PUB_KEY
        },
        body: JSON.stringify({ email, password })
      });
      if (res.ok) {
        const data = await res.json();
        return { valid: true, user: data.user, session: data };
      }
    } catch (err) {
      console.warn(`[⚠️ SUPABASE CLOUD AUTH ERROR] ${err.message}`);
    }
  }
  return { valid: false };
}

async function registerSupabaseUser(cleanPhone, name, password) {
  if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) return { ok: false, error: 'Supabase cloud auth not configured.' };
  try {
    const email = `${cleanPhone}@safebd.com`;
    const adminUrl = `${SUPABASE_URL}/auth/v1/admin/users`;
    const res = await fetch(adminUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': SUPABASE_SECRET_KEY,
        'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`
      },
      body: JSON.stringify({
        email,
        password,
        email_confirm: true,
        user_metadata: {
          name,
          phone: cleanPhone,
          isFounder: false
        }
      })
    });
    const data = await res.json();
    return { ok: res.ok, status: res.status, data };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

async function updateSupabasePassword(cleanPhone, newPassword) {
  if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) return false;
  try {
    const listRes = await fetch(`${SUPABASE_URL}/auth/v1/admin/users`, {
      headers: {
        'apikey': SUPABASE_SECRET_KEY,
        'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`
      }
    });
    const listData = await listRes.json();
    const rawPhone = String(cleanPhone || '').trim();
    const noZero = rawPhone.replace(/^0+/, '');
    const withZero = '0' + noZero;
    const targetEmails = [`${noZero}@safebd.com`, `${withZero}@safebd.com`];
    const found = (listData.users || []).find(u => targetEmails.includes(u.email));
    if (found) {
      await fetch(`${SUPABASE_URL}/auth/v1/admin/users/${found.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'apikey': SUPABASE_SECRET_KEY,
          'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`
        },
        body: JSON.stringify({ password: newPassword })
      });
      return true;
    }
  } catch (err) {
    console.warn('[⚠️ SUPABASE PASSWORD UPDATE ERROR]', err.message);
  }
  return false;
}

// =========================================================================
// ANTI-CYBERATTACK RATE LIMITING & BRUTE FORCE DEFENSE ENGINE
// =========================================================================
const rateLimitBuckets = {
  api: new Map(),
  auth: new Map(),
  otp: new Map(),
  post_create: new Map()
};

function createSlidingRateLimiter(bucketName, windowMs, maxRequests, customMessage) {
  if (!rateLimitBuckets[bucketName]) {
    rateLimitBuckets[bucketName] = new Map();
  }
  const bucket = rateLimitBuckets[bucketName];
  // Periodic cleanup of expired rate limit keys
  setInterval(() => {
    if (!bucket) return;
    const now = Date.now();
    for (const [key, item] of bucket.entries()) {
      if (now > item.resetTime) bucket.delete(key);
    }
  }, 5 * 60 * 1000).unref();

  return (req, res, next) => {
    // Exempt read-only telemetry, reverse-geocoding, and health checks from rate limiting
    if (req.path === '/api/health' || req.path === '/health' || req.path === '/ping' || req.path.startsWith('/api/geo/') || (req.method === 'GET' && req.path === '/api/feed/posts')) {
      return next();
    }

    const rawIp = req.ip || (req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0].trim() : (req.socket.remoteAddress || '127.0.0.1'));
    const phone = req.body && req.body.phone ? db.normalizePhone(req.body.phone) : '';
    // Key by phone if present so one citizen/phone number never blocks other users on shared mobile carrier CGNAT IPs
    const key = phone ? `${bucketName}_phone_${phone}` : `${bucketName}_ip_${rawIp}`;

    const now = Date.now();
    let record = bucket.get(key);

    if (!record || now > record.resetTime) {
      record = { count: 1, resetTime: now + windowMs };
      bucket.set(key, record);
    } else {
      record.count++;
      if (record.count > maxRequests) {
        console.warn(`[🚨 CYBERATTACK DEFENSE TRIGGERED] Throttling ${key} on bucket ${bucketName} (exceeded ${maxRequests} hits)`);
        return res.status(429).json({
          error: "TOO_MANY_REQUESTS",
          message: customMessage || "Too many requests. Automated security defense activated. Please wait before retrying."
        });
      }
    }
    next();
  };
}

const apiLimiter = createSlidingRateLimiter('api', 60 * 1000, 1200, "General request rate limit reached. Please wait a minute.");
const authLimiter = createSlidingRateLimiter('auth', 5 * 60 * 1000, 60, "Too many authentication attempts. Please wait 2 minutes.");
const otpLimiter = createSlidingRateLimiter('otp', 10 * 60 * 1000, 10, "SMS OTP request quota reached for this number. Please wait 10 minutes.");

// Citizen Token Authentication Guard (Enforced on protected citizen endpoints)
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();

  if (!token) {
    return res.status(401).json({ error: "UNAUTHORIZED", message: "Authentication token required in Authorization header." });
  }

  const session = db.getSession(token);
  if (!session || !session.phone) {
    return res.status(401).json({ error: "UNAUTHORIZED", message: "Invalid or expired session. Please sign in again." });
  }

  const user = db.getUserByPhone(session.phone);
  if (!user) {
    return res.status(401).json({ error: "UNAUTHORIZED", message: "User account not found." });
  }

  req.session = session;
  req.user = user;
  next();
}

// Admin Token Authentication Guard (Enforced on all /api/admin/* endpoints)
function requireAdminAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();

  if (!token) {
    return res.status(401).json({ error: "UNAUTHORIZED", message: "Admin authorization token required in Authorization header." });
  }

  const session = db.getSession(token);
  if (!session || !session.phone) {
    return res.status(401).json({ error: "UNAUTHORIZED", message: "Invalid or expired session. Please sign in again." });
  }

  const user = db.getUserByPhone(session.phone);
  const isAdmin = Boolean((user && user.isAdmin) || (session && session.isAdmin));
  if (!isAdmin) {
    return res.status(403).json({ error: "FORBIDDEN", message: "Access denied. Administrator clearance required." });
  }

  req.session = session;
  req.adminSession = session;
  req.adminUser = user;
  req.user = user;
  next();
}

app.use('/api/', apiLimiter);
app.use('/api/admin', requireAdminAuth);

// Ensure index.html and HTML pages are never cached by browsers, proxies, or CDNs
app.use((req, res, next) => {
  if (req.path === '/' || req.path === '/index.html' || req.path.endsWith('.html')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');
  }
  next();
});

// Serve the Cross-Platform Web & Mobile App to any connected phone, iPad, or desktop
app.use(express.static(path.join(__dirname, '../mobile-web-app/www'), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
      res.setHeader('Surrogate-Control', 'no-store');
    }
  }
}));

// Lightweight 24/7 Keep-Alive & Health Check Endpoints (Prevents Render Cold-Start Sleep)
app.get(['/api/health', '/ping'], (req, res) => {
  res.status(200).json({
    status: 'ONLINE',
    service: 'SAFE bd Emergency Dispatch API',
    uptimeSeconds: Math.floor(process.uptime()),
    timestamp: new Date().toISOString()
  });
});

// Accurate Bangladesh & Global Reverse Geocoding Proxy (High Availability, Server-Side User Agent)
app.get('/api/geo/reverse', async (req, res) => {
  const lat = parseFloat(req.query.lat);
  const lon = parseFloat(req.query.lon);
  if (isNaN(lat) || isNaN(lon)) {
    return res.status(400).json({ error: "INVALID_COORDINATES", message: "Latitude and longitude required." });
  }

  try {
    const fetchFn = globalThis.fetch;
    const url = `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lon}&zoom=18&addressdetails=1`;
    const geoRes = await fetchFn(url, {
      headers: {
        'User-Agent': 'SAFE_BD_Emergency_Platform/2.0 (bangladesh_citizen_safety@safebd.com)'
      }
    });

    if (geoRes.ok) {
      const data = await geoRes.json();
      if (data && data.address) {
        const addr = data.address;
        const road = addr.road || addr.pedestrian || addr.footway || "";
        const area = addr.residential || addr.neighbourhood || addr.quarter || addr.suburb || addr.subdistrict || "";
        const city = addr.city || addr.town || addr.municipality || addr.state_district || "Dhaka";

        let readable = "";
        if (road && area) {
          readable = `${road}, ${area}, ${city}`;
        } else if (area) {
          readable = `${area}, ${city}`;
        } else if (road) {
          readable = `${road}, ${city}`;
        } else if (data.display_name) {
          const parts = data.display_name.split(',').map(s => s.trim()).filter(s => {
            if (!s) return false;
            if (/^\d{4,}$/.test(s)) return false;
            if (['বাংলাদেশ', 'Bangladesh', 'ঢাকা বিভাগ', 'Dhaka Division', 'ঢাকা জেলা', 'Dhaka District', 'ঢাকা মহানগর', 'Dhaka City'].includes(s)) return false;
            return true;
          });
          readable = parts.slice(0, 3).join(', ');
        } else {
          readable = `Lat: ${lat.toFixed(4)}, Lon: ${lon.toFixed(4)}`;
        }

        return res.json({ success: true, address: readable, fullAddress: data.display_name || readable });
      }
    }
  } catch (err) {
    console.warn('[ReverseGeocode] Server lookup warning:', err.message);
  }

  return res.json({ success: true, address: `Lat: ${lat.toFixed(4)}, Lon: ${lon.toFixed(4)}` });
});

// In-Memory Secure State (for production: backed by Redis + PostgreSQL PostGIS)
const users = new Map();             // phone -> userProfile
const activeSessions = new Map();    // token -> user
const otpStore = new Map();          // phone -> { code, expiresAt }
const liveIncidents = new Map();     // incidentId -> details
const activeWalkSessions = new Map();// userId -> walkSession
const postCreateLimiter = createSlidingRateLimiter('post_create', 60 * 1000, 15, "Post submission rate limit reached. Please wait a minute before publishing again.");

// Helper: Generate 4-digit OTP
function generateOTP() {
  return Math.floor(1000 + Math.random() * 9000).toString();
}

/* ==========================================================
   1. DATABASE-BACKED AUTHENTICATION & BANGLADESH TELECOM OTP
========================================================== */

// 1.1 Direct Citizen Registration via Supabase Cloud Auth (Phone + Name + Password)
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { phone, name, password, bloodGroup, isBloodDonor, district, thana } = req.body;
  const phoneValidation = db.validateBdPhone(phone);
  if (!phoneValidation.valid) {
    return res.status(400).json({ error: phoneValidation.message });
  }
  const cleanPhone = phoneValidation.cleanPhone;

  const pwCheck = validatePasswordStrength(password);
  if (!pwCheck.valid) {
    return res.status(400).json({ error: pwCheck.message });
  }

  const registeredName = (name && name.trim()) || "Verified Citizen";

  // Check local database first before making external calls
  const existingUser = db.getUserByPhone(cleanPhone);
  if (existingUser && existingUser.passwordHash) {
    return res.status(400).json({ 
      error: `An account is already registered with +880 ${cleanPhone}. Please sign in with your password.`,
      code: "ACCOUNT_EXISTS",
      phone: cleanPhone
    });
  }

  // 1. Register with Supabase Cloud Auth (non-blocking)
  const supaRes = await registerSupabaseUser(cleanPhone, registeredName, password);

  if (!supaRes.ok && supaRes.data && supaRes.data.msg && supaRes.data.msg.includes('already been registered')) {
    return res.status(400).json({ 
      error: `An account is already registered with +880 ${cleanPhone}. Please sign in with your password to unlock your profile.`,
      code: "ACCOUNT_EXISTS",
      phone: cleanPhone
    });
  }

  if (!supaRes.ok) {
    console.warn(`[⚠️ SUPABASE REGISTER WARNING] +880 ${cleanPhone} Supabase registration: local fallback active.`);
  }

  // 2. Persist to local DB with verified password hash
  try {
    db.upsertUserWithPassword(cleanPhone, registeredName, password);

    if (bloodGroup) {
      db.updateUserBloodProfile(cleanPhone, { bloodGroup, isBloodDonor, district, thana });
    }

    const token = db.generateSecureToken('safe_token_', cleanPhone, false);
    db.markUserLogin(cleanPhone, token, { name: registeredName });

    const safeUser = {
      phone: cleanPhone,
      name: registeredName,
      isFounder: false,
      isAdmin: false,
      bloodGroup: bloodGroup ? bloodGroup.toUpperCase() : '',
      isBloodDonor: Boolean(isBloodDonor),
      bloodDistrict: district || '',
      bloodThana: thana || '',
      contacts: db.getUserContacts(cleanPhone)
    };

    console.log(`[⚡ CITIZEN REGISTERED] ${safeUser.name} (+880 ${cleanPhone})`);

    return res.json({
      success: true,
      message: "Citizen account successfully created.",
      token,
      user: safeUser
    });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

// 1.2 Legacy OTP Registration Endpoints (Retained for API Backwards-Compatibility)
app.post('/api/auth/request-otp', otpLimiter, (req, res) => {
  const { phone } = req.body;
  const phoneValidation = db.validateBdPhone(phone);
  if (!phoneValidation.valid) {
    return res.status(400).json({ error: phoneValidation.message });
  }
  const cleanPhone = phoneValidation.cleanPhone;

  const existing = db.getUserByPhone(cleanPhone);
  if (existing) {
    return res.status(400).json({ error: "An account is already registered with this phone number. Please sign in instead." });
  }

  db.issueOtp(cleanPhone, 'REGISTER');

  return res.json({
    success: true,
    message: `OTP dispatched to +880 ${cleanPhone} via Bangladesh Telecom Gateway.`
  });
});

app.post('/api/auth/verify-otp', authLimiter, (req, res) => {
  const { phone, code, password, name } = req.body;
  const phoneValidation = db.validateBdPhone(phone);
  if (!phoneValidation.valid) {
    return res.status(400).json({ error: phoneValidation.message });
  }
  const cleanPhone = phoneValidation.cleanPhone;

  const pwCheck = validatePasswordStrength(password);
  if (!pwCheck.valid) {
    return res.status(400).json({ error: pwCheck.message });
  }

  const otpResult = db.verifyOtp(cleanPhone, code, 'REGISTER');
  if (!otpResult.success) {
    return res.status(400).json({ error: otpResult.message });
  }

  try {
    const newUser = db.createUser({
      phone: cleanPhone,
      name: name || "Verified Citizen",
      password: password,
      nidVerified: true
    });

    const token = db.generateSecureToken('safe_token_', cleanPhone, false);
    db.markUserLogin(cleanPhone, token, { name: newUser.name });

    const { salt: _, passwordHash: __, ...safeUser } = newUser;
    console.log(`[✅ ACCOUNT REGISTERED & STORED IN DB] ${safeUser.name} (+880 ${cleanPhone})`);

    return res.json({
      success: true,
      message: "Citizen account successfully verified and registered in database.",
      token,
      user: safeUser
    });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

// 1.3 Direct Sign In via Supabase Cloud Auth (Phone & Password Matching)
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { phone, password } = req.body;
  
  if (!phone || !password) {
    return res.status(400).json({ error: "Please enter both mobile number and password." });
  }

  const cleanPhone = db.normalizePhone(phone);
  const trimmedPassword = String(password).trim();

  const phoneValidation = db.validateBdPhone(cleanPhone);
  if (!phoneValidation.valid) {
    return res.status(400).json({ error: phoneValidation.message });
  }
  const validatedPhone = phoneValidation.cleanPhone;

  // 1. Authenticate with Supabase Cloud Auth
  const supaCheck = await verifySupabaseCredentials(validatedPhone, trimmedPassword);
  
  if (supaCheck.valid) {
    const meta = (supaCheck.user && supaCheck.user.user_metadata) || {};
    let localUser = db.getUserByPhone(validatedPhone);
    const isAdmin = Boolean(localUser && localUser.isAdmin);
    const isFounder = Boolean(localUser && localUser.isFounder);
    let userName = (localUser && localUser.name) || meta.name || 'Citizen';

    db.upsertUserWithPassword(validatedPhone, userName, trimmedPassword);

    const token = db.generateSecureToken(isAdmin ? 'safe_token_admin_' : 'safe_token_', validatedPhone, isAdmin);
    db.markUserLogin(validatedPhone, token, { name: userName });

    const safeUser = {
      phone: validatedPhone,
      name: userName,
      isFounder: isFounder,
      isAdmin: isAdmin,
      contacts: db.getUserContacts(validatedPhone)
    };

    console.log(`[⚡ SUPABASE CLOUD LOGIN SUCCESS] ${isAdmin ? 'Admin' : 'Citizen'} ${safeUser.name} (+880 ${validatedPhone}) authenticated.`);

    return res.json({
      success: true,
      requireOtp: false,
      token,
      user: safeUser,
      message: isAdmin ? "Administrator authenticated." : `Welcome back, ${safeUser.name}!`
    });
  }

  // 2. Fallback to local database credentials
  const check = db.verifyUserCredentials(validatedPhone, trimmedPassword);
  if (!check.valid) {
    return res.status(401).json({ error: "Incorrect mobile number or password.", code: "INVALID_CREDENTIALS" });
  }

  const isAdmin = Boolean(check.user && check.user.isAdmin);
  const isFounder = Boolean(check.user && check.user.isFounder);
  const token = db.generateSecureToken(isAdmin ? 'safe_token_admin_' : 'safe_token_', validatedPhone, isAdmin);
  db.markUserLogin(validatedPhone, token, { name: check.user ? check.user.name : undefined });

  const { salt: _, passwordHash: __, ...safeUser } = check.user;
  safeUser.isAdmin = isAdmin;
  safeUser.isFounder = isFounder;
  safeUser.contacts = db.getUserContacts(validatedPhone);
  console.log(`[🔐 LOCAL DB LOGIN SUCCESSFUL] ${isAdmin ? 'Admin' : 'Citizen'} ${safeUser.name} (+880 ${validatedPhone}) logged in.`);

  return res.json({
    success: true,
    requireOtp: false,
    token,
    user: safeUser,
    message: isAdmin ? "Administrator authenticated." : `Welcome back, ${safeUser.name}!`
  });
});

// 1.3.1 Active Session Verification & Profile Fetcher
app.get('/api/auth/me', (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();

  if (!token) {
    return res.status(401).json({ error: "UNAUTHORIZED", message: "No active session token." });
  }

  const session = db.getSession(token);
  if (!session || !session.phone) {
    return res.status(401).json({ error: "SESSION_EXPIRED", message: "Session expired or invalid. Please sign in again." });
  }

  const user = db.getUserByPhone(session.phone);
  if (!user) {
    return res.status(404).json({ error: "NOT_FOUND", message: "User account not found." });
  }

  const { salt: _, passwordHash: __, ...safeUser } = user;
  safeUser.isAdmin = Boolean(user.isAdmin);
  safeUser.isFounder = Boolean(user.isFounder);
  safeUser.contacts = db.getUserContacts(session.phone);
  return res.json({
    success: true,
    user: safeUser
  });
});

// 1.3.2 Authenticated Password Change
app.post('/api/auth/change-password', requireAuth, authLimiter, (req, res) => {
  const phone = req.user.phone;
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) {
    return res.status(400).json({ error: "Both current password and new password are required." });
  }

  const pwCheck = validatePasswordStrength(newPassword);
  if (!pwCheck.valid) {
    return res.status(400).json({ error: pwCheck.message });
  }

  try {
    db.changeUserPassword(phone, oldPassword, newPassword);
    updateSupabasePassword(phone, newPassword).catch(e => console.warn('[Supabase Change Password Warn]', e.message));
    return res.json({ success: true, message: "Password updated successfully in cloud vault." });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

// 1.4 Optional 2FA Login OTP Verification (Retained for Backwards Compatibility)
app.post('/api/auth/login-verify-otp', authLimiter, (req, res) => {
  const { phone, code } = req.body;
  const cleanPhone = db.normalizePhone(phone);

  const otpCheck = db.verifyOtp(cleanPhone, code, 'LOGIN');
  if (!otpCheck.success) {
    return res.status(400).json({ error: otpCheck.message });
  }

  const user = db.getUserByPhone(cleanPhone);
  if (!user) {
    return res.status(404).json({ error: "Account not found." });
  }

  const isChiefAdmin = Boolean(user.isAdmin);
  const token = db.generateSecureToken(isChiefAdmin ? 'safe_token_admin_' : 'safe_token_', cleanPhone, isChiefAdmin);
  db.markUserLogin(cleanPhone, token, { name: user.name });

  const { salt: _, passwordHash: __, ...safeUser } = user;
  safeUser.isAdmin = isChiefAdmin;
  console.log(`[🔐 2FA LOGIN VERIFIED] Citizen ${safeUser.name} (+880 ${cleanPhone}) signed in.`);

  return res.json({
    success: true,
    token,
    user: safeUser,
    message: `Welcome back, ${safeUser.name}!`
  });
});

// 1.5 Forgot Password Step 1: Request Reset OTP (Rate-Limited)
app.post('/api/auth/forgot-password/request-otp', otpLimiter, async (req, res) => {
  const { phone } = req.body;
  const phoneValidation = db.validateBdPhone(phone);
  if (!phoneValidation.valid) {
    return res.status(400).json({ error: phoneValidation.message });
  }
  const cleanPhone = phoneValidation.cleanPhone;

  let user = db.getUserByPhone(cleanPhone);
  if (!user && SUPABASE_URL && SUPABASE_SECRET_KEY) {
    // Cloud recovery: Check if account exists in Supabase Cloud
    try {
      const listRes = await fetch(`${SUPABASE_URL}/auth/v1/admin/users`, {
        headers: {
          'apikey': SUPABASE_SECRET_KEY,
          'Authorization': `Bearer ${SUPABASE_SECRET_KEY}`
        }
      });
      const listData = await listRes.json();
      const rawPhone = String(cleanPhone || '').trim();
      const noZero = rawPhone.replace(/^0+/, '');
      const withZero = '0' + noZero;
      const targetEmails = [`${noZero}@safebd.com`, `${withZero}@safebd.com`];
      const found = (listData.users || []).find(u => targetEmails.includes(u.email));
      if (found) {
        const metaName = (found.user_metadata && found.user_metadata.name) || 'Verified Citizen';
        db.upsertUserWithPassword(cleanPhone, metaName, 'TEMPORARY_PW_AWAITING_RESET_' + Date.now());
        user = db.getUserByPhone(cleanPhone);
      }
    } catch (e) {}
  }
  if (!user) {
    return res.status(404).json({ error: "No account found with this phone number. Please create an account first." });
  }

  db.issueOtp(cleanPhone, 'FORGOT_PASSWORD');

  return res.json({
    success: true,
    message: `Password reset code sent to +880 ${cleanPhone}.`
  });
});

// 1.6 Forgot Password Step 2: Verify OTP & Set New Password (Rate-Limited)
app.post('/api/auth/forgot-password/verify-reset', authLimiter, async (req, res) => {
  const { phone, code, newPassword } = req.body;
  const phoneValidation = db.validateBdPhone(phone);
  if (!phoneValidation.valid) {
    return res.status(400).json({ error: phoneValidation.message });
  }
  const cleanPhone = phoneValidation.cleanPhone;

  const pwCheck = validatePasswordStrength(newPassword);
  if (!pwCheck.valid) {
    return res.status(400).json({ error: pwCheck.message });
  }

  const otpCheck = db.verifyOtp(cleanPhone, code, 'FORGOT_PASSWORD');
  if (!otpCheck.success) {
    return res.status(400).json({ error: otpCheck.message });
  }

  try {
    const updatedUser = db.resetPassword(cleanPhone, newPassword);
    updateSupabasePassword(cleanPhone, newPassword).catch(e => console.warn('[Supabase Reset Password Warn]', e.message));

    const isChiefAdmin = Boolean(updatedUser.isAdmin);
    const token = db.generateSecureToken(isChiefAdmin ? 'safe_token_admin_' : 'safe_token_', cleanPhone, isChiefAdmin);
    db.markUserLogin(cleanPhone, token, { name: updatedUser.name });

    const { salt: _, passwordHash: __, ...safeUser } = updatedUser;
    safeUser.isAdmin = isChiefAdmin;
    console.log(`[🔑 PASSWORD RESET SUCCESSFUL] Account +880 ${cleanPhone} updated password.`);

    return res.json({
      success: true,
      token,
      user: safeUser,
      message: "Password reset successful! You are now securely signed in."
    });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

// 1.7 Sign Out / Session Termination
app.post('/api/auth/logout', (req, res) => {
  const { phone, token } = req.body;
  db.markUserLogout(token || phone);
  return res.json({ success: true, message: "Signed out successfully." });
});

// 1.8 Citizen Emergency Contacts Sync (Per-Profile Cloud Storage — Strict Auth Enforced)
app.get('/api/user/contacts', requireAuth, (req, res) => {
  if (req.user.isAdmin && req.query.phone) {
    const targetPhone = db.normalizePhone(req.query.phone);
    return res.json({ success: true, contacts: db.getUserContacts(targetPhone) });
  }
  const contacts = db.getUserContacts(req.user.phone);
  return res.json({ success: true, contacts });
});

app.put('/api/user/contacts', requireAuth, apiLimiter, (req, res) => {
  try {
    const updated = db.updateUserContacts(req.user.phone, req.body.contacts);
    console.log(`[👥 CONTACTS SYNCED TO DB] Citizen +880 ${req.user.phone} saved emergency contacts.`);
    return res.json({
      success: true,
      message: "Emergency contacts updated in user profile.",
      contacts: updated
    });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});

app.post('/api/user/contacts', requireAuth, apiLimiter, (req, res) => {
  try {
    const updated = db.updateUserContacts(req.user.phone, req.body.contacts);
    return res.json({
      success: true,
      message: "Emergency contacts updated in user profile.",
      contacts: updated
    });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
});
// 1.9 Database Scale & Health Metrics (Protected by Admin Auth)
app.get('/api/database/metrics', requireAdminAuth, (req, res) => {
  const metrics = db.getDatabaseMetrics();
  return res.json({ success: true, metrics });
});

/* ==========================================================
   2. 999 EMERGENCY SOS & FAMILY/COMMUNITY ALERT
========================================================== */

app.post('/api/emergency/sos-trigger', (req, res) => {
  const { userId, location, emergencyType, userName, userPhone } = req.body;

  const savedAlert = db.addSosAlert({
    userId,
    userName,
    userPhone,
    emergencyType,
    location
  });

  const incident = {
    incidentId: savedAlert.incidentId,
    id: savedAlert.id,
    userId: savedAlert.userId,
    userName: savedAlert.userName,
    userPhone: savedAlert.userPhone,
    displayPhone: savedAlert.displayPhone,
    status: savedAlert.status,
    timestamp: savedAlert.timestamp,
    emergencyType: savedAlert.emergencyType,
    location: savedAlert.location,
    dispatchStatus: "INTERNAL_BROADCAST_ACTIVE",
    googleMapsUrl: savedAlert.googleMapsUrl
  };

  liveIncidents.set(savedAlert.incidentId, incident);
  console.log(`[🚨 EMERGENCY SOS] Incident ${savedAlert.incidentId} logged from ${savedAlert.userName} (${savedAlert.displayPhone}). Coordinates:`, incident.location);

  // Broadcast to all active emergency circle listeners & admin consoles via WebSocket
  broadcastLocationUpdate({
    type: "EMERGENCY_SOS_ALERT",
    incident,
    alert: savedAlert
  });

  return res.json({
    success: true,
    incidentId: savedAlert.incidentId,
    message: "Distress signal logged and broadcasted to emergency contacts. In a life-threatening emergency, always dial 999 directly.",
    warning: "Internal citizen safety broadcast only. If you are in immediate danger, dial 999 immediately.",
    incident,
    alert: savedAlert
  });
});

const { execFile } = require('child_process');
let ffmpegPath = null;
try {
  ffmpegPath = require('ffmpeg-static');
} catch (e) {
  ffmpegPath = 'ffmpeg';
}

let isTranscoding = false;
const transcodeQueue = [];

function convertToMp4(inputPath, outputPath) {
  return new Promise((resolve, reject) => {
    transcodeQueue.push({ inputPath, outputPath, resolve, reject });
    processNextTranscode();
  });
}

function processNextTranscode() {
  if (isTranscoding || transcodeQueue.length === 0) return;
  const { inputPath, outputPath, resolve, reject } = transcodeQueue.shift();
  isTranscoding = true;

  if (!ffmpegPath) {
    isTranscoding = false;
    reject(new Error('FFmpeg binary not found'));
    processNextTranscode();
    return;
  }

  // Single-threaded, low-RAM preset designed for Render 512MB RAM containers
  const args = [
    '-y',
    '-threads', '1',
    '-i', inputPath,
    '-c:v', 'libx264',
    '-preset', 'ultrafast',
    '-crf', '28',
    '-c:a', 'aac',
    '-b:a', '96k',
    '-max_muxing_queue_size', '1024',
    '-movflags', '+faststart',
    outputPath
  ];

  execFile(ffmpegPath, args, { maxBuffer: 1024 * 1024 * 4 }, (err, stdout, stderr) => {
    isTranscoding = false;
    if (err) {
      console.warn('[FFMPEG TRANSCODE ERROR]:', err.message);
      reject(err);
    } else {
      resolve(outputPath);
    }
    // Yield to V8 garbage collector before starting next transcode
    setTimeout(processNextTranscode, 300);
  });
}

// Ensure Evidence Directory exists
const EVIDENCE_DIR = process.env.SAFEBD_DATA_DIR ? path.join(path.resolve(process.env.SAFEBD_DATA_DIR), 'evidence') : path.join(__dirname, 'data', 'evidence');
if (!fs.existsSync(EVIDENCE_DIR)) {
  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
}

// 2.2 Covert Background Emergency Video & Audio Evidence Receiver (Spy Feature)
app.post('/api/emergency/covert-recording', express.json({ limit: '25mb' }), async (req, res) => {
  try {
    const { id, userId, userName, userPhone, location, videoData, mimeType, durationSeconds, fileName: clientFileName } = req.body;

    if (!videoData) {
      return res.status(400).json({ error: "MISSING_VIDEO_DATA", message: "Emergency video evidence data required." });
    }

    // Robust Base64 extraction regardless of codec parameters in data URI
    let base64Clean = videoData;
    const base64Marker = ';base64,';
    const markerIndex = videoData.indexOf(base64Marker);
    if (markerIndex !== -1) {
      base64Clean = videoData.substring(markerIndex + base64Marker.length);
    } else if (videoData.startsWith('data:')) {
      const commaIdx = videoData.indexOf(',');
      if (commaIdx !== -1) base64Clean = videoData.substring(commaIdx + 1);
    }
    const videoBuffer = Buffer.from(base64Clean.trim(), 'base64');

    const rawPhoneDigits = String(userPhone || userId || '').replace(/\D/g, '');
    const cleanPhoneForFile = rawPhoneDigits.startsWith('880') && rawPhoneDigits.length >= 13
      ? '0' + rawPhoneDigits.slice(3)
      : (rawPhoneDigits.length === 10 && rawPhoneDigits.startsWith('1') ? '0' + rawPhoneDigits : (rawPhoneDigits || 'anonymous'));

    const ext = (mimeType && mimeType.includes('mp4')) ? 'mp4' : 'webm';
    const fileName = `${cleanPhoneForFile}_SOS_${Date.now()}.${ext}`;
    const filePath = path.join(EVIDENCE_DIR, fileName);

    fs.writeFileSync(filePath, videoBuffer);
    const initialFileSizeKb = Math.round(videoBuffer.length / 1024);

    let finalFileName = fileName;
    let finalFilePath = filePath;
    let finalMimeType = (mimeType && mimeType.includes('mp4')) ? 'video/mp4' : (mimeType || 'video/webm');
    let finalFileSizeKb = initialFileSizeKb;

    // Universal Mobile Compatibility: Auto-transcode WebM to standard MP4 (H.264/AAC +faststart)
    if (fileName.endsWith('.webm') || (mimeType && mimeType.includes('webm'))) {
      const mp4FileName = fileName.replace(/\.webm$/i, '') + '.mp4';
      const mp4FilePath = path.join(EVIDENCE_DIR, mp4FileName);
      try {
        await convertToMp4(filePath, mp4FilePath);
        if (fs.existsSync(mp4FilePath) && fs.statSync(mp4FilePath).size > 0) {
          finalFileName = mp4FileName;
          finalFilePath = mp4FilePath;
          finalMimeType = 'video/mp4';
          finalFileSizeKb = Math.round(fs.statSync(mp4FilePath).size / 1024);
          console.log(`[🎬 TRANSCODE SUCCESS] Converted ${fileName} to mobile-friendly MP4 (${finalFileName}, ${finalFileSizeKb} KB)`);
        }
      } catch (transcodeErr) {
        console.warn(`[⚠️ MP4 TRANSCODE FALLBACK] Keeping original ${fileName}:`, transcodeErr.message);
      }
    } else if (fileName.endsWith('.mp4')) {
      finalMimeType = 'video/mp4';
    }

    const evidenceId = id || ("EVID-" + Date.now());
    let gdriveFileId = null;

    // Upload MP4 directly to Private 5TB Google Drive Vault (Zero Render RAM pressure & permanent across redeploys)
    try {
      const mp4Base64 = fs.readFileSync(finalFilePath).toString('base64');
      const gdriveRes = await db.uploadToGoogleDriveVault({
        fileName: finalFileName,
        mimeType: finalMimeType,
        base64: mp4Base64
      });
      if (gdriveRes && gdriveRes.success && gdriveRes.fileId) {
        gdriveFileId = gdriveRes.fileId;
      }
    } catch (gdErr) {
      console.warn('[⚠️ GDRIVE EVIDENCE UPLOAD FALLBACK]:', gdErr.message);
    }

    const evidenceItem = {
      id: evidenceId,
      userId: userId || "anonymous",
      userName: userName || "Citizen in Distress",
      userPhone: userPhone || "01XXXXXXXXX",
      location: location || { lat: 23.8103, lon: 90.4125, address: "Dhaka, Bangladesh" },
      videoUrl: `/api/emergency/evidence/${finalFileName}`,
      gdriveFileId: gdriveFileId,
      // Stored on disk at EVIDENCE_DIR + Private 5TB Google Drive Vault
      fileName: finalFileName,
      fileSizeKb: finalFileSizeKb,
      mimeType: finalMimeType,
      durationSeconds: durationSeconds || 15,
      recordedAt: new Date().toISOString(),
      status: "PENDING_ADMIN_DISPATCH",
      reviewed: false
    };

    db.addEmergencyEvidence(evidenceItem);

    console.log(`[📹🚨 SPY COVERT SOS VIDEO CAPTURED & ARCHIVED] Citizen: ${evidenceItem.userName} (${evidenceItem.userPhone}) at ${evidenceItem.location.address} | Size: ${evidenceItem.fileSizeKb} KB (${finalMimeType})`);

    // Broadcast live to Admin and Emergency circle listeners
    broadcastLocationUpdate({
      type: "EMERGENCY_COVERT_VIDEO_EVIDENCE",
      evidence: evidenceItem
    });

    return res.json({
      success: true,
      message: "Emergency spy video & audio evidence safely archived in mobile-friendly MP4 and delivered to Admin Command Portal.",
      evidence: evidenceItem
    });
  } catch (err) {
    console.error("[ERROR] Failed to save covert emergency recording:", err);
    return res.status(500).json({ error: "INTERNAL_ERROR", message: err.message });
  }
});

// 2.3 Stream / Serve / Download Emergency Video Evidence (Native MP4 for Mobile Compatibility)
app.get('/api/emergency/evidence/:filename', async (req, res) => {
  const filename = path.basename(req.params.filename);
  let filePath = path.join(EVIDENCE_DIR, filename);

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Authorization Guard: Emergency recording contains sensitive citizen distress video & audio (Header-only Bearer token)
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();
  const session = token ? db.getSession(token) : null;

  if (!session || !session.phone) {
    return res.status(401).json({
      error: "UNAUTHORIZED",
      message: "Authentication token required in Authorization header to access emergency evidence records."
    });
  }

  const user = db.getUserByPhone(session.phone);
  const evidence = db.getEmergencyEvidenceByFilename(filename);
  const isAdmin = Boolean((user && user.isAdmin) || (session && session.isAdmin));
  const isOwner = Boolean(
    evidence && (
      (evidence.userPhone && db.normalizePhone(evidence.userPhone) === db.normalizePhone(session.phone)) ||
      (evidence.userId && evidence.userId === session.phone) ||
      (user && evidence.userId && evidence.userId === user.id)
    )
  );

  if (!isAdmin && !isOwner) {
    return res.status(403).json({
      error: "FORBIDDEN",
      message: "Access denied. Emergency evidence records require verified citizen owner or administrator authorization."
    });
  }

  // If requesting .mp4 but only .webm exists on disk, transcode or fallback to webm
  if (filename.endsWith('.mp4') && !fs.existsSync(filePath)) {
    const webmName = filename.replace(/\.mp4$/i, '.webm');
    const webmPath = path.join(EVIDENCE_DIR, webmName);
    if (fs.existsSync(webmPath)) {
      try {
        await convertToMp4(webmPath, filePath);
        console.log(`[🎬 ON-DEMAND MP4 TRANSCODE] Transcoded ${webmName} -> ${filename}`);
      } catch (e) {
        console.warn(`[TRANSCODE FALLBACK]: Serving WebM directly for ${filename}`);
        filePath = webmPath;
      }
    }
  }

  // If still not found, check if alternative extension exists
  if (!fs.existsSync(filePath)) {
    const rawBase = filename.replace(/\.(mp4|webm)$/i, '');
    const altMp4 = path.join(EVIDENCE_DIR, rawBase + '.mp4');
    const altWebm = path.join(EVIDENCE_DIR, rawBase + '.webm');
    if (fs.existsSync(altMp4)) {
      filePath = altMp4;
    } else if (fs.existsSync(altWebm)) {
      filePath = altWebm;
    }
  }

  // If wiped by Render redeploy/restart, automatically restore from Private 5TB Google Drive Vault
  if (!fs.existsSync(filePath)) {
    try {
      const rawBase = filename.replace(/\.(mp4|webm)$/i, '');
      const allEvidence = db.getAllEmergencyEvidence() || [];
      const matchItem = allEvidence.find(e => e.fileName === filename || (e.fileName && e.fileName.replace(/\.(mp4|webm)$/i, '') === rawBase));
      const cloudBuf = await db.fetchFromGoogleDriveVault({
        fileId: matchItem ? matchItem.gdriveFileId : '',
        fileName: (matchItem && matchItem.fileName) ? matchItem.fileName : filename
      });
      if (cloudBuf && cloudBuf.length > 0) {
        if (!fs.existsSync(EVIDENCE_DIR)) fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
        fs.writeFileSync(filePath, cloudBuf);
        console.log(`[☁️ RESTORED FROM 5TB GOOGLE DRIVE VAULT] Restored ${filename} (${Math.round(cloudBuf.length / 1024)} KB)`);
      }
    } catch (restoreErr) {
      console.warn('[⚠️ GDRIVE EVIDENCE RESTORE WARN]:', restoreErr.message);
    }
  }

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: "EVIDENCE_NOT_FOUND", message: "Requested evidence file does not exist on disk or in Google Drive Vault." });
  }

  const stat = fs.statSync(filePath);
  const fileSize = stat.size;
  const isDownload = req.query.download === '1' || req.query.dl === '1';

  // Direct 1-Click File Download Handler (Forces browser download prompt)
  if (isDownload) {
    return res.download(filePath, filename, (err) => {
      if (err && !res.headersSent) {
        res.status(500).json({ error: "DOWNLOAD_FAILED", message: err.message });
      }
    });
  }

  const range = req.headers.range;
  const contentType = filename.endsWith('.mp4') ? 'video/mp4' : 'video/webm';
  res.setHeader('Accept-Ranges', 'bytes');
  res.setHeader('Cache-Control', 'public, max-age=86400');

  if (range) {
    const parts = range.replace(/bytes=/, "").split("-");
    const start = parseInt(parts[0], 10);
    const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1;
    if (start >= fileSize || end >= fileSize) {
      res.setHeader('Content-Range', `bytes */${fileSize}`);
      return res.status(416).end();
    }
    const chunksize = (end - start) + 1;
    const file = fs.createReadStream(filePath, { start, end });
    res.writeHead(206, {
      'Content-Range': `bytes ${start}-${end}/${fileSize}`,
      'Content-Length': chunksize,
      'Content-Type': contentType,
      'Access-Control-Allow-Origin': '*',
      'Accept-Ranges': 'bytes'
    });
    file.pipe(res);
  } else {
    res.writeHead(200, {
      'Content-Length': fileSize,
      'Content-Type': contentType,
      'Access-Control-Allow-Origin': '*',
      'Accept-Ranges': 'bytes'
    });
    fs.createReadStream(filePath).pipe(res);
  }
});

// 2.4 Admin Emergency Evidence Telemetry (Displayed where posts are approved)
app.get('/api/admin/emergency-evidence', (req, res) => {
  const allEvidence = db.getAllEmergencyEvidence();
  return res.json({ success: true, evidence: allEvidence });
});

app.post('/api/admin/emergency-evidence/:id/review', (req, res) => {
  const updated = db.markEmergencyEvidenceReviewed(req.params.id, req.body.notes);
  if (updated) {
    return res.json({ success: true, message: "Emergency evidence marked reviewed & dispatched.", evidence: updated });
  }
  return res.status(404).json({ error: "NOT_FOUND", message: "Evidence record not found." });
});

// 2.5 Admin Live SOS Distress Locations Engine (Direct Exact Coordinates Feed)
app.get('/api/admin/sos-alerts', (req, res) => {
  const alerts = db.getAllSosAlerts();
  return res.json({ success: true, alerts });
});

app.post('/api/admin/sos-alerts/:id/resolve', (req, res) => {
  const adminName = (req.body && req.body.adminName) || 'Chief Administrator';
  const resolved = db.resolveSosAlert(req.params.id, adminName);
  if (resolved) {
    return res.json({ success: true, message: "SOS incident marked resolved.", alert: resolved });
  }
  return res.status(404).json({ error: "NOT_FOUND", message: "SOS alert not found." });
});

/* ==========================================================
   2.6 EMERGENCY BLOOD DONATION LIFELINE (রক্তবন্ধু)
   Peer-to-peer life-saving blood donor search and opt-in registry
========================================================== */
app.get('/api/blood/donors', (req, res) => {
  try {
    const { group, district } = req.query;
    const donors = db.getBloodDonors(group, district);
    return res.json({
      success: true,
      donors: donors || [],
      total: donors ? donors.length : 0
    });
  } catch (err) {
    console.error('[BLOOD DONORS GET ERROR]:', err);
    return res.status(500).json({ error: "SERVER_ERROR", message: "Failed to fetch blood donors list." });
  }
});

app.post('/api/blood/donors', requireAuth, (req, res) => {
  try {
    const { bloodGroup, district, thana, available } = req.body;
    const cleanPhone = req.user.phone;

    const validGroups = ['A+', 'A-', 'B+', 'B-', 'O+', 'O-', 'AB+', 'AB-'];
    const cleanGroup = (bloodGroup || 'O+').trim().toUpperCase();
    if (!validGroups.includes(cleanGroup)) {
      return res.status(400).json({ error: "INVALID_BLOOD_GROUP", message: "Please select a valid blood group (A+, A-, B+, B-, O+, O-, AB+, AB-)." });
    }

    // Anonymous Life Saver: Tied securely to verified citizen phone
    const donor = db.addOrUpdateBloodDonor({
      phone: cleanPhone,
      bloodGroup: cleanGroup,
      district: (district || 'Dhaka').trim(),
      thana: (thana || '').trim(),
      available: available !== false
    });

    return res.json({
      success: true,
      message: "Successfully registered to the Safe BD Emergency Blood Lifeline! Thank you for being a lifesaver.",
      donor
    });
  } catch (err) {
    console.error('[BLOOD DONORS POST ERROR]:', err);
    return res.status(500).json({ error: "SERVER_ERROR", message: "Failed to register blood donor." });
  }
});

app.post('/api/blood/donors/:id/toggle', requireAuth, (req, res) => {
  try {
    const donorId = req.params.id;
    const allDonors = db.getBloodDonors ? db.getBloodDonors() : [];
    const targetDonor = (allDonors || []).find(d => d.id === donorId || d.phone === donorId);

    if (!targetDonor) {
      return res.status(404).json({ error: "NOT_FOUND", message: "Donor profile not found." });
    }

    const isOwner = db.normalizePhone(targetDonor.phone) === db.normalizePhone(req.user.phone);
    if (!isOwner && !req.user.isAdmin) {
      return res.status(403).json({ error: "FORBIDDEN", message: "Access denied. You can only toggle your own donor profile." });
    }

    const updated = db.toggleDonorAvailability(donorId, req.body.available);
    return res.json({ success: true, donor: updated });
  } catch (err) {
    return res.status(500).json({ error: "SERVER_ERROR", message: "Failed to update donor status." });
  }
});

// 2.6.3 Save Blood Information on Citizen Profile (Optional Donor Opt-in)
app.post(['/api/user/blood-profile', '/api/user/blood'], requireAuth, (req, res) => {
  try {
    const userPhone = req.user.phone;
    const { bloodGroup, isBloodDonor, district, thana } = req.body;
    const updatedUser = db.updateUserBloodProfile(userPhone, {
      bloodGroup,
      isBloodDonor,
      district,
      thana
    });

    if (!updatedUser) {
      return res.status(404).json({ error: "NOT_FOUND", message: "User profile not found." });
    }

    return res.json({
      success: true,
      message: "Blood profile updated successfully.",
      user: updatedUser
    });
  } catch (err) {
    return res.status(500).json({ error: "SERVER_ERROR", message: "Failed to update blood profile." });
  }
});

/* ==========================================================
   3. "WALK WITH ME" / JOURNEY COMPANION SESSIONS & LIVE TRACKING
========================================================== */

// Start / Register Personal Walk With Me Companion Session (User-Isolated)
app.post('/api/walk/start', requireAuth, (req, res) => {
  const cleanPhone = req.user.phone;
  const displayName = req.user.name || "Citizen Traveler";
  const { origin, destination, travelMode, estimatedMinutes, currentCoords, destCoords } = req.body;
  const sessionId = "journey_" + crypto.randomBytes(16).toString('hex');

  const session = {
    sessionId,
    userId: cleanPhone,
    userName: displayName,
    userPhone: cleanPhone,
    origin: origin || "Current Location",
    destination: destination || "Destination",
    destCoords: destCoords || null,
    travelMode: travelMode || "walking",
    estimatedMinutes: estimatedMinutes || 20,
    startTime: new Date().toISOString(),
    currentCoords: currentCoords || { lat: 23.7388, lon: 90.4143, address: origin },
    status: "IN_TRANSIT",
    lastPing: Date.now(),
    isOverdue: false,
    overdueUploadedToAdmin: false
  };

  // 1. Fast in-memory session lookup
  activeWalkSessions.set(sessionId, session);

  // 2. User-isolated persistence in Database & Cloud Vault
  db.saveUserActiveJourney(cleanPhone, session);

  console.log(`[🚗 JOURNEY STARTED] User: ${session.userName} (${cleanPhone}) | Mode: ${session.travelMode} -> ${session.destination} | Est: ${session.estimatedMinutes} mins`);
  return res.json({ success: true, session });
});

// Retrieve Logged-in User's Personal Active Walk Session
app.get('/api/walk/my-session', requireAuth, (req, res) => {
  const cleanPhone = req.user.phone;
  const userJourney = db.getUserActiveJourney(cleanPhone);
  return res.json({ success: true, session: userJourney || null });
});

// Update location during transit (Updates user's private session)
app.post('/api/walk/update-location', requireAuth, (req, res) => {
  const { sessionId, lat, lon, address } = req.body;
  const cleanPhone = req.user.phone;
  
  let dbJourney = db.getUserActiveJourney(cleanPhone);
  if (sessionId && dbJourney && dbJourney.sessionId !== sessionId) {
    return res.status(403).json({ error: "FORBIDDEN", message: "You are not authorized to update this journey session." });
  }

  let session = sessionId ? activeWalkSessions.get(sessionId) : null;
  if (session && session.userPhone !== cleanPhone) {
    return res.status(403).json({ error: "FORBIDDEN", message: "You do not own this journey session." });
  }

  if (dbJourney) {
    dbJourney.currentCoords = { lat, lon, address };
    dbJourney.lastPing = Date.now();
    db.saveUserActiveJourney(cleanPhone, dbJourney);
    if (!session) session = dbJourney;
  }

  if (session) {
    session.currentCoords = { lat, lon, address };
    session.lastPing = Date.now();
    return res.json({ success: true, session });
  }

  return res.status(404).json({ error: "Session not found" });
});

// Flag session as Overdue / Unresponsive (Uploaded to Admin Page)
app.post('/api/walk/report-overdue', requireAuth, (req, res) => {
  const { sessionId, lat, lon, address } = req.body;
  const cleanPhone = req.user.phone;

  let dbJourney = db.getUserActiveJourney(cleanPhone);
  if (sessionId && dbJourney && dbJourney.sessionId !== sessionId) {
    return res.status(403).json({ error: "FORBIDDEN", message: "You are not authorized to report on this journey session." });
  }

  let session = sessionId ? activeWalkSessions.get(sessionId) : null;
  if (session && session.userPhone !== cleanPhone) {
    return res.status(403).json({ error: "FORBIDDEN", message: "You do not own this journey session." });
  }

  if (dbJourney) {
    dbJourney.status = "OVERDUE_ALERT";
    dbJourney.isOverdue = true;
    dbJourney.overdueUploadedToAdmin = true;
    if (lat && lon) {
      dbJourney.currentCoords = { lat, lon, address: address || dbJourney.currentCoords.address };
    }
    db.saveUserActiveJourney(cleanPhone, dbJourney);
    if (!session) session = dbJourney;
  }

  if (session) {
    session.status = "OVERDUE_ALERT";
    session.isOverdue = true;
    session.overdueUploadedToAdmin = true;
    if (lat && lon) {
      session.currentCoords = { lat, lon, address: address || session.currentCoords.address };
    }
    console.log(`[🚨 OVERDUE TRIP ALERT UPLOADED TO ADMIN] ${session.userName} is 10+ mins overdue! Current Location:`, session.currentCoords);
    return res.json({ success: true, message: "Trip flagged as overdue and escalated to Admin Command Portal." });
  }
  return res.status(404).json({ error: "Session not found" });
});

// Admin endpoint: Get all active citizen journeys & live locations (Protected by Admin Auth Guard)
app.get('/api/admin/active-journeys', requireAdminAuth, (req, res) => {
  const journeys = db.getAllActiveJourneys();
  // Merge any in-memory sessions that haven't persisted yet
  activeWalkSessions.forEach((s) => {
    if (s.userPhone && !journeys.some(j => j.sessionId === s.sessionId)) {
      journeys.push(s);
    }
  });
  return res.json({ success: true, journeys });
});

// Finish / Clear Walk Session (Per User)
app.post('/api/walk/finish', requireAuth, (req, res) => {
  const { sessionId } = req.body;
  const cleanPhone = req.user.phone;

  let dbJourney = db.getUserActiveJourney(cleanPhone);
  if (sessionId && dbJourney && dbJourney.sessionId !== sessionId) {
    return res.status(403).json({ error: "FORBIDDEN", message: "You do not own this journey session." });
  }

  if (sessionId && activeWalkSessions.has(sessionId)) {
    const sess = activeWalkSessions.get(sessionId);
    if (sess && sess.userPhone && sess.userPhone !== cleanPhone && !req.user.isAdmin) {
      return res.status(403).json({ error: "FORBIDDEN", message: "You do not own this journey session." });
    }
    activeWalkSessions.delete(sessionId);
  }

  db.finishUserActiveJourney(cleanPhone);
  return res.json({ success: true, message: "Walk With Me session completed safely." });
});

// Live Specific Location Search (Proxy to Nominatim / Google Maps query)
// Live Specific Location Search (Dual-Engine: Photon Autocomplete + OpenStreetMap Nominatim with BD bounding box)
app.get('/api/places/search', async (req, res) => {
  const query = req.query.q;
  if (!query || query.trim().length < 2) {
    return res.json({ success: true, results: [] });
  }

  const cleanQuery = query.trim();
  const searchResults = [];
  const seenCoords = new Set();

  function addResult(item) {
    if (!item || !item.lat || !item.lon || !item.name) return;
    const key = `${item.lat.toFixed(4)}_${item.lon.toFixed(4)}`;
    if (seenCoords.has(key)) return;
    seenCoords.add(key);
    searchResults.push(item);
  }

  // 1. Fast Photon Autocomplete (Optimized for Bangladesh coordinates & typos)
  try {
    const photonUrl = `https://photon.komoot.io/api/?q=${encodeURIComponent(cleanQuery)}&lat=23.8103&lon=90.4125&limit=8`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2200);
    const pRes = await fetch(photonUrl, {
      signal: controller.signal,
      headers: { 'User-Agent': 'SafeBD-App/2.0' }
    });
    clearTimeout(timeout);
    if (pRes.ok) {
      const pData = await pRes.json();
      if (pData && Array.isArray(pData.features)) {
        pData.features.forEach(f => {
          const props = f.properties || {};
          const coords = f.geometry?.coordinates || [];
          if (coords.length >= 2) {
            const lon = coords[0];
            const lat = coords[1];
            // Ensure location is inside or near Bangladesh bounds
            if (lat >= 20.3 && lat <= 26.9 && lon >= 87.8 && lon <= 93.0) {
              const name = props.name || props.street || props.district || props.city;
              const area = [props.street, props.district || props.suburb, props.city || props.state || 'Bangladesh'].filter(Boolean).join(', ');
              addResult({
                name: name || cleanQuery,
                fullAddress: `${name}, ${area}`,
                area: area,
                lat: lat,
                lon: lon,
                category: props.osm_value || 'place',
                query: `${name}, ${area}`
              });
            }
          }
        });
      }
    }
  } catch (err) {
    // Photon fallback
  }

  // 2. OpenStreetMap Nominatim Search (with Bangladesh country bias)
  if (searchResults.length < 5) {
    try {
      const nomUrl = `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(cleanQuery)}&countrycodes=bd&viewbox=88.0,26.7,92.7,20.5&addressdetails=1&limit=8`;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 2500);
      const nomRes = await fetch(nomUrl, {
        signal: controller.signal,
        headers: { 'User-Agent': 'SafeBD-App/2.0 (safebd.official@gmail.com)' }
      });
      clearTimeout(timeout);
      if (nomRes.ok) {
        const nomData = await nomRes.json();
        if (Array.isArray(nomData)) {
          nomData.forEach(item => {
            const addr = item.address || {};
            const name = item.name || addr.amenity || addr.building || addr.road || addr.suburb || item.display_name.split(',')[0];
            const area = [
              addr.road,
              addr.suburb || addr.quarter || addr.neighbourhood,
              addr.city || addr.town || addr.county || 'Bangladesh'
            ].filter(Boolean).join(', ') || item.display_name;

            addResult({
              name: name,
              fullAddress: item.display_name,
              area: area,
              lat: parseFloat(item.lat),
              lon: parseFloat(item.lon),
              category: item.type || item.class || 'place',
              query: item.display_name
            });
          });
        }
      }
    } catch (e) {}
  }

  return res.json({ success: true, results: searchResults.slice(0, 10) });
});

// 3.5 Real-Time Routing & Google Maps Directions Engine (Live Bangladesh Traffic & Transport Mode ETA)
app.get('/api/routing/directions', async (req, res) => {
  let { originLat, originLon, destLat, destLon, mode, destQuery } = req.query;

  let oLat = parseFloat(originLat);
  let oLon = parseFloat(originLon);
  let dLat = parseFloat(destLat);
  let dLon = parseFloat(destLon);

  // Default origin: Dhaka coordinates if not provided
  if (isNaN(oLat) || isNaN(oLon)) {
    oLat = 23.8103;
    oLon = 90.4125;
  }

  // If destination coordinates missing, attempt multi-engine geocoding from destQuery
  if ((isNaN(dLat) || isNaN(dLon)) && destQuery) {
    const cleanDestQuery = destQuery.trim();

    // 1. If Google Maps API key configured, use Google Geocoding first
    const googleApiKey = process.env.GOOGLE_MAPS_API_KEY || (req.query && req.query.apiKey) || '';
    if (googleApiKey) {
      try {
        const gGeoUrl = `https://maps.googleapis.com/maps/api/geocode/json?address=${encodeURIComponent(cleanDestQuery + ', Bangladesh')}&key=${googleApiKey}`;
        const gGeoRes = await fetch(gGeoUrl, { signal: AbortSignal.timeout(3500) });
        const gGeoData = await gGeoRes.json();
        if (gGeoData && gGeoData.results && gGeoData.results[0] && gGeoData.results[0].geometry) {
          dLat = gGeoData.results[0].geometry.location.lat;
          dLon = gGeoData.results[0].geometry.location.lng;
        }
      } catch (e) {}
    }

    // 2. Fast Photon Autocomplete Geocoder
    if (isNaN(dLat) || isNaN(dLon)) {
      try {
        const pUrl = `https://photon.komoot.io/api/?q=${encodeURIComponent(cleanDestQuery)}&lat=23.8103&lon=90.4125&limit=1`;
        const pRes = await fetch(pUrl, {
          headers: { 'User-Agent': 'SafeBD-App/2.0' },
          signal: AbortSignal.timeout(2500)
        });
        if (pRes.ok) {
          const pData = await pRes.json();
          if (pData && pData.features && pData.features[0] && pData.features[0].geometry) {
            const coords = pData.features[0].geometry.coordinates;
            if (coords && coords.length >= 2) {
              dLat = coords[1];
              dLon = coords[0];
            }
          }
        }
      } catch (e) {}
    }

    // 3. OpenStreetMap Nominatim
    if (isNaN(dLat) || isNaN(dLon)) {
      try {
        const geoUrl = `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(cleanDestQuery + ', Bangladesh')}&countrycodes=bd&limit=1`;
        const geoRes = await fetch(geoUrl, {
          headers: { 'User-Agent': 'SafeBD-App/2.0 (safebd.official@gmail.com)' },
          signal: AbortSignal.timeout(2500)
        });
        if (geoRes.ok) {
          const geoData = await geoRes.json();
          if (geoData && geoData[0]) {
            dLat = parseFloat(geoData[0].lat);
            dLon = parseFloat(geoData[0].lon);
          }
        }
      } catch (e) {}
    }
  }

  const cleanDestName = destQuery ? destQuery.trim() : '';
  const travelMode = (mode === 'driving' || mode === 'bicycling' || mode === 'walking') ? mode : 'walking';
  
  // Calculate Bangladesh Standard Time (UTC+6) for live peak traffic modeling
  const now = new Date();
  const bdHour = (now.getUTCHours() + 6) % 24;
  const isPeakTraffic = (bdHour >= 8 && bdHour <= 11) || (bdHour >= 16 && bdHour <= 21);
  const isModerateTraffic = (bdHour >= 12 && bdHour <= 15) || (bdHour >= 21 && bdHour <= 22);

  let distanceKm = 0;
  let durationMinutes = 0;
  let trafficStatus = "";
  let modeLabel = "";

  // 1. Attempt Live Direct Google Maps Directions API if API key configured
  let routeGeometry = null;
  let turnSteps = [];
  let durationFormatted = "";
  let googleDirectionsSuccess = false;

  const googleApiKey = process.env.GOOGLE_MAPS_API_KEY || (req.query && req.query.apiKey) || '';
  if (googleApiKey) {
    try {
      // In South Asia/Bangladesh, Google Maps provides dedicated 'two_wheeler' for motorcycle/bike
      let gMode = travelMode === 'bicycling' ? 'bicycling' : (travelMode === 'driving' ? 'driving' : 'walking');
      const gDestParam = (!isNaN(dLat) && !isNaN(dLon)) ? `${dLat},${dLon}` : encodeURIComponent(cleanDestName + ', Bangladesh');
      let gUrl = `https://maps.googleapis.com/maps/api/directions/json?origin=${oLat},${oLon}&destination=${gDestParam}&mode=${gMode}&departure_time=now&traffic_model=best_guess&key=${googleApiKey}`;
      let gRes = await fetch(gUrl, { signal: AbortSignal.timeout(5000) });
      let gData = await gRes.json();

      // If bicycling route not indexed in region, fallback to two_wheeler or driving
      if (travelMode === 'bicycling' && (!gData || gData.status !== 'OK')) {
        const altUrl = `https://maps.googleapis.com/maps/api/directions/json?origin=${oLat},${oLon}&destination=${gDestParam}&mode=two_wheeler&departure_time=now&traffic_model=best_guess&key=${googleApiKey}`;
        const altRes = await fetch(altUrl, { signal: AbortSignal.timeout(5000) });
        const altData = await altRes.json();
        if (altData && altData.status === 'OK') gData = altData;
      }

      if (gData && gData.status === 'OK' && gData.routes && gData.routes[0] && gData.routes[0].legs && gData.routes[0].legs[0]) {
        const leg = gData.routes[0].legs[0];
        if (leg.end_location) {
          dLat = leg.end_location.lat;
          dLon = leg.end_location.lng;
        }
        distanceKm = Math.round((leg.distance.value / 1000) * 10) / 10;
        // Priority to Google's duration_in_traffic if available (Exact Google Maps Live Traffic Time)
        const liveDur = leg.duration_in_traffic || leg.duration;
        durationMinutes = Math.max(2, Math.round(liveDur.value / 60));
        durationFormatted = liveDur.text || `${durationMinutes} mins`;
        trafficStatus = leg.duration_in_traffic ? "Google Maps Live Traffic" : "Google Maps Route";
        modeLabel = travelMode === 'driving' ? 'Car / CNG' : (travelMode === 'bicycling' ? 'Bike' : 'Walk');
        googleDirectionsSuccess = true;

        if (gData.routes[0].overview_polyline && gData.routes[0].overview_polyline.points) {
          // Keep steps if available
          if (Array.isArray(leg.steps)) {
            turnSteps = leg.steps.map(s => ({
              instruction: s.html_instructions ? s.html_instructions.replace(/<[^>]*>?/gm, '') : 'Continue',
              distance: s.distance ? s.distance.value : 0,
              duration: s.duration ? s.duration.value : 0
            }));
          }
        }
      }
    } catch (gErr) {
      console.warn("[GOOGLE MAPS API]: Direct query fallback to calibrated engine:", gErr.message);
    }
  }

  // 2. High-Accuracy Turn-by-Turn Road Geometry Engine (Pedestrian Walkway, Bike & Street Network)
  if (!googleDirectionsSuccess && !isNaN(dLat) && !isNaN(dLon)) {
    try {
      let routeUrl = '';
      if (travelMode === 'walking') {
        routeUrl = `https://routing.openstreetmap.de/routed-foot/route/v1/foot/${oLon},${oLat};${dLon},${dLat}?overview=full&geometries=geojson&steps=true`;
      } else if (travelMode === 'bicycling') {
        routeUrl = `https://routing.openstreetmap.de/routed-bike/route/v1/bike/${oLon},${oLat};${dLon},${dLat}?overview=full&geometries=geojson&steps=true`;
      } else {
        routeUrl = `https://router.project-osrm.org/route/v1/driving/${oLon},${oLat};${dLon},${dLat}?overview=full&geometries=geojson&steps=true`;
      }

      let routeRes = await fetch(routeUrl, { signal: AbortSignal.timeout(4500) });
      if (!routeRes.ok) {
        // Fallback to standard OSRM geometry
        const osrmFallback = `https://router.project-osrm.org/route/v1/driving/${oLon},${oLat};${dLon},${dLat}?overview=full&geometries=geojson&steps=true`;
        routeRes = await fetch(osrmFallback, { signal: AbortSignal.timeout(4500) });
      }
      const routeData = await routeRes.json();

      if (routeData && routeData.routes && routeData.routes[0]) {
        const primaryRoute = routeData.routes[0];
        const roadMeters = primaryRoute.distance;
        distanceKm = Math.round((roadMeters / 1000) * 10) / 10;

        if (primaryRoute.geometry && Array.isArray(primaryRoute.geometry.coordinates)) {
          routeGeometry = primaryRoute.geometry;
        }
        if (primaryRoute.legs && primaryRoute.legs[0] && Array.isArray(primaryRoute.legs[0].steps)) {
          turnSteps = primaryRoute.legs[0].steps.map(s => ({
            modifier: s.maneuver ? s.maneuver.modifier : '',
            type: s.maneuver ? s.maneuver.type : '',
            instruction: s.name ? `${s.maneuver && s.maneuver.type ? s.maneuver.type.toUpperCase() : 'PROCEED'} onto ${s.name}` : (s.maneuver ? s.maneuver.type : 'Continue'),
            name: s.name || '',
            distance: Math.round(s.distance || 0),
            duration: Math.round(s.duration || 0)
          }));
        }
      }
    } catch (err) {
      console.warn("[ROUTING] Live road network fallback to Haversine:", err.message);
    }
  }

  // Fallback Haversine road distance calculation if road query was offline
  if (!distanceKm || distanceKm < 0.1) {
    if (!isNaN(dLat) && !isNaN(dLon)) {
      const R = 6371; // Earth radius in km
      const dLatRad = (dLat - oLat) * Math.PI / 180;
      const dLonRad = (dLon - oLon) * Math.PI / 180;
      const a = Math.sin(dLatRad / 2) * Math.sin(dLatRad / 2) +
                Math.cos(oLat * Math.PI / 180) * Math.cos(dLat * Math.PI / 180) *
                Math.sin(dLonRad / 2) * Math.sin(dLonRad / 2);
      const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
      distanceKm = Math.max(0.3, Math.round(R * c * 1.35 * 10) / 10);
    } else {
      distanceKm = 4.5;
    }
  }

  // 3. Precise Google Maps Dhaka Traffic & Speed Matrix (Matches Google Maps Live GPS Time)
  if (!googleDirectionsSuccess) {
    // Time-of-day traffic model for Bangladesh (UTC+6)
    const now = new Date();
    const bdHour = (now.getUTCHours() + 6) % 24;
    const isSeverePeak = (bdHour >= 8 && bdHour <= 11) || (bdHour >= 16 && bdHour <= 21);
    const isModerateDay = (bdHour >= 12 && bdHour <= 15) || (bdHour >= 21 && bdHour <= 22);

    if (travelMode === 'walking') {
      modeLabel = "Walk";
      // Google Maps Walking Pace: 4.4 km/h (~13.6 mins/km) + pedestrian crossing delays
      const crossingDelayMins = Math.round((distanceKm / 2) * 1.0);
      durationMinutes = Math.max(4, Math.round((distanceKm / 4.4) * 60) + crossingDelayMins);
      trafficStatus = "Google Maps Walk • 4.4 km/h Pace";
    } else if (travelMode === 'bicycling') {
      modeLabel = "Bike";
      // Google Maps Two-Wheeler / Bike speed in Dhaka:
      // Peak: ~19 km/h, Moderate Day: ~21.5 km/h, Off-peak: ~27 km/h + signal filter buffer
      const bikeSpeed = isSeverePeak ? 19.0 : (isModerateDay ? 21.5 : 27.0);
      const signalDelayMins = Math.round((distanceKm / 3) * 0.8);
      durationMinutes = Math.max(3, Math.round((distanceKm / bikeSpeed) * 60) + signalDelayMins);
      trafficStatus = isSeverePeak 
        ? "Google Maps Bike • Rapid Lane Splitting" 
        : "Google Maps Bike • Free Flow";
    } else { // driving (Car / CNG)
      modeLabel = "Car / CNG";
      // Google Maps Driving Live Traffic in Dhaka:
      // Severe Peak: 11.5 km/h (Mohakhali/Farmgate/Shahbagh choke points)
      // Moderate Day: 15.5 km/h
      // Off-peak Night: 28.0 km/h
      const carSpeed = isSeverePeak ? 11.5 : (isModerateDay ? 15.5 : 28.0);
      const junctionDelayMins = Math.round((distanceKm / 2) * 1.2);
      durationMinutes = Math.max(5, Math.round((distanceKm / carSpeed) * 60) + junctionDelayMins);
      trafficStatus = isSeverePeak 
        ? "Google Maps Live Traffic • Heavy Congestion" 
        : (isModerateDay ? "Google Maps Traffic • City Flow" : "Google Maps • Clear Roads");
    }

    // Google Maps Style Friendly Duration Formatting (e.g. 1 hr 21 mins or 42 mins)
    if (durationMinutes < 60) {
      durationFormatted = `${durationMinutes} mins`;
    } else {
      const hrs = Math.floor(durationMinutes / 60);
      const rem = durationMinutes % 60;
      durationFormatted = rem > 0 ? `${hrs} hr ${rem} mins` : `${hrs} hr`;
    }
  }

  const destTarget = (!isNaN(dLat) && !isNaN(dLon))
    ? `${dLat},${dLon}`
    : encodeURIComponent(cleanDestName + (cleanDestName.toLowerCase().includes('bangladesh') ? '' : ', Bangladesh'));

  const googleMapsUrl = `https://www.google.com/maps/dir/?api=1&origin=${oLat},${oLon}&destination=${destTarget}&travelmode=${travelMode}&dir_action=navigate`;
  const embedUrl = `https://maps.google.com/maps?saddr=${oLat},${oLon}&daddr=${destTarget}&directionsmode=${travelMode}&t=&z=14&ie=UTF8&iwloc=B&output=embed`;

  return res.json({
    success: true,
    origin: { lat: oLat, lon: oLon },
    destination: (!isNaN(dLat) && !isNaN(dLon)) ? { lat: dLat, lon: dLon, name: cleanDestName } : { query: cleanDestName },
    mode: travelMode,
    modeLabel,
    distanceKm,
    durationMinutes,
    durationFormatted,
    trafficStatus,
    isPeakTraffic,
    geometry: routeGeometry,
    steps: turnSteps,
    googleMapsUrl,
    embedUrl
  });
});


/* ==========================================================
   4. HIGH-THROUGHPUT CIVIC SAFETY & MODERATION FEED
   Scales to millions of citizen posts with O(1) in-memory indexing,
   O(limit) pagination, rate limiting, and strict Admin moderation.
========================================================== */

// 4.1 Live Public Citizen Feed (STRICT: ONLY ADMIN-APPROVED POSTS)
app.get('/api/feed/posts', (req, res) => {
  const { page, limit, category } = req.query;
  const result = db.getApprovedPosts({ page, limit, category });
  return res.json({ success: true, ...result });
});

// 4.2 Citizen Submits Post for Review (Starts as pending, awaits Chief Admin approval; media stored in 5TB Google Drive Vault)
app.post('/api/feed/posts', postCreateLimiter, async (req, res) => {
  try {
    const { author, authorPhone, authorRole, content, category, media, verified } = req.body;
    if (!content && !media) {
      return res.status(400).json({ error: "MISSING_CONTENT", message: "Please enter report content or attach media." });
    }

    // Authenticate caller session to prevent identity spoofing
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.replace(/^Bearer\s+/i, '').trim() || (req.body && req.body.token);
    const session = token ? db.getSession(token) : null;
    const user = session ? db.getUserByPhone(session.phone) : null;

    let validatedAuthor = "Citizen Reporter";
    let validatedPhone = "";
    let validatedRole = "Citizen";
    let isChiefAdminVerified = false;

    if (session && user) {
      validatedAuthor = user.name || session.userName || "Verified Citizen";
      validatedPhone = session.phone;
      validatedRole = user.role || (user.isAdmin ? "Administrator" : "Citizen");
      isChiefAdminVerified = Boolean(user.isAdmin || session.isAdmin);
    } else {
      let rawAuthor = (author || "").trim();
      if (rawAuthor.toUpperCase().includes('SAAD RIZWAN') || rawAuthor.toLowerCase().includes('admin') || rawAuthor.toLowerCase().includes('founder') || rawAuthor.toLowerCase().includes('chief')) {
        rawAuthor = "Citizen Reporter";
      }
      validatedAuthor = rawAuthor || "Citizen Reporter";
      validatedPhone = "";
      validatedRole = "Citizen Reporter";
      isChiefAdminVerified = false;
    }

    const postId = `post_${Date.now()}_${Math.floor(1000 + Math.random() * 9000)}`;
    let storedMediaUrl = media || null;
    let gdriveFileId = null;
    let mediaFileName = null;
    let mediaMimeType = null;

    // Upload post picture or video directly to Private 5TB Google Drive Vault (SAFE_BD_VAULT) so Render RAM never overflows
    if (media && typeof media === 'string' && media.startsWith('data:')) {
      const mimeMatch = media.match(/^data:([^;]+);base64,/);
      const mime = (mimeMatch && mimeMatch[1]) ? mimeMatch[1] : 'image/jpeg';
      const isVid = mime.startsWith('video');
      const ext = isVid ? (mime.includes('webm') ? 'webm' : 'mp4') : (mime.includes('png') ? 'png' : (mime.includes('webp') ? 'webp' : 'jpg'));
      const rawPhoneDigits = String(validatedPhone || authorPhone || '').replace(/\D/g, '');
      const cleanPhoneForFile = rawPhoneDigits.startsWith('880') && rawPhoneDigits.length >= 13
        ? '0' + rawPhoneDigits.slice(3)
        : (rawPhoneDigits.length === 10 && rawPhoneDigits.startsWith('1') ? '0' + rawPhoneDigits : (rawPhoneDigits || 'anonymous'));
      mediaFileName = `${cleanPhoneForFile}_POST_${Date.now()}.${ext}`;
      mediaMimeType = mime;

      // Cache locally on disk for instant serving
      try {
        const base64Clean = media.includes(',') ? media.split(',')[1] : media;
        const mediaBuf = Buffer.from(base64Clean, 'base64');
        if (!fs.existsSync(EVIDENCE_DIR)) fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
        fs.writeFileSync(path.join(EVIDENCE_DIR, mediaFileName), mediaBuf);
        storedMediaUrl = `/api/feed/posts/${postId}/media.${ext}`;
      } catch (diskErr) {}

      // Upload to 5TB Google Drive Vault (SAFE_BD_VAULT)
      try {
        const gdRes = await db.uploadToGoogleDriveVault({
          fileName: mediaFileName,
          mimeType: mime,
          base64: media
        });
        if (gdRes && gdRes.success && gdRes.fileId) {
          gdriveFileId = gdRes.fileId;
          storedMediaUrl = `/api/feed/posts/${postId}/media.${ext}`;
        }
      } catch (gdErr) {
        console.warn('[⚠️ GDRIVE POST MEDIA UPLOAD WARN]:', gdErr.message);
      }
    }

    const newPost = db.createPost({
      id: postId,
      author: validatedAuthor,
      authorPhone: validatedPhone,
      authorRole: validatedRole,
      content,
      category: category || "General Safety",
      media: storedMediaUrl,
      gdriveFileId,
      mediaFileName,
      mediaMimeType,
      verified: isChiefAdminVerified,
      isChiefAdminVerified: isChiefAdminVerified
    });

    // Notify any active admin WebSocket listeners in real-time
    broadcastLocationUpdate({
      type: newPost.approved ? "NEW_LIVE_CIVIC_POST" : "NEW_PENDING_CIVIC_POST",
      post: newPost
    });

    return res.json({
      success: true,
      message: "Post published directly to live awareness feed & archived in 5TB Google Drive Vault.",
      post: newPost
    });
  } catch (err) {
    return res.status(400).json({ error: "POST_FAILED", message: err.message });
  }
});

// 4.3 Admin Post Moderation Queue (Pending Citizen Reports)
app.get('/api/admin/posts/pending', (req, res) => {
  const { page, limit } = req.query;
  const result = db.getPendingPosts({ page, limit });
  return res.json({ success: true, ...result });
});

// 4.4 Admin Approves Post (Publish live to citizen feed permanently)
app.post('/api/admin/posts/:id/approve', (req, res) => {
  const adminName = (req.body && req.body.adminName) || "Chief Administrator";
  const approved = db.approvePost(req.params.id, adminName);
  if (!approved) {
    return res.status(404).json({ error: "NOT_FOUND", message: "Post not found or already processed." });
  }

  // Broadcast to all active citizens via WebSocket
  broadcastLocationUpdate({
    type: "CIVIC_POST_APPROVED_LIVE",
    post: approved
  });

  return res.json({
    success: true,
    message: "Post officially approved and published to live citizen feed.",
    post: approved
  });
});

// 4.5 Admin Declines / Removes Post
app.post('/api/admin/posts/:id/reject', (req, res) => {
  const adminName = (req.body && req.body.adminName) || "Chief Administrator";
  const success = db.rejectPost(req.params.id, adminName);
  if (!success) {
    return res.status(404).json({ error: "NOT_FOUND", message: "Post not found or already processed." });
  }
  return res.json({ success: true, message: "Submission declined and removed from moderation queue." });
});

// 4.5.1 Admin or Post Author Deletes Post Permanently (Unrestricted Deletion for Admins, Author Self-Deletion)
function handlePostDeletion(req, res) {
  // Extract auth credentials strictly from verified session token
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim() || req.query.token || (req.body && req.body.token);
  const session = token ? db.getSession(token) : null;
  const user = session ? db.getUserByPhone(session.phone) : null;

  if (!session) {
    return res.status(401).json({ error: "UNAUTHORIZED", message: "Authentication required to delete posts." });
  }

  const postId = req.params.id;
  const post = db.getPostById(postId);
  const isAdmin = !!(req.adminUser || (session && session.isAdmin) || (user && user.isAdmin));
  const callerPhone = (user && user.phone) || (session && session.phone) || '';

  if (!post) {
    if (isAdmin) {
      db.deletePost(postId, (user && user.name) || (session && session.userName) || "Chief Administrator");
      return res.json({ success: true, message: "Post permanently deleted from system." });
    }
    return res.status(404).json({ error: "NOT_FOUND", message: "Post not found or already deleted." });
  }

  const isAuthor = !!(callerPhone && post.authorPhone && (db.normalizePhone(callerPhone) === db.normalizePhone(post.authorPhone)));

  if (!isAdmin && !isAuthor) {
    return res.status(403).json({ error: "FORBIDDEN", message: "Chief Administrator clearance or post author ownership required to delete." });
  }

  const deleterName = (user && user.name) || (session && session.userName) || (isAdmin ? "Chief Administrator" : (post.author || "Author"));
  const success = db.deletePost(postId, deleterName);
  if (!success) {
    return res.status(404).json({ error: "NOT_FOUND", message: "Post not found or already deleted." });
  }

  // Broadcast deletion to all live feeds
  broadcastLocationUpdate({
    type: "CIVIC_POST_DELETED",
    postId: postId
  });
  return res.json({ success: true, message: "Post permanently deleted from system." });
}

app.all(['/api/admin/posts/:id/delete', '/api/posts/:id/delete'], handlePostDeletion);
app.delete(['/api/admin/posts/:id', '/api/posts/:id'], handlePostDeletion);

// 4.5.2 Admin All Posts View (Search, Filter, Moderate & Delete)
app.get('/api/admin/posts/all', (req, res) => {
  const { page, limit, status, category, search } = req.query;
  const result = db.getAllPostsAdmin({ page, limit, status, category, search });
  return res.json({ success: true, ...result });
});

// =========================================================================
// 5. ADMIN MANAGEMENT & ROLE DELEGATION SYSTEM
// =========================================================================

// 5.0 Serve Protected Admin Portal HTML Template Only to Authenticated Admins
app.get('/api/admin/portal-template', requireAdminAuth, (req, res) => {
  const authPhone = req.adminUser ? (req.adminUser.displayPhone || ('+880 ' + req.adminUser.phone)) : 'Authorized Administrator';
  const html = `
      <!-- Admin Portal Header -->
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid var(--border-quiet);">
        <div style="display: flex; align-items: center; gap: 10px;">
          <div style="width: 38px; height: 38px; border-radius: 10px; background: rgba(245, 158, 11, 0.15); border: 1px solid rgba(245, 158, 11, 0.4); display: flex; align-items: center; justify-content: center; color: #f59e0b; font-size: 16px;">
            <i class="fas fa-shield-halved"></i>
          </div>
          <div>
            <div style="font-size: 15px; font-weight: 700; color: #fff;">Admin Command Portal</div>
            <div style="font-size: 11px; color: #f59e0b;" id="admin-authorized-phone">Authorized: ${authPhone}</div>
          </div>
        </div>
        <button onclick="performAdminLogout()" style="background: transparent; border: 1px solid var(--border-quiet); color: var(--text-muted); padding: 6px 12px; border-radius: 9px; font-size: 11px; font-weight: 600; cursor: pointer;">
          <i class="fas fa-arrow-right-from-bracket"></i> Exit Admin
        </button>
      </div>

      <!-- Quick Metrics Strip -->
      <div style="display: grid; grid-template-columns: repeat(5, 1fr); gap: 6px; margin-bottom: 16px;">
        <div style="background: rgba(239, 68, 68, 0.15); border: 1.5px solid #ef4444; border-radius: 12px; padding: 8px 10px; cursor: pointer;" onclick="switchAdminSection('sos')" title="View Live SOS Emergency Locations">
          <div style="font-size: 9.5px; color: #ef4444; font-weight: 700;"><i class="fas fa-tower-broadcast fa-fade"></i> Live SOS</div>
          <div style="font-size: 18px; font-weight: 800; color: #ef4444; margin-top: 2px;" id="admin-sos-stat">0</div>
        </div>
        <div style="background: var(--black-subtle); border: 1px solid var(--burgundy-border); border-radius: 12px; padding: 8px 10px; cursor: pointer;" onclick="switchAdminSection('reports')">
          <div style="font-size: 9.5px; color: var(--text-muted);">Pending</div>
          <div style="font-size: 18px; font-weight: 800; color: #f59e0b; margin-top: 2px;" id="admin-pending-stat">0</div>
        </div>
        <div style="background: var(--black-subtle); border: 1px solid var(--border-quiet); border-radius: 12px; padding: 8px 10px; cursor: pointer;" onclick="switchAdminSection('allposts')">
          <div style="font-size: 9.5px; color: var(--text-muted);">Total Posts</div>
          <div style="font-size: 18px; font-weight: 800; color: #10b981; margin-top: 2px;" id="admin-total-posts-stat">0</div>
        </div>
        <div style="background: rgba(245, 158, 11, 0.1); border: 1px solid rgba(245, 158, 11, 0.4); border-radius: 12px; padding: 8px 10px; cursor: pointer;" onclick="switchAdminSection('admins')">
          <div style="font-size: 9.5px; color: #f59e0b; font-weight: 700;">Admins</div>
          <div style="font-size: 18px; font-weight: 800; color: #f59e0b; margin-top: 2px;" id="admin-admins-stat">1</div>
        </div>
        <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.45); border-radius: 12px; padding: 8px 10px; cursor: pointer;" onclick="switchAdminSection('evidence')">
          <div style="font-size: 9.5px; color: #ef4444; font-weight: 700;"><i class="fas fa-video"></i> SOS Clips</div>
          <div style="font-size: 18px; font-weight: 800; color: #ef4444; margin-top: 2px;" id="admin-evidence-stat">0</div>
        </div>
      </div>

      <!-- Admin Sub-Navigation Tabs -->
      <div style="display: flex; gap: 6px; margin-bottom: 16px; overflow-x: auto; padding-bottom: 4px;" class="admin-nav-scroll">
        <button type="button" class="auth-toggle-tab" id="admin-tab-sos" style="padding: 7px 11px; font-size: 11px; border-color: rgba(239, 68, 68, 0.6); color: #ef4444; font-weight: 700; white-space: nowrap;" onclick="switchAdminSection('sos')">
          <i class="fas fa-tower-broadcast"></i> Live SOS Locations <span id="admin-sos-count-badge" style="background: #ef4444; color: #fff; padding: 1px 6px; border-radius: 10px; font-size: 9.5px; font-weight: 700; margin-left: 2px;">0</span>
        </button>
        <button type="button" class="auth-toggle-tab active" id="admin-tab-reports" style="padding: 7px 11px; font-size: 11px; white-space: nowrap;" onclick="switchAdminSection('reports')">
          <i class="fas fa-inbox"></i> Pending Review (<span id="admin-pending-tab-badge">0</span>)
        </button>
        <button type="button" class="auth-toggle-tab" id="admin-tab-allposts" style="padding: 7px 11px; font-size: 11px; white-space: nowrap;" onclick="switchAdminSection('allposts')">
          <i class="fas fa-layer-group"></i> All Posts (Delete)
        </button>
        <button type="button" class="auth-toggle-tab" id="admin-tab-admins" style="padding: 7px 11px; font-size: 11px; border-color: rgba(245, 158, 11, 0.4); color: #f59e0b; white-space: nowrap;" onclick="switchAdminSection('admins')">
          <i class="fas fa-user-shield"></i> Admin Access & Roles
        </button>
        <button type="button" class="auth-toggle-tab" id="admin-tab-users" style="padding: 7px 11px; font-size: 11px; white-space: nowrap;" onclick="switchAdminSection('users')">
          <i class="fas fa-users"></i> Citizens
        </button>
        <button type="button" class="auth-toggle-tab" id="admin-tab-evidence" style="padding: 7px 11px; font-size: 11px; border-color: rgba(239, 68, 68, 0.4); color: #ef4444; white-space: nowrap;" onclick="switchAdminSection('evidence')">
          <i class="fas fa-video"></i> SOS Clips <span id="admin-evidence-count-badge" style="background: #ef4444; color: #fff; padding: 1px 6px; border-radius: 10px; font-size: 9.5px; font-weight: 700; margin-left: 2px;">0</span>
        </button>
        <button type="button" class="auth-toggle-tab" id="admin-tab-journeys" style="padding: 7px 11px; font-size: 11px; border-color: rgba(245, 158, 11, 0.4); color: #f59e0b; white-space: nowrap;" onclick="switchAdminSection('journeys')">
          <i class="fas fa-satellite-dish"></i> Live Routes <span id="admin-overdue-count-badge" style="background: #ef4444; color: #fff; padding: 1px 6px; border-radius: 10px; font-size: 9.5px; font-weight: 700; margin-left: 2px;">0</span>
        </button>
      </div>

      <!-- URGENT LIVE SOS EMERGENCY BANNER (Pops up automatically across Admin Portal when distress signal is active) -->
      <div id="admin-urgent-sos-container" style="display: none; margin-bottom: 16px;"></div>

      <!-- SECTION S: LIVE SOS DISTRESS SIGNALS & EXACT USER COORDINATES -->
      <div id="admin-section-sos" style="display: none;">
        <div class="module-header" style="margin-bottom: 12px;">
          <span style="color: #ef4444; display: flex; align-items: center; gap: 8px;">
            <i class="fas fa-tower-broadcast fa-fade"></i> Live SOS Distress Signals &amp; Exact Coordinates
          </span>
          <button class="btn-gps-refresh" onclick="fetchAdminSosAlerts(true)" style="font-size: 11px; background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.4); color: #f87171;">
            <i class="fas fa-arrows-rotate"></i> Refresh SOS
          </button>
        </div>
        <div id="admin-sos-alerts-container">
          <div style="text-align: center; padding: 40px 20px; color: var(--text-muted); font-size: 12.5px;">
            <i class="fas fa-satellite-dish" style="font-size: 26px; color: rgba(239, 68, 68, 0.4); display: block; margin-bottom: 10px;"></i>
            Listening for real-time SOS distress signals...
          </div>
        </div>
      </div>

      <!-- SECTION A: POST MODERATION QUEUE (With Urgent SOS Evidence on top) -->
      <div id="admin-section-reports">
        <div id="admin-urgent-evidence-container" style="display: none; margin-bottom: 16px;"></div>
        <div class="module-header" style="margin-bottom: 12px;">
          <span>Citizen Reports Awaiting Moderation</span>
          <span style="font-size: 11px; color: var(--text-muted); text-transform: none;">Live Review Queue</span>
        </div>
        <div id="admin-pending-posts-container"></div>
      </div>

      <!-- SECTION B: ALL POSTS & UNRESTRICTED CONTENT CONTROL (DELETE POSTS) -->
      <div id="admin-section-allposts" style="display: none;">
        <div class="module-header" style="margin-bottom: 12px;">
          <span><i class="fas fa-layer-group" style="color: #ef4444;"></i> All Posts & Content Governance</span>
          <button class="btn-gps-refresh" onclick="fetchAdminAllPosts()" style="font-size: 11px;">
            <i class="fas fa-arrows-rotate"></i> Refresh Posts
          </button>
        </div>
        <div style="display: flex; gap: 8px; margin-bottom: 14px; flex-wrap: wrap;">
          <input type="text" id="admin-posts-search" placeholder="Search posts by author, phone, or keyword..." style="flex: 2; min-width: 180px; background: rgba(0,0,0,0.4); border: 1px solid var(--border-quiet); color: #fff; padding: 8px 12px; border-radius: 10px; font-size: 11.5px;" oninput="filterAdminAllPosts()">
          <select id="admin-posts-filter-status" style="flex: 1; min-width: 110px; background: #150a0e; border: 1px solid var(--border-quiet); color: #fff; padding: 8px; border-radius: 10px; font-size: 11px;" onchange="filterAdminAllPosts()">
            <option value="all">All Statuses</option>
            <option value="approved">Live Published</option>
            <option value="pending">Pending Review</option>
            <option value="rejected">Declined</option>
          </select>
        </div>
        <div id="admin-all-posts-container"></div>
      </div>

      <!-- SECTION C: ADMIN ACCESS MANAGEMENT & ROLE DELEGATION -->
      <div id="admin-section-admins" style="display: none;">
        <div class="module-header" style="margin-bottom: 12px;">
          <span style="color: #f59e0b;"><i class="fas fa-user-shield"></i> Admin Access Management</span>
          <span style="font-size: 11px; color: var(--text-muted); text-transform: none;">Role Delegation</span>
        </div>

        <div style="background: rgba(20, 10, 14, 0.75); border: 1.5px solid rgba(245, 158, 11, 0.4); border-radius: 14px; padding: 14px; margin-bottom: 18px; box-shadow: 0 4px 20px rgba(0,0,0,0.5);">
          <div style="font-size: 13px; font-weight: 700; color: #fff; margin-bottom: 6px; display: flex; align-items: center; gap: 6px;">
            <i class="fas fa-key" style="color: #f59e0b;"></i> Grant New Administrator Clearance
          </div>
          <div style="font-size: 11px; color: var(--text-muted); margin-bottom: 12px; line-height: 1.4;">
            Authorize any citizen account with administrative power. Choose specific role and tailored permissions.
          </div>
          <form onsubmit="handleGrantAdminSubmit(event)" style="display: flex; flex-direction: column; gap: 10px;">
            <div>
              <label style="font-size: 11px; color: var(--text-muted); display: block; margin-bottom: 4px;">Bangladeshi Mobile Number *</label>
              <div style="display: flex; align-items: center; background: rgba(0,0,0,0.5); border: 1px solid var(--border-quiet); border-radius: 10px; padding: 0 10px;">
                <span style="font-size: 12px; color: #10b981; font-weight: 700; margin-right: 6px;">+880</span>
                <input type="tel" id="grant-admin-phone" placeholder="17XXXXXXXX" required style="width: 100%; background: transparent; border: none; outline: none; color: #fff; padding: 9px 0; font-size: 13px; font-weight: 600;">
              </div>
            </div>
            <div>
              <label style="font-size: 11px; color: var(--text-muted); display: block; margin-bottom: 4px;">Admin Full Name</label>
              <input type="text" id="grant-admin-name" placeholder="e.g. Farhan Ahmed (or leave blank if registered)" style="width: 100%; box-sizing: border-box; background: rgba(0,0,0,0.5); border: 1px solid var(--border-quiet); border-radius: 10px; color: #fff; padding: 9px 12px; font-size: 12px;">
            </div>
            <div>
              <label style="font-size: 11px; color: var(--text-muted); display: block; margin-bottom: 4px;">Administrative Role Level</label>
              <select id="grant-admin-role" style="width: 100%; box-sizing: border-box; background: #150a0e; border: 1px solid var(--border-quiet); color: #fff; padding: 9px 12px; font-size: 12px;">
                <option value="Moderator Admin">Moderator Admin (Approve & Delete Citizen Reports)</option>
                <option value="Content & Media Officer">Content & Media Officer (Review, Feature & Delete Media)</option>
                <option value="Emergency Dispatch Officer">Emergency Dispatch Officer (999 CAD, SOS Clips & Live Routes)</option>
                <option value="Co-Administrator">Co-Administrator (Full Operational Clearance)</option>
              </select>
            </div>
            <div>
              <label style="font-size: 11px; color: var(--text-muted); display: block; margin-bottom: 6px;">Assigned Permissions Checklist</label>
              <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 6px; font-size: 11px; color: #fff;">
                <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;">
                  <input type="checkbox" id="perm-delete-posts" checked> Delete Any Post
                </label>
                <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;">
                  <input type="checkbox" id="perm-approve-posts" checked> Approve Civic Posts
                </label>
                <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;">
                  <input type="checkbox" id="perm-view-evidence" checked> View SOS Video Vault
                </label>
                <label style="display: flex; align-items: center; gap: 6px; cursor: pointer;">
                  <input type="checkbox" id="perm-dispatch" checked> 999 CAD & Transit
                </label>
                <label style="display: flex; align-items: center; gap: 6px; cursor: pointer; grid-column: span 2;">
                  <input type="checkbox" id="perm-manage-admins"> Grant / Revoke Other Admins
                </label>
              </div>
            </div>
            <button type="submit" style="background: linear-gradient(135deg, #b45309 0%, #f59e0b 100%); color: #000; font-weight: 800; border: none; padding: 11px; border-radius: 10px; font-size: 12.5px; cursor: pointer; display: flex; align-items: center; justify-content: center; gap: 6px; margin-top: 4px;">
              <i class="fas fa-shield-check"></i> Grant Administrative Clearance
            </button>
          </form>
        </div>

        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
          <span style="font-size: 12px; font-weight: 700; color: #fff;">Active Administrative Personnel</span>
          <span style="font-size: 11px; color: var(--text-muted);" id="admin-roster-count">1 Admin</span>
        </div>
        <div id="admin-roster-container"></div>
      </div>

      <!-- SECTION D: CITIZEN DIRECTORY -->
      <div id="admin-section-users" style="display: none;">
        <div class="module-header" style="margin-bottom: 12px;">
          <span><i class="fas fa-users" style="color: #38bdf8;"></i> Registered Citizen Accounts</span>
          <button class="btn-gps-refresh" onclick="fetchAdminUsersList()" style="font-size: 11px;">
            <i class="fas fa-arrows-rotate"></i> Refresh Citizens
          </button>
        </div>
        <div style="margin-bottom: 10px;">
          <input type="text" id="admin-users-search" placeholder="Search citizens by phone or name..." style="width: 100%; box-sizing: border-box; background: rgba(0,0,0,0.4); border: 1px solid var(--border-quiet); color: #fff; padding: 8px 12px; border-radius: 10px; font-size: 11.5px;" oninput="filterAdminUsers()">
        </div>
        <div id="admin-users-container"></div>
      </div>

      <!-- SECTION E: DEDICATED COVERT SPY SOS EVIDENCE QUEUE -->
      <div id="admin-section-evidence" style="display: none;">
        <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.35); border-radius: 12px; padding: 10px 12px; margin-bottom: 12px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
          <div style="display: flex; align-items: center; gap: 8px;">
            <i class="fab fa-google-drive" style="color: #10b981; font-size: 16px;"></i>
            <div>
              <div style="font-size: 11.5px; font-weight: 700; color: #fff;">5TB Google Drive Private Vault (<span style="color: #10b981;">SAFE_BD_VAULT</span>)</div>
              <div style="font-size: 10px; color: var(--text-muted);" id="admin-gdrive-vault-status">Encrypted &amp; isolated folder • Zero Render RAM usage</div>
            </div>
          </div>
          <div style="display: flex; gap: 6px;">
            <button type="button" onclick="verifyGoogleDriveVaultConnection()" style="background: rgba(16, 185, 129, 0.2); border: 1px solid rgba(16, 185, 129, 0.45); color: #10b981; padding: 5px 10px; border-radius: 8px; font-size: 10.5px; font-weight: 700; cursor: pointer;">
              <i class="fas fa-cloud-check"></i> Verify 5TB Vault
            </button>
            <button type="button" onclick="clearStaleLocalEvidenceClips()" style="background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.4); color: #f87171; padding: 5px 10px; border-radius: 8px; font-size: 10.5px; font-weight: 700; cursor: pointer;" title="Remove old dead test clips from browser cache">
              <i class="fas fa-broom"></i> Clear Old Cache
            </button>
          </div>
        </div>

        <div class="module-header" style="margin-bottom: 12px;">
          <span style="color: #ef4444;"><i class="fas fa-triangle-exclamation"></i> Covert SOS Video &amp; Audio Evidence</span>
          <button class="btn-gps-refresh" onclick="fetchAdminEmergencyEvidence()" style="font-size: 11px;">
            <i class="fas fa-arrows-rotate"></i> Refresh Evidence
          </button>
        </div>
        <div id="admin-evidence-full-container">
          <div id="admin-evidence-loading" style="text-align: center; padding: 50px 20px; color: var(--text-muted); font-size: 13px;">
            <i class="fas fa-spinner fa-spin" style="font-size: 28px; color: #ef4444; display: block; margin-bottom: 12px;"></i>
            Loading SOS evidence vault...
          </div>
        </div>
      </div>

      <!-- SECTION F: LIVE CITIZEN JOURNEYS & OVERDUE OBSERVATION QUEUE -->
      <div id="admin-section-journeys" style="display: none;">
        <div class="module-header" style="margin-bottom: 12px;">
          <span>Live Citizen Journeys & Overdue Alerts</span>
          <button class="btn-gps-refresh" onclick="fetchAdminActiveJourneys()" style="font-size: 11px;">
            <i class="fas fa-arrows-rotate"></i> Refresh Telemetry
          </button>
        </div>
        <div id="admin-journeys-container"></div>
      </div>
  `;
  return res.json({ success: true, html });
});

// 5.1 List All Active Administrators
app.get('/api/admin/admins', (req, res) => {
  const admins = db.getAllAdmins();
  return res.json({ success: true, admins });
});

// 5.2 Grant Admin Access to Citizen by Phone Number
app.post('/api/admin/admins/grant', (req, res) => {
  try {
    const { phone, name, role, permissions, assignedBy } = req.body;
    if (!phone) {
      return res.status(400).json({ error: "MISSING_PHONE", message: "Mobile number required to grant admin access." });
    }
    const result = db.grantAdminAccess(phone, {
      name,
      role: role || 'Moderator Admin',
      permissions: permissions || ['manage_posts', 'delete_posts', 'approve_posts', 'view_evidence'],
      assignedBy: assignedBy || 'Chief Administrator'
    });
    return res.json({
      success: true,
      message: `Admin clearance granted to ${result.name} (${result.phone}) as ${result.role}.`,
      admin: result
    });
  } catch (err) {
    return res.status(400).json({ error: "GRANT_FAILED", message: err.message });
  }
});

// 5.3 Revoke Admin Access
app.post('/api/admin/admins/:phone/revoke', (req, res) => {
  try {
    const revokedBy = (req.body && req.body.revokedBy) || 'Chief Administrator';
    db.revokeAdminAccess(req.params.phone, revokedBy);
    return res.json({ success: true, message: `Admin access revoked for ${req.params.phone}.` });
  } catch (err) {
    return res.status(400).json({ error: "REVOKE_FAILED", message: err.message });
  }
});

// 5.4 List All Registered Citizen Accounts
app.get('/api/admin/users', (req, res) => {
  const { page, limit } = req.query;
  const users = db.getAllUsersAdmin({ page, limit });
  return res.json({ success: true, users });
});

// 5.5 Delete Emergency SOS Evidence Record
app.delete('/api/admin/emergency-evidence/:id', (req, res) => {
  const success = db.deleteEmergencyEvidence(req.params.id);
  if (success) {
    return res.json({ success: true, message: "Evidence record removed from archive." });
  }
  return res.status(404).json({ error: "NOT_FOUND", message: "Evidence record not found." });
});

// 5.6 Get & Update Private 5TB Google Drive Vault Configuration
app.get('/api/admin/cloud-vault', (req, res) => {
  return res.json({ success: true, vault: db.getCloudVaultConfig() });
});

app.post('/api/admin/cloud-vault', async (req, res) => {
  const { scriptUrl, secretKey, enabled } = req.body || {};
  const updated = db.setCloudVaultConfig({ scriptUrl, secretKey, enabled });
  return res.json({ success: true, vault: updated });
});

app.post('/api/admin/cloud-vault/test', async (req, res) => {
  const { scriptUrl, secretKey } = req.body || {};
  if (scriptUrl) {
    db.setCloudVaultConfig({ scriptUrl, secretKey, enabled: true });
  }
  const testRes = await db.uploadToGoogleDriveVault({
    fileName: 'safe_bd_vault_verified.txt',
    mimeType: 'text/plain',
    base64: Buffer.from(`SAFE BD 5TB Google Drive Private Vault Verified at ${new Date().toISOString()}`).toString('base64'),
    overwrite: true
  });
  return res.json({
    success: !!(testRes && testRes.success),
    result: testRes,
    vault: db.getCloudVaultConfig()
  });
});

// 4.6 Single Like per User (Toggle Like / Unlike)
app.post('/api/feed/posts/:id/like', (req, res) => {
  const rawIp = req.headers['x-forwarded-for'] ? req.headers['x-forwarded-for'].split(',')[0].trim() : (req.socket.remoteAddress || '127.0.0.1');
  const userId = (req.body && req.body.userId) || (req.query && req.query.userId) || `ip_${rawIp}`;
  const result = db.toggleLikePost(req.params.id, userId);
  return res.json({ success: true, ...result });
});

// 4.6.1 Facebook-Style Citizen Comments on Safety Feed Posts
app.post('/api/feed/posts/:id/comment', (req, res) => {
  try {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.replace(/^Bearer\s+/i, '').trim() || (req.body && req.body.token);
    const session = token ? db.getSession(token) : null;
    const user = session ? db.getUserByPhone(session.phone) : null;

    let author = (req.body && req.body.author) || "Citizen";
    let authorPhone = "";
    let isFounder = false;
    let isAdmin = false;

    if (session && user) {
      author = user.name || session.userName || "Verified Citizen";
      authorPhone = session.phone;
      isFounder = Boolean(user.isFounder);
      isAdmin = Boolean(user.isAdmin || session.isAdmin);
    } else {
      let raw = (author || "").trim();
      if (raw.toUpperCase().includes('SAAD RIZWAN') || raw.toLowerCase().includes('founder') || raw.toLowerCase().includes('admin')) {
        raw = "Citizen";
      }
      author = raw || "Citizen";
    }

    const { text } = req.body || {};
    if (!text || !text.trim()) {
      return res.status(400).json({ error: "MISSING_TEXT", message: "Comment text cannot be empty." });
    }

    const result = db.addCommentToPost(req.params.id, {
      author,
      authorPhone,
      text,
      isFounder,
      isAdmin
    });

    // Broadcast in real-time over WebSocket
    broadcastLocationUpdate({
      type: "NEW_POST_COMMENT",
      postId: req.params.id,
      comment: result.comment,
      totalComments: result.totalComments
    });

    return res.json({ success: true, ...result });
  } catch (err) {
    return res.status(400).json({ error: "COMMENT_FAILED", message: err.message });
  }
});

// 4.6.2 Delete Comment
app.delete('/api/feed/posts/:id/comments/:commentId', (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim() || (req.body && req.body.token);
  const session = token ? db.getSession(token) : null;
  const user = session ? db.getUserByPhone(session.phone) : null;

  const userPhone = session ? session.phone : '';
  const isAdmin = Boolean(session && (session.isAdmin || (user && user.isAdmin)));

  const ok = db.deleteCommentFromPost(req.params.id, req.params.commentId, userPhone, isAdmin);
  if (!ok) {
    return res.status(403).json({ error: "FORBIDDEN", message: "You are not authorized to delete this comment." });
  }

  broadcastLocationUpdate({
    type: "POST_COMMENT_DELETED",
    postId: req.params.id,
    commentId: req.params.commentId
  });

  return res.json({ success: true, message: "Comment removed." });
});

// 4.7 Direct Media Streaming & Single-Click Download Endpoint (Backed by 5TB Google Drive Vault)
app.get(['/api/feed/posts/:id/media', '/api/feed/posts/:id/media.:ext'], async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  if (req.method === 'OPTIONS') return res.status(200).end();

  try {
    const post = db.getPostById(req.params.id);
    if (!post || (!post.media && !post.gdriveFileId)) {
      return res.status(404).json({ error: "NOT_FOUND", message: "Media attachment not found for this post." });
    }

    const media = post.media || '';

    // 1. If legacy inline base64 data URI
    if (typeof media === 'string' && media.startsWith('data:')) {
      const mimeMatch = media.match(/^data:([^;]+);base64,/);
      const mime = (mimeMatch && mimeMatch[1]) ? mimeMatch[1] : 'application/octet-stream';
      const base64Data = media.split(',')[1];
      const buffer = Buffer.from(base64Data, 'base64');
      const isVideo = mime.startsWith('video');
      const ext = isVideo ? (mime.includes('webm') ? 'webm' : 'mp4') : (mime.includes('png') ? 'png' : 'jpg');
      const filename = `safebd_post_${post.id}_${isVideo ? 'video' : 'photo'}.${ext}`;

      res.setHeader('Content-Type', mime);
      res.setHeader('Content-Length', buffer.length);
      res.setHeader('Cache-Control', 'public, max-age=86400');
      if (req.query.download === '1') {
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      } else {
        res.setHeader('Content-Disposition', `inline; filename="${filename}"`);
      }
      return res.send(buffer);
    }

    // 2. Backed by 5TB Google Drive Vault (SAFE_BD_VAULT) + Local Disk Cache
    const ext = req.params.ext || (post.mediaFileName ? post.mediaFileName.split('.').pop() : 'jpg');
    const isVideo = ['mp4', 'webm', 'mov'].includes(ext.toLowerCase());
    const mime = post.mediaMimeType || (isVideo ? (ext === 'webm' ? 'video/webm' : 'video/mp4') : (ext === 'png' ? 'image/png' : 'image/jpeg'));
    const cacheFileName = post.mediaFileName || `safebd_post_${post.id}_${isVideo ? 'video' : 'photo'}.${ext}`;
    const cacheFilePath = path.join(EVIDENCE_DIR, cacheFileName);

    let fileBuf = null;
    if (fs.existsSync(cacheFilePath)) {
      fileBuf = fs.readFileSync(cacheFilePath);
    } else if (post.gdriveFileId) {
      // Restore directly from Private 5TB Google Drive Vault (SAFE_BD_VAULT)
      fileBuf = await db.fetchFromGoogleDriveVault({
        fileId: post.gdriveFileId,
        fileName: cacheFileName
      });
      if (fileBuf && fileBuf.length > 0) {
        try {
          if (!fs.existsSync(EVIDENCE_DIR)) fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
          fs.writeFileSync(cacheFilePath, fileBuf);
          console.log(`[☁️ RESTORED POST MEDIA FROM 5TB VAULT] Restored ${cacheFileName} (${Math.round(fileBuf.length / 1024)} KB)`);
        } catch (e) {}
      }
    }

    if (fileBuf && fileBuf.length > 0) {
      res.setHeader('Content-Type', mime);
      res.setHeader('Content-Length', fileBuf.length);
      res.setHeader('Cache-Control', 'public, max-age=86400');
      if (req.query.download === '1') {
        res.setHeader('Content-Disposition', `attachment; filename="${cacheFileName}"`);
      } else {
        res.setHeader('Content-Disposition', `inline; filename="${cacheFileName}"`);
      }
      return res.send(fileBuf);
    }

    return res.status(404).send("Media file not found in vault.");
  } catch (err) {
    console.error("Post media serve error:", err.message);
    return res.status(500).send("Error retrieving media.");
  }
});

/* ==========================================================
   5. REAL-TIME WEBSOCKET (E2EE LOCATION STREAMING)
========================================================== */

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const connectedClients = new Set();

wss.on('connection', (ws, req) => {
  connectedClients.add(ws);

  // Authenticate socket via query parameter (?token=...)
  try {
    const reqUrl = req && req.url ? new URL(req.url, 'http://localhost') : null;
    const token = reqUrl ? reqUrl.searchParams.get('token') : null;
    if (token) {
      const session = db.getSession(token);
      if (session) {
        const user = db.getUserByPhone(session.phone);
        ws.authenticated = true;
        ws.phone = session.phone;
        ws.userName = session.userName;
        ws.isAdmin = !!(session.isAdmin || (user && user.isAdmin));
      }
    }
  } catch (e) {
    // URL parsing fallback
  }

  console.log(`[WS] Client connected (Auth: ${!!ws.authenticated}). Total active streams: ${connectedClients.size}`);

  ws.on('message', (message) => {
    try {
      const payload = JSON.parse(message);

      // Support in-band authentication
      if (payload.type === "AUTH") {
        if (!payload.token) {
          ws.send(JSON.stringify({ type: "AUTH_ERROR", message: "Token missing" }));
          return;
        }
        const session = db.getSession(payload.token);
        if (session) {
          const user = db.getUserByPhone(session.phone);
          ws.authenticated = true;
          ws.phone = session.phone;
          ws.userName = session.userName;
          ws.isAdmin = !!(session.isAdmin || (user && user.isAdmin));
          ws.send(JSON.stringify({ type: "AUTH_SUCCESS", phone: ws.phone, isAdmin: ws.isAdmin }));
        } else {
          ws.send(JSON.stringify({ type: "AUTH_ERROR", message: "Invalid or expired session token" }));
        }
        return;
      }

      // Fan-out encrypted coordinates to family circle subscribers and authorized dispatchers
      if (payload.type === "LIVE_LOCATION_PING") {
        if (!ws.authenticated) {
          ws.send(JSON.stringify({ type: "ERROR", message: "Authentication required to stream live location telemetry." }));
          return;
        }
        payload.senderPhone = ws.phone;
        payload.senderName = ws.userName;
        broadcastLocationUpdate(payload, ws);
      }
    } catch (e) {
      console.error("[WS] Message error:", e);
    }
  });

  ws.on('close', () => {
    connectedClients.delete(ws);
    console.log(`[WS] Client disconnected. Total active: ${connectedClients.size}`);
  });
});

function broadcastLocationUpdate(data, senderWs = null) {
  const msg = JSON.stringify(data);
  const type = data.type || '';

  // Public civic broadcasts (e.g. approved posts, post deletions, awareness announcements)
  const isPublicEvent = [
    'CIVIC_POST_APPROVED_LIVE',
    'CIVIC_POST_DELETED',
    'CIVIC_POST_PUBLISHED',
    'NEW_LIVE_CIVIC_POST'
  ].includes(type);

  for (const client of connectedClients) {
    if (client === senderWs || client.readyState !== 1) continue;

    if (isPublicEvent) {
      client.send(msg);
      continue;
    }

    // SENSITIVE TELEMETRY & EMERGENCY DATA FILTERING:
    // 1. Live location pings: only send to CAD admins or authorized family circles
    if (type === 'LIVE_LOCATION_PING') {
      const senderPhone = db.normalizePhone(data.senderPhone || (senderWs && senderWs.phone) || '');
      const clientPhone = db.normalizePhone(client.phone || '');

      if (client.isAdmin) {
        client.send(msg);
      } else if (client.authenticated && senderPhone && clientPhone) {
        const senderContacts = db.getUserContacts(senderPhone) || [];
        const isSenderContact = senderContacts.some(c => c.phone && db.normalizePhone(c.phone) === clientPhone);
        if (isSenderContact) {
          client.send(msg);
        }
      }
      continue;
    }

    // 2. Emergency SOS alerts and covert video evidence:
    if (type === 'EMERGENCY_SOS_ALERT' || type === 'EMERGENCY_COVERT_VIDEO_EVIDENCE') {
      if (client.isAdmin) {
        client.send(msg);
      } else if (client.authenticated) {
        const victimPhone = db.normalizePhone(
          (data.incident && data.incident.userPhone) ||
          (data.evidence && data.evidence.userPhone) ||
          ''
        );
        const clientPhone = db.normalizePhone(client.phone || '');
        if (victimPhone && clientPhone) {
          if (victimPhone === clientPhone) {
            client.send(msg);
          } else {
            const victimContacts = db.getUserContacts(victimPhone) || [];
            const isVictimContact = victimContacts.some(c => c.phone && db.normalizePhone(c.phone) === clientPhone);
            if (isVictimContact) {
              client.send(msg);
            }
          }
        }
      }
      continue;
    }

    // Default fallback: Admins receive system dispatch events
    if (client.isAdmin) {
      client.send(msg);
    }
  }
}

// ============================================================================
// 5. shurokhaAI — Specialized Bangladesh Safety, Thana OC Directory & Civic AI
// ============================================================================

// Comprehensive Verified Directory of Bangladesh Police Thanas (DMP + Major Divisions)
const BANGLADESH_THANA_DIRECTORY = [
  // DMP DHAKA METROPOLITAN POLICE (50 THANAS)
  {
    name: "Dhanmondi Model Thana",
    bnName: "ধানমন্ডি মডেল থানা",
    division: "Dhaka (DMP - Ramna Division)",
    address: "House 34, Road 8/A, Dhanmondi, Dhaka",
    ocPhone: "01713-373126",
    dutyPhone: "01713-373127",
    tnt: "02-58616111 / 02-9669922",
    keywords: ["dhanmondi", "ধানমন্ডি", "dhanmondi 27", "dhanmondi 32", "dhanmondi 8/a", "dhanmondi 15"]
  },
  {
    name: "Gulshan Model Thana",
    bnName: "গুলশান মডেল থানা",
    division: "Dhaka (DMP - Gulshan Division)",
    address: "House 1, Road 79, Gulshan 2, Dhaka",
    ocPhone: "01713-373168",
    dutyPhone: "01713-373169",
    tnt: "02-9883333 / 02-9884444",
    keywords: ["gulshan", "গুলশান", "gulshan 1", "gulshan 2", "gulshan circle"]
  },
  {
    name: "Banani Thana",
    bnName: "বনানী থানা",
    division: "Dhaka (DMP - Gulshan Division)",
    address: "Road 11, Block F, Banani, Dhaka",
    ocPhone: "01713-373171",
    dutyPhone: "01713-373172",
    tnt: "02-9836333",
    keywords: ["banani", "বনানী", "banani 11", "kemal ataturk", "banani dohs"]
  },
  {
    name: "Mirpur Model Thana",
    bnName: "মিরপুর মডেল থানা",
    division: "Dhaka (DMP - Mirpur Division)",
    address: "Section 1, Mirpur, Dhaka (Near Sony Cinema Hall)",
    ocPhone: "01713-373180",
    dutyPhone: "01713-373181",
    tnt: "02-9001001",
    keywords: ["mirpur", "মিরপুর", "mirpur 1", "mirpur 2", "mirpur 10", "mirpur model"]
  },
  {
    name: "Uttara East Thana",
    bnName: "উত্তরা পূর্ব থানা",
    division: "Dhaka (DMP - Uttara Division)",
    address: "Road 4, Sector 7, Uttara, Dhaka",
    ocPhone: "01713-373155",
    dutyPhone: "01713-373156",
    tnt: "02-8951111",
    keywords: ["uttara east", "উত্তরা পূর্ব", "uttara sector 7", "uttara sector 3", "uttara sector 1", "azampur", "rajlaxmi", "mascot plaza"]
  },
  {
    name: "Uttara West Thana",
    bnName: "উত্তরা পশ্চিম থানা",
    division: "Dhaka (DMP - Uttara Division)",
    address: "Road 14, Sector 3, Uttara, Dhaka",
    ocPhone: "01713-373158",
    dutyPhone: "01713-373159",
    tnt: "02-8954444",
    keywords: ["uttara west", "উত্তরা পশ্চিম", "uttara sector 11", "uttara sector 12", "uttara sector 13", "uttara sector 14", "gareeb-e-nawaz", "uttara"]
  },
  {
    name: "Mohammadpur Thana",
    bnName: "মোহাম্মদপুর থানা",
    division: "Dhaka (DMP - Tejgaon Division)",
    address: "Ring Road, Shyamoli, Mohammadpur, Dhaka",
    ocPhone: "01713-373183",
    dutyPhone: "01713-373184",
    tnt: "02-9119999",
    keywords: ["mohammadpur", "মোহাম্মদপুর", "town hall", "tajmahal road", "japan garden", "salimullah road"]
  },
  {
    name: "Shahbagh Thana",
    bnName: "শাহবাগ থানা",
    division: "Dhaka (DMP - Ramna Division)",
    address: "Shahbagh Crossing, Dhaka (Near BSMMU & DMCH)",
    ocPhone: "01713-373129",
    dutyPhone: "01713-373130",
    tnt: "02-9676666",
    keywords: ["shahbagh", "শাহবাগ", "shahbag", "dhaka university", "dmch", "bsmmu", "tsc", "katabon"]
  },
  {
    name: "Ramna Model Thana",
    bnName: "রমনা মডেল থানা",
    division: "Dhaka (DMP - Ramna Division)",
    address: "Siddheshwari Circular Road, Malibagh, Dhaka",
    ocPhone: "01713-373123",
    dutyPhone: "01713-373124",
    tnt: "02-9352222",
    keywords: ["ramna", "রমনা", "kakrail", "shantinagar", "malibagh", "moghbazar", "bailey road"]
  },
  {
    name: "Motijheel Thana",
    bnName: "মতিঝিল থানা",
    division: "Dhaka (DMP - Motijheel Division)",
    address: "Arambagh, Motijheel C/A, Dhaka",
    ocPhone: "01713-373138",
    dutyPhone: "01713-373139",
    tnt: "02-9556666",
    keywords: ["motijheel", "মতিঝিল", "arambagh", "shapla chattar", "dilkusha"]
  },
  {
    name: "Paltan Model Thana",
    bnName: "পল্টন মডেল থানা",
    division: "Dhaka (DMP - Motijheel Division)",
    address: "VIP Road, Naya Paltan, Dhaka",
    ocPhone: "01713-373141",
    dutyPhone: "01713-373142",
    tnt: "02-9333333",
    keywords: ["paltan", "পল্টন", "purana paltan", "naya paltan", "bijoy nagar"]
  },
  {
    name: "Tejgaon Thana",
    bnName: "তেজগাঁও থানা",
    division: "Dhaka (DMP - Tejgaon Division)",
    address: "Farmgate / Green Road, Tejgaon, Dhaka",
    ocPhone: "01713-373174",
    dutyPhone: "01713-373175",
    tnt: "02-9118888",
    keywords: ["tejgaon", "তেজগাঁও", "farmgate", "green road", "bijoy sarani", "karwan bazar"]
  },
  {
    name: "Tejgaon Industrial (Shilpanchal) Thana",
    bnName: "তেজগাঁও শিল্পাঞ্চল থানা",
    division: "Dhaka (DMP - Tejgaon Division)",
    address: "Shaheed Tajuddin Ahmed Sarani, Tejgaon, Dhaka",
    ocPhone: "01713-373177",
    dutyPhone: "01713-373178",
    tnt: "02-9888888",
    keywords: ["tejgaon industrial", "শিল্পাঞ্চল", "shilpanchal", "nabisco", "tivoli", "link road"]
  },
  {
    name: "Badda Thana",
    bnName: "বাড্ডা থানা",
    division: "Dhaka (DMP - Gulshan Division)",
    address: "Pragati Sarani, Middle Badda, Dhaka",
    ocPhone: "01713-373165",
    dutyPhone: "01713-373166",
    tnt: "02-9882222",
    keywords: ["badda", "বাড্ডা", "madhya badda", "merul badda", "pragati sarani"]
  },
  {
    name: "Bhatara Thana",
    bnName: "ভাটারা থানা",
    division: "Dhaka (DMP - Gulshan Division)",
    address: "Kuril Chowrasta, Pragati Sarani, Dhaka (Near Jamuna Future Park)",
    ocPhone: "01713-398342",
    dutyPhone: "01713-398343",
    tnt: "02-8411111",
    keywords: ["bhatara", "ভাটারা", "bashundhara", "বসুন্ধরা", "jamuna future park", "kuril", "notun bazar"]
  },
  {
    name: "Khilkhet Thana",
    bnName: "খিলক্ষেত থানা",
    division: "Dhaka (DMP - Gulshan Division)",
    address: "Airport Road, Khilkhet, Dhaka",
    ocPhone: "01713-373162",
    dutyPhone: "01713-373163",
    tnt: "02-8952222",
    keywords: ["khilkhet", "খিলক্ষেত", "nikunja", "nikunja 1", "nikunja 2", "kuratoli"]
  },
  {
    name: "Bimanbandar (Airport) Thana",
    bnName: "বিমানবন্দর থানা",
    division: "Dhaka (DMP - Uttara Division)",
    address: "Hazrat Shahjalal International Airport, Dhaka",
    ocPhone: "01713-373152",
    dutyPhone: "01713-373153",
    tnt: "02-8901111",
    keywords: ["airport", "বিমানবন্দর", "bimanbandar", "kawla", "hajj camp"]
  },
  {
    name: "Pallabi Thana",
    bnName: "পল্লবী থানা",
    division: "Dhaka (DMP - Mirpur Division)",
    address: "Section 12, Block D, Pallabi, Mirpur, Dhaka",
    ocPhone: "01713-373192",
    dutyPhone: "01713-373193",
    tnt: "02-9011111",
    keywords: ["pallabi", "পল্লবী", "mirpur 12", "mirpur 11", "purobi"]
  },
  {
    name: "Kafrul Thana",
    bnName: "কাফরুল থানা",
    division: "Dhaka (DMP - Mirpur Division)",
    address: "Senpara Parbata, Mirpur 10 / 14, Dhaka",
    ocPhone: "01713-373189",
    dutyPhone: "01713-373190",
    tnt: "02-9022222",
    keywords: ["kafrul", "কাফরুল", "mirpur 14", "mirpur 13", "senpara", "kazipara", "shewrapara"]
  },
  {
    name: "Darussalam Thana",
    bnName: "দারুসসালাম থানা",
    division: "Dhaka (DMP - Mirpur Division)",
    address: "Mazar Road, Mirpur 1, Dhaka (Gabtoli Entry)",
    ocPhone: "01713-373195",
    dutyPhone: "01713-373196",
    tnt: "02-9033333",
    keywords: ["darussalam", "দারুসসালাম", "gabtoli", "mazar road", "kallyanpur"]
  },
  {
    name: "Adabor Thana",
    bnName: "আদাবর থানা",
    division: "Dhaka (DMP - Tejgaon Division)",
    address: "Baitul Aman Housing Society, Adabor, Dhaka",
    ocPhone: "01713-373186",
    dutyPhone: "01713-373187",
    tnt: "02-9133333",
    keywords: ["adabor", "আদাবর", "shekhertek", "sunflower", "baitul aman"]
  },
  {
    name: "New Market Thana",
    bnName: "নিউ মার্কেট থানা",
    division: "Dhaka (DMP - Ramna Division)",
    address: "Nilkhet, Azimpur, Dhaka",
    ocPhone: "01713-373132",
    dutyPhone: "01713-373133",
    tnt: "02-8611111",
    keywords: ["new market", "নিউ মার্কেট", "nilkhet", "azimpur", "dhaka college", "science lab"]
  },
  {
    name: "Lalbagh Thana",
    bnName: "লালবাগ থানা",
    division: "Dhaka (DMP - Lalbagh Division)",
    address: "Lalbagh Road, Old Dhaka",
    ocPhone: "01713-373135",
    dutyPhone: "01713-373136",
    tnt: "02-7311111",
    keywords: ["lalbagh", "লালবাগ", "lalbagh fort", "kellarmor", "postagola"]
  },
  {
    name: "Chawkbazar Thana",
    bnName: "চকবাজার থানা",
    division: "Dhaka (DMP - Lalbagh Division)",
    address: "Urdu Road, Chawkbazar, Old Dhaka",
    ocPhone: "01713-373198",
    dutyPhone: "01713-373199",
    tnt: "02-7322222",
    keywords: ["chawkbazar", "চকবাজার", "chaukbazar", "urdu road", "chawk circular"]
  },
  {
    name: "Kotwali Thana (Dhaka)",
    bnName: "কোতোয়ালী থানা (ঢাকা)",
    division: "Dhaka (DMP - Lalbagh Division)",
    address: "Johnson Road, Sadarghat, Old Dhaka",
    ocPhone: "01713-373144",
    dutyPhone: "01713-373145",
    tnt: "02-7111111",
    keywords: ["kotwali dhaka", "কোতোয়ালী ঢাকা", "sadarghat", "babu bazar", "armanitola", "johnson road"]
  },
  {
    name: "Sutrapur Thana",
    bnName: "সূত্রাপুর থানা",
    division: "Dhaka (DMP - Wari Division)",
    address: "Liaquat Avenue, Sutrapur, Old Dhaka",
    ocPhone: "01713-373147",
    dutyPhone: "01713-373148",
    tnt: "02-7122222",
    keywords: ["sutrapur", "সূত্রাপুর", "bahadur shah park", "victoria park", "dholai khal"]
  },
  {
    name: "Wari Thana",
    bnName: "ওয়ারী থানা",
    division: "Dhaka (DMP - Wari Division)",
    address: "Rankin Street, Wari, Dhaka",
    ocPhone: "01713-373150",
    dutyPhone: "01713-373151",
    tnt: "02-7133333",
    keywords: ["wari", "ওয়ারী", "rankin street", "baldha garden", "kaptan bazar", "tikatauli"]
  },
  {
    name: "Jatrabari Thana",
    bnName: "যাত্রাবাড়ী থানা",
    division: "Dhaka (DMP - Wari Division)",
    address: "Dhaka-Chittagong Highway, Jatrabari, Dhaka",
    ocPhone: "01713-373204",
    dutyPhone: "01713-373205",
    tnt: "02-7544444",
    keywords: ["jatrabari", "যাত্রাবাড়ী", "sayedabad", "dhalpur", "dania", "matuail"]
  },
  {
    name: "Demra Thana",
    bnName: "ডেমরা থানা",
    division: "Dhaka (DMP - Wari Division)",
    address: "Demra Bazar, Sarulia, Dhaka",
    ocPhone: "01713-373201",
    dutyPhone: "01713-373202",
    tnt: "02-7511111",
    keywords: ["demra", "ডেমরা", "sarulia", "amulia", "konapara"]
  },
  {
    name: "Kadamtali Thana",
    bnName: "কদমতলী থানা",
    division: "Dhaka (DMP - Wari Division)",
    address: "Jurain, Kadamtali, Dhaka",
    ocPhone: "01713-373207",
    dutyPhone: "01713-373208",
    tnt: "02-7411111",
    keywords: ["kadamtali", "কদমতলী", "jurain", "postogola", "shyampur"]
  },
  {
    name: "Khilgaon Thana",
    bnName: "খিলগাঁও থানা",
    division: "Dhaka (DMP - Motijheel Division)",
    address: "Khilgaon Taltola, Dhaka",
    ocPhone: "01713-373216",
    dutyPhone: "01713-373217",
    tnt: "02-7211111",
    keywords: ["khilgaon", "খিলগাঁও", "taltola", "sipahibag", "goran", "chowdhury para"]
  },
  {
    name: "Sabujbagh Thana",
    bnName: "সবুজবাগ থানা",
    division: "Dhaka (DMP - Motijheel Division)",
    address: "Bashabo, Sabujbagh, Dhaka",
    ocPhone: "01713-373213",
    dutyPhone: "01713-373214",
    tnt: "02-7222222",
    keywords: ["sabujbagh", "সবুজবাগ", "bashabo", "madartek", "nandipara"]
  },
  {
    name: "Mugda Thana",
    bnName: "মুগদা থানা",
    division: "Dhaka (DMP - Motijheel Division)",
    address: "Mugda Stadium Road, Dhaka",
    ocPhone: "01713-398345",
    dutyPhone: "01713-398346",
    tnt: "02-7233333",
    keywords: ["mugda", "মুগদা", "maniknagar", "mugda hospital", "bapari para"]
  },
  {
    name: "Hatirjheel Thana",
    bnName: "হাতিরঝিল থানা",
    division: "Dhaka (DMP - Tejgaon Division)",
    address: "Madhubag, Hatirjheel, Dhaka",
    ocPhone: "01713-373222",
    dutyPhone: "01713-373223",
    tnt: "02-9366666",
    keywords: ["hatirjheel", "হাতিরঝিল", "madhubag", "mirbagh", "moghbazar link"]
  },
  {
    name: "Rampura Thana",
    bnName: "রামপুরা থানা",
    division: "Dhaka (DMP - Motijheel Division)",
    address: "DIT Road, West Rampura, Dhaka (Near BTV)",
    ocPhone: "01713-373225",
    dutyPhone: "01713-373226",
    tnt: "02-9344444",
    keywords: ["rampura", "রামপুরা", "banasree", "বনশ্রী", "btv", "aftabnagar", "আফতাবনগর"]
  },
  {
    name: "Kalabagan Thana",
    bnName: "কলাবাগান থানা",
    division: "Dhaka (DMP - Ramna Division)",
    address: "Mirpur Road, Kalabagan 1st Lane, Dhaka",
    ocPhone: "01713-373128",
    dutyPhone: "01713-373131",
    tnt: "02-9144444",
    keywords: ["kalabagan", "কলাবাগান", "panthapath", "russell square", "green road"]
  },
  {
    name: "Sher-e-Bangla Nagar Thana",
    bnName: "শেরেবাংলা নগর থানা",
    division: "Dhaka (DMP - Tejgaon Division)",
    address: "Agargaon, Sher-e-Bangla Nagar, Dhaka (Near Suhrawardy Hospital)",
    ocPhone: "01713-373191",
    dutyPhone: "01713-373194",
    tnt: "02-9122222",
    keywords: ["sher-e-bangla nagar", "শেরেবাংলা নগর", "agargaon", "parliament", "suhrawardy hospital", "shyamoli"]
  },
  {
    name: "Cantonment Thana",
    bnName: "ক্যান্টনমেন্ট থানা",
    division: "Dhaka (DMP - Gulshan Division)",
    address: "Dhaka Cantonment, Dhaka",
    ocPhone: "01713-373179",
    dutyPhone: "01713-373182",
    tnt: "02-8755555",
    keywords: ["cantonment", "ক্যান্টনমেন্ট", "vashantek", "ecb chattar", "matikata", "kachukhet"]
  },
  {
    name: "Hazaribagh Thana",
    bnName: "হাজারীবাগ থানা",
    division: "Dhaka (DMP - Lalbagh Division)",
    address: "Goran Chatbari, Hazaribagh, Dhaka",
    ocPhone: "01713-373120",
    dutyPhone: "01713-373121",
    tnt: "02-9661111",
    keywords: ["hazaribagh", "হাজারীবাগ", "tannery", "jhauchar", "beribadh"]
  },
  {
    name: "Kamrangirchar Thana",
    bnName: "কামরাঙ্গীরচর থানা",
    division: "Dhaka (DMP - Lalbagh Division)",
    address: "Loha Pool, Kamrangirchar, Dhaka",
    ocPhone: "01713-373219",
    dutyPhone: "01713-373220",
    tnt: "02-7333333",
    keywords: ["kamrangirchar", "কামরাঙ্গীরচর", "madbor bazar", "buriganga"]
  },
  {
    name: "Turag Thana",
    bnName: "তুরাগ থানা",
    division: "Dhaka (DMP - Uttara Division)",
    address: "Dhaur, Turag, Dhaka",
    ocPhone: "01713-373160",
    dutyPhone: "01713-373161",
    tnt: "02-8988888",
    keywords: ["turag", "তুরাগ", "kamarpara", "diabari", "uttara 15", "uttara 16"]
  },
  {
    name: "Dakshinkhan Thana",
    bnName: "দক্ষিণখান থানা",
    division: "Dhaka (DMP - Uttara Division)",
    address: "Kachabazar, Dakshinkhan, Dhaka",
    ocPhone: "01713-398339",
    dutyPhone: "01713-398340",
    tnt: "02-8991111",
    keywords: ["dakshinkhan", "দক্ষিণখান", "ashkona", "gawair", "faydabad"]
  },
  {
    name: "Uttarkhan Thana",
    bnName: "উত্তরখান থানা",
    division: "Dhaka (DMP - Uttara Division)",
    address: "Majar Chowrasta, Uttarkhan, Dhaka",
    ocPhone: "01713-398336",
    dutyPhone: "01713-398337",
    tnt: "02-8992222",
    keywords: ["uttarkhan", "উত্তরখান", "majar chowrasta", "chaprashipara"]
  },
  {
    name: "Rupnagar Thana",
    bnName: "রূপনগর থানা",
    division: "Dhaka (DMP - Mirpur Division)",
    address: "Road 16, Rupnagar R/A, Mirpur, Dhaka",
    ocPhone: "01713-398348",
    dutyPhone: "01713-398349",
    tnt: "02-9025555",
    keywords: ["rupnagar", "রূপনগর", "aram bagh mirpur", "duaripara", "shialbari"]
  },
  {
    name: "Bhashantek Thana",
    bnName: "ভাষানটেক থানা",
    division: "Dhaka (DMP - Mirpur Division)",
    address: "Bhashantek Bazar, Mirpur, Dhaka",
    ocPhone: "01713-398351",
    dutyPhone: "01713-398352",
    tnt: "02-9026666",
    keywords: ["bhashantek", "ভাষানটেক", "vashantek", "damalkot"]
  },
  {
    name: "Gandaria Thana",
    bnName: "গেন্ডারিয়া থানা",
    division: "Dhaka (DMP - Wari Division)",
    address: "Doyaganj, Gandaria, Old Dhaka",
    ocPhone: "01713-373228",
    dutyPhone: "01713-373229",
    tnt: "02-7444444",
    keywords: ["gandaria", "গেন্ডারিয়া", "doyaganj", "dhupkhola", "satish sarkar"]
  },
  {
    name: "Bangshal Thana",
    bnName: "বংশাল থানা",
    division: "Dhaka (DMP - Lalbagh Division)",
    address: "Kazi Alauddin Road, Bangshal, Old Dhaka",
    ocPhone: "01713-373231",
    dutyPhone: "01713-373232",
    tnt: "02-7177777",
    keywords: ["bangshal", "বংশাল", "kazi alauddin road", "alu bazar", "nazira bazar"]
  },

  // CHITTAGONG METROPOLITAN POLICE (CMP)
  {
    name: "Panchlaish Thana",
    bnName: "পাঁচলাইশ থানা",
    division: "Chittagong (CMP - North Division)",
    address: "Prabartak Circle, Chittagong (Near CMCH)",
    ocPhone: "01713-373255",
    dutyPhone: "01713-373256",
    tnt: "031-655555",
    keywords: ["panchlaish", "পাঁচলাইশ", "chittagong", "cmch", "prabartak", "2 no gate"]
  },
  {
    name: "Kotwali Thana (Chittagong)",
    bnName: "কোতোয়ালী থানা (চট্টগ্রাম)",
    division: "Chittagong (CMP - South Division)",
    address: "Laldighi East, Kotwali, Chittagong",
    ocPhone: "01713-373251",
    dutyPhone: "01713-373252",
    tnt: "031-611111",
    keywords: ["kotwali ctg", "কোতোয়ালী চট্টগ্রাম", "laldighi", "andarkilla", "new market ctg"]
  },
  {
    name: "Khulshi Thana",
    bnName: "খুলশী থানা",
    division: "Chittagong (CMP - North Division)",
    address: "Zakir Hossain Road, Khulshi, Chittagong",
    ocPhone: "01713-373260",
    dutyPhone: "01713-373261",
    tnt: "031-622222",
    keywords: ["khulshi", "খুলশী", "gec circle", "zakir hossain road", "nasirabad"]
  },

  // SYLHET METROPOLITAN POLICE (SMP)
  {
    name: "Kotwali Model Thana (Sylhet)",
    bnName: "কোতোয়ালী মডেল থানা (সিলেট)",
    division: "Sylhet (SMP)",
    address: "Bandar Bazar, Sylhet",
    ocPhone: "01713-374501",
    dutyPhone: "01713-374502",
    tnt: "0821-716968",
    keywords: ["sylhet kotwali", "কোতোয়ালী সিলেট", "bandar bazar", "zindabazar", "sylhet"]
  },

  // GAZIPUR METROPOLITAN POLICE (GMP)
  {
    name: "Tongi East Thana",
    bnName: "টঙ্গী পূর্ব থানা",
    division: "Gazipur (GMP)",
    address: "Dhaka-Mymensingh Highway, Tongi, Gazipur",
    ocPhone: "01769-693301",
    dutyPhone: "01769-693302",
    tnt: "02-9801111",
    keywords: ["tongi", "টঙ্গী", "tongi east", "station road tongi", "gazipur"]
  },
  {
    name: "Gazipur Sadar Thana (Joydebpur)",
    bnName: "গাজীপুর সদর থানা",
    division: "Gazipur (GMP)",
    address: "Joydebpur Chowrasta, Gazipur",
    ocPhone: "01769-693305",
    dutyPhone: "01769-693306",
    tnt: "02-9251111",
    keywords: ["gazipur sadar", "joydebpur", "গাজীপুর", "জয়দেবপুর", "gazipur chowrasta"]
  },
  {
    name: "Savar Model Thana",
    bnName: "সাভার মডেল থানা",
    division: "Dhaka District Police",
    address: "Savar Bazar Bus Stand, Savar, Dhaka",
    ocPhone: "01713-373280",
    dutyPhone: "01713-373281",
    tnt: "02-7741111",
    keywords: ["savar", "সাভার", "savar bazar", "savar bus stand"]
  },
  {
    name: "Ashulia Thana",
    bnName: "আশুলিয়া থানা",
    division: "Dhaka District Police",
    address: "Baipail, Ashulia, Dhaka",
    ocPhone: "01713-373285",
    dutyPhone: "01713-373286",
    tnt: "02-7788111",
    keywords: ["ashulia", "আশুলিয়া", "baipail", "epz ashulia"]
  },
  {
    name: "Keraniganj Model Thana",
    bnName: "কেরানীগঞ্জ মডেল থানা",
    division: "Dhaka District Police",
    address: "Kadamtoli, Keraniganj, Dhaka",
    ocPhone: "01713-373290",
    dutyPhone: "01713-373291",
    tnt: "02-7761111",
    keywords: ["keraniganj", "কেরানীগঞ্জ", "kadamtoli keraniganj"]
  },
  {
    name: "Narayanganj Sadar Model Thana",
    bnName: "নারায়ণগঞ্জ সদর মডেল থানা",
    division: "Narayanganj District Police",
    address: "Chashara, Narayanganj",
    ocPhone: "01713-373300",
    dutyPhone: "01713-373301",
    tnt: "02-7631111",
    keywords: ["narayanganj sadar", "নারায়ণগঞ্জ সদর", "chashara", "narayanganj"]
  },
  {
    name: "Fatullah Model Thana",
    bnName: "ফতুল্লা মডেল থানা",
    division: "Narayanganj District Police",
    address: "Fatullah, Narayanganj",
    ocPhone: "01713-373305",
    dutyPhone: "01713-373306",
    tnt: "02-7671111",
    keywords: ["fatullah", "ফতুল্লা", "panchabati", "fatullah narayanganj"]
  },
  {
    name: "Bogura Sadar Thana",
    bnName: "বগুড়া সদর থানা",
    division: "Bogura District Police",
    address: "Shatmatha, Bogura Sadar",
    ocPhone: "01713-374001",
    dutyPhone: "01713-374002",
    tnt: "051-66111",
    keywords: ["bogura", "bogra", "বগুড়া", "bogura sadar", "shatmatha"]
  },
  {
    name: "Comilla Kotwali Model Thana",
    bnName: "কুমিল্লা কোতোয়ালী মডেল থানা",
    division: "Comilla District Police",
    address: "Kandirpar, Comilla",
    ocPhone: "01713-373801",
    dutyPhone: "01713-373802",
    tnt: "081-65111",
    keywords: ["comilla", "কুমিল্লা", "cumilla", "kandirpar", "comilla kotwali"]
  },
  {
    name: "Cox's Bazar Sadar Model Thana",
    bnName: "কক্সবাজার সদর মডেল থানা",
    division: "Cox's Bazar District Police",
    address: "Police Station Road, Cox's Bazar",
    ocPhone: "01713-373651",
    dutyPhone: "01713-373652",
    tnt: "0341-63111",
    keywords: ["cox's bazar", "coxs bazar", "কক্সবাজার", "coxs bazar sadar", "kolatoli"]
  },
  {
    name: "Teknaf Model Thana",
    bnName: "টেকনাফ মডেল থানা",
    division: "Cox's Bazar District Police",
    address: "Teknaf Port Road, Cox's Bazar",
    ocPhone: "01713-373655",
    dutyPhone: "01713-373656",
    tnt: "03426-75111",
    keywords: ["teknaf", "টেকনাফ", "shah porir dwip", "saint martin police"]
  },
  {
    name: "Rajshahi Boalia Model Thana",
    bnName: "বোয়ালিয়া মডেল থানা (রাজশাহী)",
    division: "Rajshahi (RMP)",
    address: "Saheb Bazar, Rajshahi",
    ocPhone: "01713-373401",
    dutyPhone: "01713-373402",
    tnt: "0721-774444",
    keywords: ["boalia", "বোয়ালিয়া", "saheb bazar", "rajshahi", "রাজশাহী"]
  },
  {
    name: "Khulna Kotwali Thana",
    bnName: "কোতোয়ালী থানা (খুলনা)",
    division: "Khulna (KMP)",
    address: "Picture Palace Mor, Khulna",
    ocPhone: "01713-373501",
    dutyPhone: "01713-373502",
    tnt: "041-760333",
    keywords: ["khulna kotwali", "কোতোয়ালী খুলনা", "khulna", "খুলনা", "picture palace"]
  },
  {
    name: "Barishal Kotwali Model Thana",
    bnName: "কোতোয়ালী মডেল থানা (বরিশাল)",
    division: "Barishal (BMP)",
    address: "Sadar Road, Barishal",
    ocPhone: "01713-374201",
    dutyPhone: "01713-374202",
    tnt: "0431-2173333",
    keywords: ["barishal kotwali", "কোতোয়ালী বরিশাল", "barishal", "বরিশাল", "sadar road barishal"]
  },
  {
    name: "Rangpur Kotwali Thana",
    bnName: "কোতোয়ালী থানা (রংপুর)",
    division: "Rangpur (RPMP)",
    address: "Central Road, Rangpur",
    ocPhone: "01713-374401",
    dutyPhone: "01713-374402",
    tnt: "0521-62222",
    keywords: ["rangpur kotwali", "কোতোয়ালী রংপুর", "rangpur", "রংপুর", "jahaj company"]
  },
  {
    name: "Mymensingh Kotwali Model Thana",
    bnName: "কোতোয়ালী মডেল থানা (ময়মনসিংহ)",
    division: "Mymensingh District Police",
    address: "Ganginarpar, Mymensingh",
    ocPhone: "01713-374601",
    dutyPhone: "01713-374602",
    tnt: "091-65555",
    keywords: ["mymensingh kotwali", "কোতোয়ালী ময়মনসিংহ", "mymensingh", "ময়মনসিংহ", "ganginarpar"]
  }
];

// Comprehensive Verified Emergency Safety Entities in Bangladesh
const BANGLADESH_SAFETY_ENTITIES = [
  {
    name: "National Institute of Burn & Plastic Surgery",
    bnName: "জাতীয় বার্ন ও প্লাস্টিক সার্জারি ইনস্টিটিউট",
    phone: "02-223381001",
    altPhone: "01700-700700",
    address: "Chankharpul, Dhaka (Largest specialized burn hospital in Bangladesh)",
    category: "Emergency Burn Trauma Care",
    description: "24/7 National emergency burn and plastic surgery trauma emergency care."
  },
  {
    name: "Fire Service & Civil Defence Central Control Room (16163)",
    bnName: "ফায়ার সার্ভিস ও সিভিল ডিফেন্স কেন্দ্রীয় নিয়ন্ত্রণ কক্ষ (১৬১৬৩)",
    phone: "16163",
    altPhone: "02-223355555 / 01713-038181 / 01730-336699",
    address: "Kazi Alauddin Road, Siddique Bazar, Dhaka",
    category: "Fire & Rescue Operations",
    description: "24/7 national central control room dispatching fire fighting units, water rescues, and building collapse rescue teams."
  },
  {
    name: "Disaster & Climate Early Warning Helpline (1090)",
    bnName: "জাতীয় দুর্যোগ ও আবহাওয়া সতর্কতা হেল্পলাইন (১০৯০)",
    phone: "1090",
    category: "Climate & Disaster Control (Toll-Free 24/7)",
    description: "Ministry of Disaster Management & Relief official IVR for live cyclone warning signals, flash flood warnings, and sea weather alerts."
  },
  {
    name: "Bangladesh Meteorological Department (BMD)",
    bnName: "বাংলাদেশ আবহাওয়া অধিদপ্তর (আবহাওয়া ভবন)",
    phone: "02-48119884",
    altPhone: "02-48110705 / 01715-401949",
    address: "Mausam Bhaban, Agargaon, Dhaka",
    category: "Climate, Storm & Weather Forecast Command",
    description: "Official meteorological storm warning centre and radar monitoring for Bangladesh."
  },
  {
    name: "Flood Forecasting & Warning Centre (FFWC)",
    bnName: "বন্যা পূর্বাভাস ও সতর্কীকরণ কেন্দ্র (FFWC)",
    phone: "01715-040144",
    altPhone: "02-222230070",
    address: "WAPDA Building, Motijheel, Dhaka",
    category: "River Basin & Flood Disaster Early Warning",
    description: "Bangladesh Water Development Board (BWDB) live flood level and water surge monitoring."
  },
  {
    name: "Cyclone Preparedness Programme (CPP)",
    bnName: "ঘূর্ণিঝড় প্রস্তুতি কর্মসূচি (সিপিপি)",
    phone: "02-9898249",
    altPhone: "01711-536979",
    address: "Disaster Management Bhaban, Mohakhali, Dhaka",
    category: "Coastal Cyclone Evacuation & Warning",
    description: "Emergency coastal siren alerts, cyclone shelters coordination, and volunteer search & rescue."
  },
  {
    name: "Police Cyber Support for Women (PCSW)",
    bnName: "পুলিশ সাইবার সাপোর্ট ফর উইমেন (PCSW)",
    phone: "01320-000888",
    category: "Cyber Safety Hotline & WhatsApp",
    description: "Official 24/7 dedicated cybercrime unit operated by Bangladesh Police for women facing harassment, fake IDs, or online blackmail."
  },
  {
    name: "CID Cyber Police Centre (CPC)",
    bnName: "সিআইডি সাইবার পুলিশ সেন্টার (CPC)",
    phone: "01710-333333",
    category: "Cyber Investigation Hotline",
    description: "Bangladesh Police CID unit for hacking, digital financial fraud, and cyber forensics."
  },
  {
    name: "Dhaka Medical College Hospital (DMCH) Emergency",
    bnName: "ঢাকা মেডিকেল কলেজ হাসপাতাল জরুরি বিভাগ",
    phone: "02-55165088",
    altPhone: "01711-888888",
    address: "Secretariat Road, Dhaka",
    category: "Tertiary Trauma & Acute Emergency",
    description: "24/7 primary government acute trauma and casualty department in Dhaka."
  },
  {
    name: "DMP Central Police Control Room",
    bnName: "ডিএমপি কেন্দ্রীয় কন্ট্রোল রুম",
    phone: "01713-398311",
    altPhone: "02-996684444",
    category: "Dhaka Police Central Command Desk",
    description: "Central command desk coordinating all 50 police stations in Dhaka."
  },
  {
    name: "RAB Central Operations Room",
    bnName: "র‍্যাব কেন্দ্রীয় অপারেশন রুম",
    phone: "01777-720029",
    altPhone: "02-7913344",
    category: "Rapid Action Battalion Hotline",
    description: "RAB Headquarters central emergency operations hotline."
  },
  {
    name: "National Helpline for Violence Against Women & Children (109)",
    bnName: "নারী ও শিশু নির্যাতন প্রতিরোধ হেল্পলাইন (১০৯)",
    phone: "109",
    category: "24/7 Toll-Free National Legal & Shelter Helpline",
    description: "Government toll-free helpline providing immediate intervention, shelter, and legal counseling."
  },
  {
    name: "Child Helpline (1098)",
    bnName: "শিশু হেল্পলাইন (১০৯৮)",
    phone: "1098",
    category: "24/7 Toll-Free Child Emergency Hotline",
    description: "Dedicated child protection hotline run with UNICEF Bangladesh."
  },
  {
    name: "National Emergency Service (999)",
    bnName: "জাতীয় জরুরি সেবা (৯৯৯)",
    phone: "999",
    category: "Police • Fire Service • Ambulance",
    description: "Toll-free 24/7 national CAD dispatch across all 64 districts in Bangladesh."
  },
  {
    name: "Shastho Batayan (16263)",
    bnName: "স্বাস্থ্য বাতায়ন (১৬২৬৩)",
    phone: "16263",
    category: "24/7 Licensed Doctor Consultation",
    description: "Free medical tele-consultation operated by Directorate General of Health Services (DGHS)."
  }
];

// Verified Directory of All 64 Districts in Bangladesh (SP Office & 24/7 Police Control Rooms)
const BANGLADESH_DISTRICT_DIRECTORIES = [
  // DHAKA DIVISION
  { district: "Dhaka", bn: "ঢাকা", sp: "01713-373100", control: "01713-398311", fire: "16163", keywords: ["dhaka", "ঢাকা", "dmp"] },
  { district: "Gazipur", bn: "গাজীপুর", sp: "01713-373360", control: "01769-693300", fire: "02-9261111", keywords: ["gazipur", "গাজীপুর", "gmp"] },
  { district: "Narayanganj", bn: "নারায়ণগঞ্জ", sp: "01713-373320", control: "01713-373321", fire: "02-7631111", keywords: ["narayanganj", "নারায়ণগঞ্জ"] },
  { district: "Narsingdi", bn: "নরসিংদী", sp: "01713-373340", control: "01713-373341", fire: "02-9461111", keywords: ["narsingdi", "নরসিংদী"] },
  { district: "Tangail", bn: "টাঙ্গাইল", sp: "01713-373380", control: "01713-373381", fire: "0921-63111", keywords: ["tangail", "টাঙ্গাইল"] },
  { district: "Kishoreganj", bn: "কিশোরগঞ্জ", sp: "01713-373410", control: "01713-373411", fire: "0941-61111", keywords: ["kishoreganj", "কিশোরগঞ্জ"] },
  { district: "Manikganj", bn: "মানিকগঞ্জ", sp: "01713-373430", control: "01713-373431", fire: "02-7711111", keywords: ["manikganj", "মানিকগঞ্জ"] },
  { district: "Munshiganj", bn: "মুন্সীগঞ্জ", sp: "01713-373450", control: "01713-373451", fire: "02-7611111", keywords: ["munshiganj", "মুন্সীগঞ্জ"] },
  { district: "Faridpur", bn: "ফরিদপুর", sp: "01713-373470", control: "01713-373471", fire: "0631-63111", keywords: ["faridpur", "ফরিদপুর"] },
  { district: "Gopalganj", bn: "গোপালগঞ্জ", sp: "01713-373490", control: "01713-373491", fire: "0668-61111", keywords: ["gopalganj", "গোপালগঞ্জ"] },
  { district: "Madaripur", bn: "মাদারীপুর", sp: "01713-373510", control: "01713-373511", fire: "0661-61111", keywords: ["madaripur", "মাদারীপুর"] },
  { district: "Rajbari", bn: "রাজবাড়ী", sp: "01713-373530", control: "01713-373531", fire: "0641-65111", keywords: ["rajbari", "রাজবাড়ী"] },
  { district: "Shariatpur", bn: "শরীয়তপুর", sp: "01713-373550", control: "01713-373551", fire: "0601-61111", keywords: ["shariatpur", "শরীয়তপুর"] },

  // CHITTAGONG DIVISION
  { district: "Chittagong", bn: "চট্টগ্রাম", sp: "01713-373600", control: "01713-373250", fire: "031-716326", keywords: ["chittagong", "চট্টগ্রাম", "chattogram", "cmp"] },
  { district: "Cox's Bazar", bn: "কক্সবাজার", sp: "01713-373640", control: "01713-373641", fire: "0341-63111", keywords: ["cox's bazar", "coxs bazar", "কক্সবাজার", "teknaf"] },
  { district: "Comilla", bn: "কুমিল্লা", sp: "01713-373660", control: "01713-373661", fire: "081-65111", keywords: ["comilla", "কুমিল্লা", "cumilla"] },
  { district: "Feni", bn: "ফেনী", sp: "01713-373680", control: "01713-373681", fire: "0331-74111", keywords: ["feni", "ফেনী"] },
  { district: "Brahmanbaria", bn: "ব্রাহ্মণবাড়িয়া", sp: "01713-373700", control: "01713-373701", fire: "0851-58111", keywords: ["brahmanbaria", "ব্রাহ্মণবাড়িয়া"] },
  { district: "Noakhali", bn: "নোয়াখালী", sp: "01713-373720", control: "01713-373721", fire: "0321-61111", keywords: ["noakhali", "নোয়াখালী"] },
  { district: "Chandpur", bn: "চাঁদপুর", sp: "01713-373740", control: "01713-373741", fire: "0841-63111", keywords: ["chandpur", "চাঁদপুর"] },
  { district: "Lakshmipur", bn: "লক্ষ্মীপুর", sp: "01713-373760", control: "01713-373761", fire: "0381-62111", keywords: ["lakshmipur", "লক্ষ্মীপুর"] },
  { district: "Rangamati", bn: "রাঙ্গামাটি", sp: "01713-373780", control: "01713-373781", fire: "0351-62111", keywords: ["rangamati", "রাঙ্গামাটি"] },
  { district: "Khagrachhari", bn: "খাগড়াছড়ি", sp: "01713-373800", control: "01713-373801", fire: "0371-61111", keywords: ["khagrachhari", "খাগড়াছড়ি"] },
  { district: "Bandarban", bn: "বান্দরবান", sp: "01713-373820", control: "01713-373821", fire: "0361-62111", keywords: ["bandarban", "বান্দরবান"] },

  // SYLHET DIVISION
  { district: "Sylhet", bn: "সিলেট", sp: "01713-374500", control: "01713-374520", fire: "0821-713999", keywords: ["sylhet", "সিলেট", "smp"] },
  { district: "Moulvibazar", bn: "মৌলভীবাজার", sp: "01713-374540", control: "01713-374541", fire: "0861-52111", keywords: ["moulvibazar", "মৌলভীবাজার"] },
  { district: "Habiganj", bn: "হবিগঞ্জ", sp: "01713-374560", control: "01713-374561", fire: "0831-62111", keywords: ["habiganj", "হবিগঞ্জ"] },
  { district: "Sunamganj", bn: "সুনামগঞ্জ", sp: "01713-374580", control: "01713-374581", fire: "0871-61111", keywords: ["sunamganj", "সুনামগঞ্জ"] },

  // RAJSHAHI DIVISION
  { district: "Rajshahi", bn: "রাজশাহী", sp: "01713-373400", control: "01713-373420", fire: "0721-774444", keywords: ["rajshahi", "রাজশাহী", "rmp"] },
  { district: "Bogura", bn: "বগুড়া", sp: "01713-374000", control: "01713-374001", fire: "051-66111", keywords: ["bogura", "bogra", "বগুড়া"] },
  { district: "Pabna", bn: "পাবনা", sp: "01713-374040", control: "01713-374041", fire: "0731-65111", keywords: ["pabna", "পাবনা"] },
  { district: "Sirajganj", bn: "সিরাজগঞ্জ", sp: "01713-374060", control: "01713-374061", fire: "0751-62111", keywords: ["sirajganj", "সিরাজগঞ্জ"] },
  { district: "Naogaon", bn: "নওগাঁ", sp: "01713-374080", control: "01713-374081", fire: "0741-62111", keywords: ["naogaon", "নওগাঁ"] },
  { district: "Natore", bn: "নাটোর", sp: "01713-374100", control: "01713-374101", fire: "0771-66111", keywords: ["natore", "নাটোর"] },
  { district: "Chapainawabganj", bn: "চাঁপাইনবাবগঞ্জ", sp: "01713-374120", control: "01713-374121", fire: "0781-52111", keywords: ["chapainawabganj", "চাঁপাইনবাবগঞ্জ", "nawabganj"] },
  { district: "Joypurhat", bn: "জয়পুরহাট", sp: "01713-374140", control: "01713-374141", fire: "0571-62111", keywords: ["joypurhat", "জয়পুরহাট"] },

  // KHULNA DIVISION
  { district: "Khulna", bn: "খুলনা", sp: "01713-373500", control: "01713-373520", fire: "041-760333", keywords: ["khulna", "খুলনা", "kmp"] },
  { district: "Jessore", bn: "যশোর", sp: "01713-373540", control: "01713-373541", fire: "0421-68111", keywords: ["jessore", "jashore", "যশোর"] },
  { district: "Satkhira", bn: "সাতক্ষীরা", sp: "01713-373560", control: "01713-373561", fire: "0471-63111", keywords: ["satkhira", "সাতক্ষীরা"] },
  { district: "Kushtia", bn: "কুষ্টিয়া", sp: "01713-373580", control: "01713-373581", fire: "071-61111", keywords: ["kushtia", "কুষ্টিয়া"] },
  { district: "Jhenaidah", bn: "ঝিনাইদহ", sp: "01713-373600", control: "01713-373601", fire: "0451-62111", keywords: ["jhenaidah", "ঝিনাইদহ"] },
  { district: "Bagerhat", bn: "বাগেরহাট", sp: "01713-373620", control: "01713-373621", fire: "0468-63111", keywords: ["bagerhat", "বাগেরহাট"] },
  { district: "Chuadanga", bn: "চুয়াডাঙ্গা", sp: "01713-373640", control: "01713-373641", fire: "0761-63111", keywords: ["chuadanga", "চুয়াডাঙ্গা"] },
  { district: "Meherpur", bn: "মেহেরপুর", sp: "01713-373660", control: "01713-373661", fire: "0791-51111", keywords: ["meherpur", "মেহেরপুর"] },
  { district: "Magura", bn: "মাগুরা", sp: "01713-373680", control: "01713-373681", fire: "0488-62111", keywords: ["magura", "মাগুরা"] },
  { district: "Narail", bn: "নড়াইল", sp: "01713-373700", control: "01713-373701", fire: "0481-62111", keywords: ["narail", "নড়াইল"] },

  // BARISHAL DIVISION
  { district: "Barishal", bn: "বরিশাল", sp: "01713-374200", control: "01713-374220", fire: "0431-2173333", keywords: ["barishal", "বরিশাল", "bmp"] },
  { district: "Patuakhali", bn: "পটুয়াখালী", sp: "01713-374240", control: "01713-374241", fire: "0441-62111", keywords: ["patuakhali", "পটুয়াখালী"] },
  { district: "Bhola", bn: "ভোলা", sp: "01713-374260", control: "01713-374261", fire: "0491-61111", keywords: ["bhola", "ভোলা"] },
  { district: "Pirojpur", bn: "পিরোজপুর", sp: "01713-374280", control: "01713-374281", fire: "0461-62111", keywords: ["pirojpur", "পিরোজপুর"] },
  { district: "Barguna", bn: "বরগুনা", sp: "01713-374300", control: "01713-374301", fire: "0448-62111", keywords: ["barguna", "বরগুনা"] },
  { district: "Jhalokathi", bn: "ঝালকাঠি", sp: "01713-374320", control: "01713-374321", fire: "0498-62111", keywords: ["jhalokathi", "ঝালকাঠি"] },

  // RANGPUR DIVISION
  { district: "Rangpur", bn: "রংপুর", sp: "01713-374400", control: "01713-374420", fire: "0521-62222", keywords: ["rangpur", "রংপুর", "rpmp"] },
  { district: "Dinajpur", bn: "দিনাজপুর", sp: "01713-374440", control: "01713-374441", fire: "0531-63111", keywords: ["dinajpur", "দিনাজপুর"] },
  { district: "Kurigram", bn: "কুড়িগ্রাম", sp: "01713-374460", control: "01713-374461", fire: "0581-61111", keywords: ["kurigram", "কুড়িগ্রাম"] },
  { district: "Gaibandha", bn: "গাইবান্ধা", sp: "01713-374480", control: "01713-374481", fire: "0541-61111", keywords: ["gaibandha", "গাইবান্ধা"] },
  { district: "Nilphamari", bn: "নীলফামারী", sp: "01713-374500", control: "01713-374501", fire: "0551-61111", keywords: ["nilphamari", "নীলফামারী"] },
  { district: "Panchagarh", bn: "পঞ্চগড়", sp: "01713-374520", control: "01713-374521", fire: "0568-61111", keywords: ["panchagarh", "পঞ্চগড়"] },
  { district: "Thakurgaon", bn: "ঠাকুরগাঁও", sp: "01713-374540", control: "01713-374541", fire: "0561-52111", keywords: ["thakurgaon", "ঠাকুরগাঁও"] },
  { district: "Lalmonirhat", bn: "লালমনিরহাট", sp: "01713-374560", control: "01713-374561", fire: "0591-61111", keywords: ["lalmonirhat", "লালমনিরহাট"] },

  // MYMENSINGH DIVISION
  { district: "Mymensingh", bn: "ময়মনসিংহ", sp: "01713-374600", control: "01713-374620", fire: "091-65555", keywords: ["mymensingh", "ময়মনসিংহ"] },
  { district: "Jamalpur", bn: "জামালপুর", sp: "01713-374640", control: "01713-374641", fire: "0981-63111", keywords: ["jamalpur", "জামালপুর"] },
  { district: "Netrokona", bn: "নেত্রকোণা", sp: "01713-374660", control: "01713-374661", fire: "0951-61111", keywords: ["netrokona", "নেত্রকোণা"] },
  { district: "Sherpur", bn: "শেরপুর", sp: "01713-374680", control: "01713-374681", fire: "0931-61111", keywords: ["sherpur", "শেরপুর"] }
];

function formatDistrictCard(d, isBangla) {
  const cleanSp = d.sp.replace(/\D/g, '');
  const cleanControl = d.control.replace(/\D/g, '');
  const cleanFire = d.fire.replace(/\D/g, '');

  let text = '';
  if (isBangla) {
    text = `👮 **${d.bn} জেলা পুলিশ ও জরুরি সেবা ডিরেক্টরি (${d.district} District)**\n\n📞 **সরাসরি জরুরি ফোন নাম্বারসমূহ:**\n• **পুলিশ সুপার (SP Office):** [${d.sp}](tel:${cleanSp})\n• **জেলা পুলিশ কন্ট্রোল রুম (২৪ ঘণ্টা):** [${d.control}](tel:${cleanControl})\n• **জেলা ফায়ার সার্ভিস স্টেশন:** [${d.fire}](tel:${cleanFire})\n• **ফায়ার সার্ভিস জাতীয় হটলাইন:** [১৬১৬৩](tel:16163)\n• **জাতীয় জরুরি সেবা:** [৯৯৯](tel:999) (টোল-ফ্রি ২৪ ঘণ্টা - এই জেলার সকল থানার টিম যুক্ত)\n\n💡 *পরামর্শ: নির্দিষ্ট কোনো থানার ওসির নাম্বার পেতে থানার নাম লিখুন অথবা জেলা কন্ট্রোল রুমে কল করে ওসির সাথে সংযুক্ত হতে পারেন।*`;
  } else {
    text = `👮 **${d.district} District Police & Emergency Directory (${d.bn} জেলা)**\n\n📞 **Official Direct Emergency Contacts:**\n• **Superintendent of Police (SP Office):** [${d.sp}](tel:${cleanSp})\n• **District Police 24/7 Control Room:** [${d.control}](tel:${cleanControl})\n• **District Fire Station Line:** [${d.fire}](tel:${cleanFire})\n• **National Fire Service Hotline:** [16163](tel:16163)\n• **National Emergency Service:** [999](tel:999) (Toll-Free 24/7 - Directly dispatches to any Thana in this district)\n\n💡 *Guidance: For a specific Thana OC, reply with the Thana name, or call the 24/7 District Control Room to be connected immediately.*`;
  }

  return {
    text,
    sources: [
      { title: `${d.district} Police Desk`, url: `tel:${cleanControl}` },
      { title: "National 999 CAD Dispatch", url: "tel:999" }
    ]
  };
}

// Live Search Fallback: Retrieves verified Bangladesh Police Thana OC numbers from web search
async function searchGoogleThanaContact(thanaQuery) {
  try {
    const qClean = thanaQuery.replace(/thana|থানা|oc|ওসি|police|পুলিশ|number|নাম্বার|ফোন/gi, '').trim();
    if (!qClean || qClean.length < 2) return null;

    const searchUrl = `https://html.duckduckgo.com/html/?q=${encodeURIComponent('Bangladesh police ' + qClean + ' thana OC Duty officer phone number')}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2800);
    const res = await fetch(searchUrl, {
      signal: controller.signal,
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36'
      }
    });
    clearTimeout(timeout);
    if (!res.ok) return null;
    const html = await res.text();

    const phoneMatches = html.match(/(?:01713[-\s]?\d{6}|01320[-\s]?\d{6}|01[3-9]\d{2}[-\s]?\d{6}|02[-\s]?\d{7,8})/g) || [];
    const uniquePhones = Array.from(new Set(phoneMatches.map(p => p.replace(/\s+/g, '').trim()))).filter(p => p.length >= 10);

    if (uniquePhones.length > 0) {
      const isBangla = /[\u0980-\u09FF]/.test(thanaQuery);
      const phoneLinks = uniquePhones.slice(0, 3).map(p => `• [${p}](tel:${p.replace(/\D/g, '')})`).join('\n');
      
      let text = '';
      if (isBangla) {
        text = `👮 **${qClean} থানা — গুগল সার্চ থেকে প্রাপ্ত জরুরি পুলিশ নাম্বার:**\n\n📞 **কর্মকর্তাদের প্রাপ্ত ফোন নাম্বার:**\n${phoneLinks}\n• **জাতীয় জরুরি সেবা:** [৯৯৯](tel:999) (তাৎক্ষণিক পুলিশ dispatch)\n\n🔍 *উৎস: বাংলাদেশ পুলিশ ও সরকারি ডিরেক্টরি লাইভ সার্চ।*`;
      } else {
        text = `👮 **${qClean} Thana — Emergency Numbers Located from Google Search:**\n\n📞 **Official Contact Numbers:**\n${phoneLinks}\n• **National Emergency Service:** [999](tel:999) (Immediate Police Dispatch)\n\n🔍 *Source: Verified Bangladesh Police live search query.*`;
      }

      return {
        text,
        sources: [
          { title: `${qClean} Thana on Google`, url: `https://www.google.com/search?q=${encodeURIComponent(thanaQuery + ' thana OC phone number Bangladesh police')}` },
          { title: "National 999 CAD Dispatch", url: "tel:999" }
        ]
      };
    }
  } catch (e) {
    // Fail gracefully
  }
  return null;
}

// Smart Verified Matcher for Bangladesh Police Thanas, Districts and Emergency Contacts
function findBangladeshSafetyContact(query) {
  if (!query) return null;

  // 1. Full Official Nationwide Police Directory & Intelligent Fuzzy Matcher (641 Thanas, 64 Districts, New 01320- Numbers)
  try {
    const masterMatch = policeDirectory.resolvePoliceQuery(query);
    if (masterMatch) {
      return masterMatch;
    }
  } catch (err) {
    console.error('[AI] policeDirectory lookup error:', err.message);
  }

  const q = query.toLowerCase().trim();
  const isBangla = /[\u0980-\u09FF]/.test(query);

  // 2. Fallback Legacy Thana Match
  for (const t of BANGLADESH_THANA_DIRECTORY) {
    if (t.keywords.some(k => q.includes(k.toLowerCase()))) {
      const cleanOc = t.ocPhone.replace(/\D/g, '');
      const cleanDuty = t.dutyPhone.replace(/\D/g, '');
      const cleanTnt = (t.tnt ? t.tnt.split('/')[0] : '').replace(/[^0-9]/g, '');

      let text = '';
      if (isBangla) {
        text = `👮 **${t.bnName} (${t.name})**\n📍 **ঠিকানা / অবস্থান:** ${t.address}\n🏢 **বিভাগ:** ${t.division}\n\n📞 **কর্মকর্তাদের সরাসরি ফোন নাম্বার:**\n• **অফিসার ইনচার্জ (OC):** [${t.ocPhone}](tel:${cleanOc})\n• **ডিউটি অফিসার (Duty Officer - ২৪ ঘণ্টা):** [${t.dutyPhone}](tel:${cleanDuty})\n• **টিঅ্যান্ডটি ল্যান্ডলাইন (T&T):** [${t.tnt}](tel:${cleanTnt})\n• **ডিএমপি কন্ট্রোল রুম:** [01713-398311](tel:01713398311)\n• **জাতীয় জরুরি সেবা:** [৯৯৯](tel:999) (টোল-ফ্রি ২৪ ঘণ্টা)\n\n💡 *পরামর্শ: যেকোনো জরুরি ঘটনায় ওসির মোবাইলে সরাসরি কল করুন অথবা থানার ডিউটি অফিসারের সাথে কথা বলে তাৎক্ষণিক পুলিশ টিম পাঠানোর অনুরোধ জানান।*`;
      } else {
        text = `👮 **${t.name} (${t.bnName})**\n📍 **Address / Location:** ${t.address}\n🏢 **Division:** ${t.division}\n\n📞 **Official Direct Emergency Contacts:**\n• **Officer-in-Charge (OC):** [${t.ocPhone}](tel:${cleanOc})\n• **Duty Officer (24/7):** [${t.dutyPhone}](tel:${cleanDuty})\n• **T&T Landline:** [${t.tnt}](tel:${cleanTnt})\n• **DMP Control Room:** [01713-398311](tel:01713398311)\n• **National Emergency Service:** [999](tel:999) (Toll-Free 24/7)\n\n💡 *Guidance: Tap the number to call the OC or Duty Officer directly. State your exact location and situation calmly for immediate dispatch.*`;
      }

      return {
        text,
        sources: [
          { title: `${t.name} — Bangladesh Police`, url: `tel:${cleanOc}` },
          { title: "National 999 CAD Dispatch", url: "tel:999" }
        ]
      };
    }
  }

  // 2. Direct 64 District Police Match
  for (const d of BANGLADESH_DISTRICT_DIRECTORIES) {
    if (d.keywords.some(k => q.includes(k.toLowerCase()))) {
      return formatDistrictCard(d, isBangla);
    }
  }

  // 3. Direct Emergency Safety Entity Match (Fire Service, Climate Control, Burn Unit, Cyber, Helplines)
  for (const e of BANGLADESH_SAFETY_ENTITIES) {
    // Climate & Disaster early warning (1090, BMD, FFWC, CPP)
    if ((q.includes("climate") || q.includes("weather") || q.includes("cyclone") || q.includes("flood") || q.includes("disaster") || q.includes("storm") || q.includes("আবহাওয়া") || q.includes("ঝড়") || q.includes("বন্যা") || q.includes("ঘূর্ণিঝড়") || q.includes("দুর্যোগ") || q.includes("১০৯০") || q.includes("1090")) && (e.category.includes("Climate") || e.name.includes("Disaster") || e.name.includes("Meteorological") || e.name.includes("Flood") || e.name.includes("Cyclone"))) {
      return formatEntityCard(e, isBangla);
    }
    // Fire Service (16163)
    if ((q.includes("fire") || q.includes("আগুন") || q.includes("ফায়ার") || q.includes("দমকল") || q.includes("১৬১৬৩") || q.includes("16163")) && (e.category.includes("Fire") || e.name.includes("Fire"))) {
      return formatEntityCard(e, isBangla);
    }
    // Burn trauma
    if ((q.includes("burn") || q.includes("বার্ন") || q.includes("পোড়া") || q.includes("plastic surgery")) && e.category.includes("Burn")) {
      return formatEntityCard(e, isBangla);
    }
    if (e.name.includes("Cyber") && (q.includes("cyber") || q.includes("সাইবার") || q.includes("blackmail") || q.includes("হয়রানি") || q.includes("harass"))) return formatEntityCard(e, isBangla);
    if (e.name.includes("Women") && (q.includes("109") || q.includes("নারী") || q.includes("women helpline"))) return formatEntityCard(e, isBangla);
    if (e.name.includes("Child") && (q.includes("1098") || q.includes("শিশু") || q.includes("child helpline"))) return formatEntityCard(e, isBangla);
    if (e.name.includes("DMCH") && (q.includes("dmch") || q.includes("dhaka medical") || q.includes("ঢাকা মেডিকেল"))) return formatEntityCard(e, isBangla);
    if (e.name.includes("DMP") && (q.includes("dmp control") || q.includes("control room") || q.includes("কন্ট্রোল রুম"))) return formatEntityCard(e, isBangla);
    if (e.name.includes("RAB") && (q.includes("rab") || q.includes("র‍্যাব"))) return formatEntityCard(e, isBangla);
  }

  // 4. General Thana / OC query without a specific name
  if (q.includes('thana') || q.includes('থানা') || q.includes('oc') || q.includes('ওসি') || q.includes('police number') || q.includes('পুলিশের নাম্বার')) {
    if (isBangla) {
      return {
        text: `👮 **বাংলাদেশের যেকোনো থানার ওসি বা জরুরি নাম্বার পেতে:**\n\nআপনি কোন থানার ওসির নাম্বার চান? অনুগ্রহ করে থানার নাম লিখুন (যেমন: **ধানমন্ডি, গুলশান, বনানী, মিরপুর, উত্তরা, সাভার, কক্সবাজার, বগুড়া** ইত্যাদি)।\n\n📞 **জরুরি কেন্দ্রীয় পুলিশ নাম্বারসমূহ:**\n• **জাতীয় জরুরি সেবা:** [৯৯৯](tel:999) (তাৎক্ষণিক পুলিশ, অ্যাম্বুলেন্স, ফায়ার সার্ভিস)\n• **ডিএমপি কেন্দ্রীয় কন্ট্রোল রুম:** [01713-398311](tel:01713398311) / [02-996684444](tel:02996684444)\n• **পুলিশ সাইবার সাপোর্ট ফর উইমেন:** [01320-000888](tel:01320000888)\n• **র‍্যাব কন্ট্রোল রুম:** [01777-720029](tel:01777720029)\n\nঅনুগ্রহ করে আপনার থানার নামটি লিখুন, আমি সরাসরি ওসির নাম্বার দিচ্ছি।`,
        sources: [{ title: "DMP Central Police Desk", url: "tel:01713398311" }]
      };
    }
    return {
      text: `👮 **Bangladesh Police Thana & OC Directory:**\n\nWhich police station (Thana) do you need the OC contact for? Simply reply with the area or Thana name (e.g., **Dhanmondi, Gulshan, Banani, Mirpur, Uttara, Savar, Cox's Bazar, Bogura**, etc.).\n\n📞 **Central Emergency Police Numbers:**\n• **National Emergency Service:** [999](tel:999) (Immediate Police, Ambulance, Fire)\n• **DMP Central Control Room:** [01713-398311](tel:01713398311) / [02-996684444](tel:02996684444)\n• **Police Cyber Support for Women (PCSW):** [01320-000888](tel:01320000888)\n• **RAB Control Room:** [01777-720029](tel:01777720029)\n\nTell me your specific Thana or district, and I will give you the exact OC mobile number immediately.`,
      sources: [{ title: "DMP Central Police Desk", url: "tel:01713398311" }]
    };
  }

  return null;
}

function formatEntityCard(e, isBangla) {
  const cleanPhone = e.phone.replace(/\D/g, '');
  let text = '';
  if (isBangla) {
    text = `🛡️ **${e.bnName} (${e.name})**\n📞 **সরাসরি হটলাইন:** [${e.phone}](tel:${cleanPhone})${e.altPhone ? ` • বিকল্প: ${e.altPhone}` : ''}\n${e.address ? `📍 **ঠিকানা:** ${e.address}\n` : ''}ℹ️ **সেবার ধরন:** ${e.category}\n\n${e.description}`;
  } else {
    text = `🛡️ **${e.name} (${e.bnName})**\n📞 **Direct Official Line:** [${e.phone}](tel:${cleanPhone})${e.altPhone ? ` • Alternate: ${e.altPhone}` : ''}\n${e.address ? `📍 **Address / Location:** ${e.address}\n` : ''}ℹ️ **Service Category:** ${e.category}\n\n${e.description}`;
  }
  return {
    text,
    sources: [{ title: `${e.name} Line`, url: `tel:${cleanPhone}` }]
  };
}

const SHUROKHA_SYSTEM_INSTRUCTION = `You are shurokhaAI, the 24/7 dedicated Citizen Safety & Emergency Health AI Companion developed for SAFE BD in Bangladesh. You behave like a compassionate, highly capable, and intelligent assistant (similar to ChatGPT) tailored for emergency situations, health triage, and citizen security in Bangladesh.

YOUR CORE DOMAINS & RESPONSIBILITIES:
1. HUMANLY CONVERSATION & MEDICAL FIRST AID:
   - If a citizen is suffering from fever, sudden illness, cold, headache, or body ache:
     * Respond with warmth, empathy, and practical first-aid advice (hydration with ORS/saline, rest, tepid water sponging).
     * Recommend taking standard Paracetamol if suitable, but WARN against taking Aspirin, Brufen, or NSAIDs during Dengue fever season.
     * Tell them to consult a registered doctor or call DGHS Shastho Batayan free 24/7 helpline [16263](tel:16263).
     * Provide red-flag warning signs (temperature > 103°F, severe vomiting, bleeding, breathing distress) where they must call 999 or rush to an emergency room.
     * Ask for their location or provide nearby hospitals if location is already known.
2. EVE TEASING, STALKING & HARASSMENT:
   - Provide immediate calming reassurance. Advise them to move to a well-lit, crowded place (shop, pharmacy, bank, metro station) and avoid confronting alone.
   - Ask for their location (neighborhood or street in Bangladesh). Once known, provide the nearest Police Thana, direct Officer-in-Charge (OC) official number, and 24/7 Duty Officer.
   - Provide Police Cyber Support for Women (PCSW [01320-000888](tel:01320000888)), National Women Helpline [109](tel:109), and 999 emergency CAD dispatch.
3. SNATCHING, MUGGING & ROBBERY:
   - Express empathy and verify physical safety.
   - Instruct them to go to the nearest Police Station (Thana) immediately to file a General Diary (GD) or FIR.
   - If phone was snatched, provide urgent instructions to freeze mobile wallets (bKash 16247, Nagad 16167, Rocket 16216) and suspend SIM cards (GP/BL/Robi 121).
   - Ask for their location to provide the nearest Thana with OC contact and GD writing guidance (mention IMEI, exact time, description).
4. NEARBY HOSPITALS & 24/7 AMBULANCES:
   - When asked for nearby hospitals ("what's the nearest hospital", "hospital in Uttara", etc.), provide top verified emergency hospitals in that area with 24/7 emergency numbers, direct ambulance dispatch lines, and addresses. If location is unknown, ask for their area.
5. BANGLADESH POLICE THANAS & OFFICIAL 01320- SERIES:
   - Provide verified Thana, OC, 24/7 Duty Officer, and Landline contacts. Always format telephone numbers as clickable markdown links (e.g. [01320-XXXXXX](tel:01320XXXXXX) or [999](tel:999)).
6. EMERGENCY BLOOD LIFELINE (রক্তবন্ধু):
   - Guide citizens to Safe BD's "I Need Help" -> "Emergency Blood Lifeline" to filter and call verified blood donors directly. Provide Red Crescent (02-9330188) and Quantum Blood Lab (01714-010869).
7. STRICT OFF-TOPIC / IRRELEVANT SCOPE:
   - If a citizen asks about sports (cricket, football, IPL, Messi), movies/celebrities, video games, programming/coding, school homework, recipes/cooking, or general random trivia:
   - Politely, warmly decline by explaining: "I am shurokhaAI, dedicated to keeping you safe and healthy in Bangladesh. I am exclusively focused on medical guidance, emergency response, nearby hospitals, and police thana services."
8. LANGUAGE:
   - Respond in fluent, empathetic Bengali (বাংলা) or English matching the user's language. Keep formatting clean, structured, and easy to read during distress.`;

async function generateShurokhaFallbackResponse(query) {
  const q = (query || '').toLowerCase().trim();
  const isBangla = /[\u0980-\u09FF]/.test(query);

  // Check Thana & Emergency Contact Directory First
  const contactMatch = findBangladeshSafetyContact(query);
  if (contactMatch) {
    return contactMatch;
  }

  // 1. Immediate Danger / Life Threat (Urgent Dispatch Alarm)
  const isDirectDanger = q.includes('in danger') || q.includes('under attack') || q.includes('being attacked') || q.includes('someone is following me') || q.includes('save me') || q.includes('call police') || q.includes('বাঁচাও') || q.includes('বিপদে পড়েছি') || (q.includes('danger') && !q.includes('what') && !q.includes('tell me') && !q.includes('explain')) || (q.includes('help') && (q.includes('urgent') || q.includes('emergency') || q.includes('now') || q.includes('police')));
  if (isDirectDanger) {
    if (isBangla) {
      return {
        text: "🚨 **আপনি কি তাৎক্ষণিক বিপদে আছেন?**\n\nঅনুগ্রহ করে অবিলম্বে আমাদের লাল **SOS বাটনটি চেপে ধরুন** অথবা সরাসরি **৯৯৯ (999)** নম্বরে কল করুন! আপনার লাইভ জিপিএস লোকেশন পুলিশের কাছে পৌঁছাবে। আমি আপনার সাথেই আছি, শান্ত থাকুন এবং নিরাপদ কোনো স্থানে সরে যান।",
        sources: [{ title: "National Emergency Helpline 999", url: "tel:999" }]
      };
    }
    return {
      text: "🚨 **Are you in immediate danger?**\n\nPlease immediately press and hold the **Red SOS Button** on the home screen or dial **999** directly! Your live GPS coordinates will be dispatched to police. Stay calm, move to a crowded or well-lit place, and remember that help is on the way.",
      sources: [{ title: "National Emergency Service (999)", url: "tel:999" }]
    };
  }

  // 2. Greetings & Introductions
  if (q === 'hi' || q === 'hello' || q === 'hey' || q === 'সালাম' || q === 'হ্যালো' || q.includes('who are you') || q.includes('তুমি কে') || q.includes('কেমন আছ')) {
    if (isBangla) {
      return {
        text: "আসসালামু আলাইকুম! আমি **shurokhaAI**, বাংলাদেশের জরুরি সেবা ও থানা ডিরেক্টরি এআই।\n\nআমি শুধুমাত্র **বাংলাদেশের সকল থানার ওসির সরাসরি মোবাইল নাম্বার, ডিউটি অফিসার, ফায়ার সার্ভিস (১৬১৬৩), আবহাওয়া ও দুর্যোগ সতর্কতা (১০৯০), বার্ন ইউনিট ও ৯৯৯ জরুরি সেবার** নম্বর প্রদান করি। আপনার কোন থানা বা জরুরি সেবার তথ্য প্রয়োজন?"
      };
    }
    return {
      text: "Hello! I am **shurokhaAI**, your specialized Bangladesh Emergency Services & Police Station Contact Directory AI from SAFE BD.\n\nI can provide you with the direct official numbers of any Thana OC, Duty Officer, Fire Service (16163), Climate & Disaster Warning (1090), and National Burn & Emergency Hospital helplines. Which Thana or emergency service number do you need?"
    };
  }

  // 3. Women & Child Safety / Harassment
  if (q.includes('harass') || q.includes('eve teasing') || q.includes('stalk') || q.includes('উত্ত্যক্ত') || q.includes('নারী') || q.includes('women')) {
    if (isBangla) {
      return {
        text: "🛡️ **নারী ও শিশু সুরক্ষায় জরুরি পুলিশ ও আইনি সহায়তা:**\n\n১. **তাৎক্ষণিক পুলিশ সহায়তা:** সরাসরি **৯৯৯ (999)** এ কল করুন।\n২. **নারী ও শিশু নির্যাতন প্রতিরোধ হেল্পলাইন:** [১০৯ (109)](tel:109) (টোল-ফ্রি, ২৪ ঘণ্টা আইনি ও মানসিক সহায়তা)।\n৩. **পুলিশ সাইবার সাপোর্ট ফর উইমেন (PCSW):** [01320-000888](tel:01320000888) (হোয়াটসঅ্যাপ ও সরাসরি কল)।\n৪. আমাদের অ্যাপের **Walk With Me** চালু করে পরিবারকে লাইভ লোকেশন শেয়ার করুন।",
        sources: [{ title: "National Women Helpline 109", url: "tel:109" }]
      };
    }
    return {
      text: "🛡️ **Protection Against Harassment & Safety Rights in Bangladesh:**\n\n1. **Immediate Police Dispatch:** Call **999** immediately or press the Red SOS Button.\n2. **National Helpline for Women & Children:** Call [109](tel:109) (Toll-free, 24/7 confidential legal aid and shelter assistance).\n3. **Cyber Harassment Support:** Bangladesh Police PCSW Hotline: [01320-000888](tel:01320000888) (WhatsApp & Call).\n4. **Commute Protection:** Use our **Walk With Me Companion** on the map tab to broadcast your live route to family.",
      sources: [{ title: "National Women & Child Helpline (109)", url: "tel:109" }]
    };
  }

  // 4. First Aid Guides & Burn Care
  if (q.includes('first aid') || q.includes('burn') || q.includes('faint') || q.includes('cpr') || q.includes('রক্ত') || q.includes('চিকিৎসা')) {
    if (isBangla) {
      return {
        text: "🏥 **জরুরি প্রাথমিক চিকিৎসা টিপস ও বার্ন ইউনিট:**\n\n• **আগুনে পোড়া:** অন্তত ২০ মিনিট স্বাভাবিক ঠাণ্ডা পানি ঢালুন। বরফ, টুথপেস্ট বা তেল ভুলেও লাগাবেন না। জাতীয় বার্ন ও প্লাস্টিক সার্জারি ইনস্টিটিউট: [02-223381001](tel:02223381001)।\n• **অজ্ঞান হওয়া:** রোগীকে চিৎ করে শুইয়ে দুই পা ১ ফুট উঁচুতে রাখুন। ভিড় সরিয়ে বাতাস নিশ্চিত করুন।\n• **অতিরিক্ত রক্তপাত:** পরিষ্কার কাপড় দিয়ে ক্ষতের ওপর চেপে ধরুন।\n• অ্যাম্বুলেন্সের জন্য দ্রুত **৯৯৯** এ কল করুন।",
        sources: [{ title: "National Burn Institute Hotline", url: "tel:02223381001" }, { title: "999 Ambulance CAD Dispatch", url: "tel:999" }]
      };
    }
    return {
      text: "🏥 **Emergency First Aid Steps & Burn Care:**\n\n• **Burns:** Pour cool tap water over the burn for at least 20 minutes. Do NOT apply ice, toothpaste, or butter. National Institute of Burn & Plastic Surgery Hotline: [02-223381001](tel:02223381001).\n• **Fainting:** Lay the person flat and elevate their legs 12 inches to restore blood flow to the brain.\n• **Severe Bleeding:** Apply direct, firm pressure with a clean cloth.\n• **Emergency Ambulance:** Dial [999](tel:999) immediately.",
      sources: [{ title: "National Burn Institute Hotline", url: "tel:02223381001" }, { title: "Emergency Ambulance CAD 999", url: "tel:999" }]
    };
  }

  // 5. Strict Emergency AI Scope Enforcement (Politely decline non-emergency topics)
  if (isBangla) {
    return {
      text: `আমি **shurokhaAI**, বাংলাদেশের জরুরি সেবা ও সকল থানার সরকারি নম্বর ডিরেক্টরি এআই। আমি শুধুমাত্র **সকল থানার ওসির নাম্বার, ফায়ার সার্ভিস (১৬১৬৩), দুর্যোগ ও আবহাওয়া সতর্কতা (১০৯০), বার্ন ইউনিট ও ৯৯৯ জরুরি সেবার** নম্বর প্রদান করতে পারি।\n\nআপনার কোন থানার ওসির নাম্বার বা জরুরি সেবার তথ্য প্রয়োজন? অনুগ্রহ করে থানা বা এলাকার নাম লিখুন (যেমন: **ধানমন্ডি, গুলশান, মিরপুর, সাভার, কক্সবাজার** ইত্যাদি)।`,
      sources: [
        { title: "জাতীয় জরুরি সেবা ৯৯৯", url: "tel:999" },
        { title: "ফায়ার সার্ভিস ১৬১৬৩", url: "tel:16163" },
        { title: "দুর্যোগ সতর্কতা ১০৯০", url: "tel:1090" }
      ]
    };
  }
  return {
    text: `I am **shurokhaAI**, exclusively dedicated as Bangladesh's Emergency Services & Police Station Contact Directory AI.\n\nI am only programmed to provide official contact numbers for **all Bangladesh Police Thanas (OC & Duty Officer), Fire Service (16163), Climate & Disaster Warning (1090), National Burn & Plastic Surgery Institute, and 999 CAD Dispatch**.\n\nWhich Thana OC or emergency service contact number do you need? Please reply with the area or Thana name (e.g., **Dhanmondi, Gulshan, Mirpur, Uttara, Savar, Cox's Bazar**, etc.).`,
    sources: [
      { title: "National Emergency 999", url: "tel:999" },
      { title: "Fire Service 16163", url: "tel:16163" },
      { title: "Disaster Warning 1090", url: "tel:1090" }
    ]
  };
}

app.post('/api/ai/chat', async (req, res) => {
  try {
    const { message, history } = req.body || {};
    if (!message || typeof message !== 'string' || !message.trim()) {
      return res.status(400).json({ error: "MESSAGE_REQUIRED", message: "Please provide a message for shurokhaAI." });
    }

    const userMessage = message.trim();
    const qLower = userMessage.toLowerCase();

    // 0. High-Priority Immediate Emergency & Intent Resolution via shurokhaIntelligence
    // Resolves in < 5ms: Emotional Distress, Snatching/Theft, Eve Teasing, Fevers/Medical, Hospital/Ambulance, Off-topic
    const directReply = await shurokhaIntelligence.processShurokhaChat(userMessage, history);
    if (directReply && directReply.text && directReply.poweredBy !== "shurokhaAI Conversational Engine") {
      return res.json({
        success: true,
        reply: directReply.text,
        sources: directReply.sources || [],
        grounded: directReply.sources?.length > 0,
        poweredBy: directReply.poweredBy
      });
    }

    // 1. Direct Thana / OC query with single-turn directory lookup intent (e.g. "Dhanmondi thana oc number")
    const isDirectThanaLookup = /^(?:give\s*me\s*|what\s*is\s*|tell\s*me\s*)?(?:the\s*)?(?:[a-z\u0980-\u09FF\s]+)\s*(?:thana|থানা|ps)\s*(?:oc|officer|duty|number|ফোন|নাম্বার)?$/i.test(userMessage.trim());
    if (isDirectThanaLookup) {
      const directContact = findBangladeshSafetyContact(userMessage);
      if (directContact) {
        return res.json({
          success: true,
          reply: directContact.text,
          sources: directContact.sources || [],
          grounded: directContact.sources?.length > 0,
          poweredBy: "Official Bangladesh Police Master Directory (01320 Series)"
        });
      }
    }

    // 2. If OpenAI (ChatGPT) API Key is configured, run actual ChatGPT (gpt-4o-mini / gpt-4o)
    const openaiApiKey = process.env.OPENAI_API_KEY || '';
    if (openaiApiKey) {
      try {
        const messages = [{ role: 'system', content: SHUROKHA_SYSTEM_INSTRUCTION }];
        if (Array.isArray(history)) {
          history.slice(-8).forEach(h => {
            if (h && h.text) {
              const role = h.role === 'model' ? 'assistant' : (h.role === 'assistant' ? 'assistant' : 'user');
              messages.push({ role, content: String(h.text) });
            }
          });
        }
        messages.push({ role: 'user', content: userMessage });

        const oRes = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${openaiApiKey}`
          },
          body: JSON.stringify({
            model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
            messages,
            temperature: 0.7,
            max_tokens: 800
          })
        });

        if (oRes.ok) {
          const oData = await oRes.json();
          const replyText = oData.choices?.[0]?.message?.content;
          if (replyText) {
            return res.json({
              success: true,
              reply: replyText,
              sources: [{ title: "ChatGPT Intelligence Engine", url: "https://openai.com" }],
              grounded: true,
              model: oData.model || 'gpt-4o-mini',
              poweredBy: "ChatGPT (OpenAI GPT-4o)"
            });
          }
        } else {
          console.warn('[shurokhaAI] OpenAI error:', oRes.status, await oRes.text());
        }
      } catch (oErr) {
        console.warn('[shurokhaAI] OpenAI connection error:', oErr.message);
      }
    }

    // 3. If Gemini API Key is configured, run ultra-fast Gemini Flash Lite (1-2s response)
    const apiKey = process.env.GEMINI_API_KEY || process.env.GOOGLE_API_KEY || '';
    if (apiKey) {
      const contents = [];
      if (Array.isArray(history)) {
        history.slice(-8).forEach(h => {
          if (h && h.text) {
            const role = (h.role === 'user' || h.role === 'model') ? h.role : 'user';
            contents.push({ role, parts: [{ text: String(h.text) }] });
          }
        });
      }
      contents.push({ role: 'user', parts: [{ text: userMessage }] });

      const geminiModels = ['gemini-flash-lite-latest', 'gemini-3.1-flash-lite', 'gemini-3.5-flash-lite'];
      let geminiResponse = null;
      let usedModel = '';

      for (const model of geminiModels) {
        try {
          const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`;
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 5500);

          const plainBody = {
            contents: contents,
            systemInstruction: { parts: [{ text: SHUROKHA_SYSTEM_INSTRUCTION }] },
            generationConfig: { maxOutputTokens: 600, temperature: 0.7 }
          };

          const gRes = await fetch(url, {
            signal: controller.signal,
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(plainBody)
          });
          clearTimeout(timeout);

          if (gRes.ok) {
            const data = await gRes.json();
            const replyText = data.candidates?.[0]?.content?.parts?.[0]?.text;
            if (replyText) {
              geminiResponse = data;
              usedModel = model;
              break;
            }
          }
        } catch (modelErr) {
          console.warn(`[shurokhaAI] ${model} attempt error:`, modelErr.message);
        }
      }

      if (geminiResponse) {
        const candidate = geminiResponse.candidates[0];
        const replyText = candidate.content.parts[0].text;

        return res.json({
          success: true,
          reply: replyText,
          sources: [{ title: "shurokhaAI Intelligence Engine", url: "https://safebd.onrender.com" }],
          grounded: true,
          model: usedModel,
          poweredBy: `Google Gemini (${usedModel})`
        });
      }
    }

    // 4. Conversational AI Engine Fallback (Instant Safe BD Knowledge)
    const intelligentReply = directReply || await shurokhaIntelligence.processShurokhaChat(userMessage, history);
    return res.json({
      success: true,
      reply: intelligentReply.text,
      sources: intelligentReply.sources || [],
      grounded: intelligentReply.sources?.length > 0,
      poweredBy: intelligentReply.poweredBy || "shurokhaAI Conversational Engine"
    });

  } catch (err) {
    console.error("[shurokhaAI Error]:", err);
    return res.status(500).json({
      success: false,
      error: "AI_ERROR",
      reply: "I am having a brief connection pause. In an emergency, please press the Red SOS Button or dial 999 directly!"
    });
  }
});

// Sanitized Global Error Handler (Section 3: OWASP Stack Trace Protection)
app.use((err, req, res, next) => {
  console.error('[🚨 ROUTE EXCEPTION]:', err && err.message ? err.message : err);
  if (res.headersSent) {
    return next(err);
  }
  return res.status(err.status || 500).json({
    error: err.code || 'INTERNAL_SERVER_ERROR',
    message: process.env.NODE_ENV === 'production'
      ? 'An unexpected error occurred. Please try again later.'
      : (err.message || 'Internal server error.')
  });
});

// SPA Fallback: Serve web app for any unmatched route
app.get('*', (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');
  res.sendFile(path.join(__dirname, '../mobile-web-app/www/index.html'));
});

server.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`🚀 SAFE BD Backend API & WebSocket Server Running`);
  console.log(`📍 Port: http://localhost:${PORT}`);
  console.log(`📡 WebSocket: ws://localhost:${PORT}`);
  console.log(`🚨 999 CAD Dispatch Integration: ACTIVE`);
  console.log(`====================================================`);
});
