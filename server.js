// ══════════════════════════════════════════════════════════════
//  EduHub Backend API — Node.js + Firebase Admin SDK
//  النسخة المصححة للعمل مع ملف serviceAccount.json مباشرة
// ══════════════════════════════════════════════════════════════
require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const admin      = require('firebase-admin');
const jwt        = require('jsonwebtoken');
const multer     = require('multer');
const path       = require('path');
const { v4: uuidv4 } = require('uuid');

// ── INIT ─────────────────────────────────────────────────────
const app = express();
const PORT = process.env.PORT || 3000;

// ── FIREBASE CONNECTION (FIXED) ──────────────────────────────
// بدلاً من JSON.parse الفاشل، سنقرأ الملف مباشرة
try {
    const serviceAccountPath = path.join(__dirname, 'serviceAccount.json');
    const serviceAccount = require(serviceAccountPath);

    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        storageBucket: process.env.FIREBASE_STORAGE_BUCKET || 'eduhub-c1395.firebasestorage.app'
    });
    console.log("✅ Firebase Connected Successfully via serviceAccount.json");
} catch (error) {
    console.error("❌ Firebase Initialization Failed!");
    console.error("Error Details:", error.message);
    console.log("تأكد من وجود ملف serviceAccount.json في نفس المجلد بجانب server.js");
    process.exit(1); // إيقاف السيرفر في حالة فشل الاتصال بفايربيز
}

const db      = admin.firestore();
const bucket  = admin.storage().bucket();

// ── SECURITY MIDDLEWARE ───────────────────────────────────────
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  contentSecurityPolicy: false,
}));

app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : '*',
  methods: ['GET','POST','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','x-admin-token','x-user-code'],
}));

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true }));

// ── RATE LIMITING ─────────────────────────────────────────────
const globalLimiter = rateLimit({ windowMs:60*1000, max:120, message:{error:'Too many requests'} });
app.use(globalLimiter);

// ── SECRETS ────────────────────────────────────────────────────
const JWT_SECRET  = process.env.JWT_SECRET  || 'SUPER_SECRET_KEY_FOR_EDU_HUB_2024';
const ADMIN_PIN   = process.env.ADMIN_PIN   || '000000';

// ── MULTER ─────────────────────────────────────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }
});

// ══════════════════════════════════════════════════════════════
//  MIDDLEWARES & HELPERS
// ══════════════════════════════════════════════════════════════
function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!token) return res.status(401).json({ error: 'Admin token required' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== 'admin') throw new Error('Not admin');
    req.admin = payload;
    next();
  } catch(e) {
    return res.status(403).json({ error: 'Invalid or expired admin token' });
  }
}

function requireUser(req, res, next) {
  const code = req.headers['x-user-code'];
  if (!code) return res.status(401).json({ error: 'User code required' });
  req.userCode = code.toUpperCase();
  next();
}

// ══════════════════════════════════════════════════════════════
//  ROUTES (اختصار للوظائف الأساسية للتجربة)
// ══════════════════════════════════════════════════════════════

app.get('/health', (req, res) => res.json({ status: 'ok', project: 'EduHub' }));

// مسار تسجيل دخول الطالب
app.post('/auth/login', requireUser, async (req, res) => {
  try {
    await db.collection('codes').doc(req.userCode).update({
      lastLogin: admin.firestore.FieldValue.serverTimestamp(),
      lastIP: req.ip,
    });
    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ error: 'Login record failed' });
  }
});

// مسار التحقق من بن الإدمن
app.post('/admin/verify', async (req, res) => {
  const { pin } = req.body;
  if (pin === ADMIN_PIN) {
    const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '4h' });
    res.json({ token });
  } else {
    res.status(403).json({ error: 'Invalid PIN' });
  }
});

// ══════════════════════════════════════════════════════════════
//  START SERVER
// ══════════════════════════════════════════════════════════════
app.listen(PORT, () => {
  console.log(`\n🚀 [EduHub Backend] Running on: http://localhost:${PORT}`);
  console.log(`📅 Started at: ${new Date().toLocaleString()}`);
});