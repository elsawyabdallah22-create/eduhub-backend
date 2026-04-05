// ══════════════════════════════════════════════════════════════
//  EduHub Backend API — النسخة الذكية (بدء الوقت عند الدخول)
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

const app = express();
const PORT = process.env.PORT || 3000;

// ── FIREBASE CONNECTION ──────────────────────────────
try {
    const serviceAccountPath = path.join(__dirname, 'serviceAccount.json');
    const serviceAccount = require(serviceAccountPath);

    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        storageBucket: process.env.FIREBASE_STORAGE_BUCKET || 'eduhub-c1395.firebasestorage.app'
    });
    console.log("✅ Firebase Connected Successfully");
} catch (error) {
    console.error("❌ Firebase Error:", error.message);
    process.exit(1);
}

const db = admin.firestore();

// ── SECURITY & MIDDLEWARE ──────────────────────────────
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' }, contentSecurityPolicy: false }));
app.use(cors({ origin: '*', methods: ['GET','POST'], allowedHeaders: ['Content-Type','x-user-code'] }));
app.use(express.json());

const globalLimiter = rateLimit({ windowMs: 60 * 1000, max: 100 });
app.use(globalLimiter);

const JWT_SECRET = process.env.JWT_SECRET || 'SUPER_SECRET_KEY';
const ADMIN_PIN  = process.env.ADMIN_PIN  || '000000';

// ── ROUTES ─────────────────────────────────────────────

app.get('/health', (req, res) => res.json({ status: 'ok', project: 'EduHub' }));

// مسار تسجيل الدخول الذكي (تفعيل الكود عند أول دخول)
app.post('/auth/login', async (req, res) => {
    const userCode = req.headers['x-user-code'];
    if (!userCode) return res.status(401).json({ error: 'Code required' });

    const cleanCode = userCode.trim().toUpperCase();

    try {
        const codeRef = db.collection('codes').doc(cleanCode);
        const doc = await codeRef.get();

        if (!doc.exists) return res.status(404).json({ error: 'الكود غير موجود' });

        const data = doc.data();

        // ✨ التفعيل التلقائي: إذا كان الكود جديداً ولم يستخدم بعد
        if (data.activated === false) {
            const oneHour = 3600000; // ساعة بالملي ثانية
            const duration = data.duration || oneHour; // يستخدم المدة المحددة أو ساعة افتراضية
            const expiryTime = Date.now() + duration;

            await codeRef.update({
                activated: true,
                expiresAt: expiryTime,
                startTime: admin.firestore.FieldValue.serverTimestamp()
            });
            console.log(`🚀 Code ${cleanCode} has been activated just now.`);
        }

        // تحديث سجلات الدخول العادية
        await codeRef.update({
            lastLogin: admin.firestore.FieldValue.serverTimestamp(),
            lastIP: req.ip,
        });

        res.json({ ok: true, activatedNow: data.activated === false });
    } catch (e) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// مسار التحقق من بن الإدمن (لوحة التحكم)
app.post('/admin/verify', async (req, res) => {
    const { pin } = req.body;
    if (pin === ADMIN_PIN) {
        const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '4h' });
        res.json({ token });
    } else {
        res.status(403).json({ error: 'Invalid PIN' });
    }
});

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));