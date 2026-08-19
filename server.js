const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const util = require('util');
const rateLimit = require('express-rate-limit');

const scryptAsync = util.promisify(crypto.scrypt);

const app = express();

const PORT = Number(process.env.PORT) || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

const ADMIN_USER = String(process.env.ADMIN_USER || 'admin').trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const SESSION_SECRET = process.env.SESSION_SECRET || '';
const RECOVERY_CONTACT = process.env.RECOVERY_CONTACT || 'با ادمین EmadNet تماس بگیرید';

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const TELEGRAM_ADMIN_CHAT_ID = process.env.TELEGRAM_ADMIN_CHAT_ID || '';

const SUPPLIER_API_KEY = process.env.SUPPLIER_API_KEY || '';
const SUPPLIER_API_URL = process.env.SUPPLIER_API_URL || '';

const BACKUP_TOKEN = process.env.BACKUP_TOKEN || '';

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(express.json({ limit: '512kb' }));
app.use(express.urlencoded({ extended: false, limit: '512kb' }));

if (!SESSION_SECRET) {
  console.warn('WARNING: SESSION_SECRET is not set.');
}

app.use(session({
  name: 'emadnet.sid',
  secret: SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  rolling: true,
  proxy: true,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: 'auto',
    maxAge: 1000 * 60 * 60 * 24 * 7
  }
}));

// Rate Limiter برای جلوگیری از هک و فشار CPU روی لاگین و ثبت نام
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 دقیقه
  max: 15, // حداکثر ۱۵ درخواست
  message: { error: 'تعداد درخواست‌های شما زیاد بوده است. لطفاً ۱۵ دقیقه دیگر دوباره تلاش کنید.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// هش کردن پسورد به‌صورت Non-blocking (Async) برای جلوگیری از قفل شدن CPU
async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hashBuf = await scryptAsync(password, salt, 64);
  return `${salt}:${hashBuf.toString('hex')}`;
}

async function verifyPassword(password, stored) {
  try {
    if (!stored) return false;
    const [salt, original] = String(stored).split(':');
    if (!salt || !original) return false;

    const hashBuf = await scryptAsync(password, salt, 64);
    const buf = Buffer.from(original, 'hex');

    return hashBuf.length === buf.length && crypto.timingSafeEqual(hashBuf, buf);
  } catch {
    return false;
  }
}

function safeUser(user) {
  return {
    id: user.id,
    username: user.username,
    role: user.role
  };
}

function defaultDatabase() {
  return {
    users: [],
    recoveryRequests: [],
    orders: [],
    coupons: [],
    plans: [
      { id: 1, name: 'Starter', gb: 50, days: 30, price: 120000, active: true },
      { id: 2, name: 'Pro', gb: 150, days: 90, price: 300000, active: true },
      { id: 3, name: 'Max', gb: 400, days: 180, price: 520000, active: true }
    ]
  };
}

// خواندن دیتابیس به‌صورت غیرهمگام (Async)
async function readDB() {
  try {
    if (!fs.existsSync(DB_FILE)) return defaultDatabase();

    const raw = await fs.promises.readFile(DB_FILE, 'utf8');
    const db = JSON.parse(raw);

    return {
      users: Array.isArray(db.users) ? db.users : [],
      recoveryRequests: Array.isArray(db.recoveryRequests) ? db.recoveryRequests : [],
      orders: Array.isArray(db.orders) ? db.orders : [],
      coupons: Array.isArray(db.coupons) ? db.coupons : [],
      plans: Array.isArray(db.plans) ? db.plans : []
    };
  } catch (error) {
    console.error('DATABASE READ ERROR:', error);
    return defaultDatabase();
  }
}

// جلوگیری از Race Condition با صف نوشتن ساده (Mutex)
let writeQueue = Promise.resolve();

function writeDB(db) {
  writeQueue = writeQueue.then(async () => {
    await fs.promises.mkdir(DATA_DIR, { recursive: true });
    const tempFile = `${DB_FILE}.tmp`;
    await fs.promises.writeFile(tempFile, JSON.stringify(db, null, 2), 'utf8');
    await fs.promises.rename(tempFile, DB_FILE);
  }).catch(err => {
    console.error('DATABASE WRITE ERROR:', err);
  });
  return writeQueue;
}

async function ensureDB() {
  await fs.promises.mkdir(DATA_DIR, { recursive: true });

  if (!fs.existsSync(DB_FILE)) {
    const db = defaultDatabase();
    const initialPassword = ADMIN_PASSWORD || crypto.randomBytes(24).toString('hex');

    if (!ADMIN_PASSWORD) {
      console.warn('WARNING: ADMIN_PASSWORD is not set. A random admin password was generated for this first database.');
    }

    db.users.push({
      id: 'admin',
      username: ADMIN_USER,
      password: await hashPassword(initialPassword),
      role: 'admin',
      createdAt: new Date().toISOString()
    });

    await writeDB(db);
    return;
  }

  const db = await readDB();

  if (!db.users.some(user => user.username === ADMIN_USER)) {
    const initialPassword = ADMIN_PASSWORD || crypto.randomBytes(24).toString('hex');

    db.users.push({
      id: 'admin',
      username: ADMIN_USER,
      password: await hashPassword(initialPassword),
      role: 'admin',
      createdAt: new Date().toISOString()
    });

    await writeDB(db);
  }
}

function requireLogin(req, res, next) {
  if (!req.session?.user) {
    return res.status(401).json({ error: 'ابتدا وارد حساب خود شوید.' });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (req.session?.user?.role !== 'admin') {
    return res.status(403).json({ error: 'دسترسی ادمین ندارید.' });
  }
  next();
}

function sendTelegram(text) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_ADMIN_CHAT_ID) {
    return Promise.resolve(false);
  }

  return fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      chat_id: TELEGRAM_ADMIN_CHAT_ID,
      text
    })
  }).then(r => r.ok).catch(() => false);
}

async function supplierCreateOrder(order) {
  if (!SUPPLIER_API_KEY || !SUPPLIER_API_URL) {
    return { configured: false, skipped: true };
  }

  try {
    const r = await fetch(SUPPLIER_API_URL, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'Authorization': `Bearer ${SUPPLIER_API_KEY}`
      },
      body: JSON.stringify({
        planId: order.planId,
        planName: order.planName,
        gb: order.gb,
        days: order.days,
        orderId: order.id,
        username: order.username
      })
    });

    const text = await r.text();
    let data;

    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }

    return {
      configured: true,
      ok: r.ok,
      status: r.status,
      data
    };
  } catch (e) {
    return {
      configured: true,
      ok: false,
      error: e.message
    };
  }
}

/* Health check */
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    app: 'EmadNet',
    version: '4.1.0',
    uptime: Math.floor(process.uptime())
  });
});

/* Backup endpoint */
app.get('/internal/backup/export', async (req, res) => {
  try {
    const auth = req.get('authorization') || '';

    if (!BACKUP_TOKEN || auth !== `Bearer ${BACKUP_TOKEN}`) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    if (!fs.existsSync(DB_FILE)) {
      return res.status(404).json({ error: 'Database file not found' });
    }

    const raw = await fs.promises.readFile(DB_FILE, 'utf8');
    const data = JSON.parse(raw);

    res.set('Cache-Control', 'no-store');

    return res.json({
      ok: true,
      app: 'EmadNet',
      createdAt: new Date().toISOString(),
      data
    });
  } catch (error) {
    console.error('BACKUP ERROR:', error);
    return res.status(500).json({ error: 'Backup failed' });
  }
});

app.get('/api/plans', async (req, res) => {
  const db = await readDB();
  res.json(db.plans.filter(p => p.active !== false));
});

app.post('/api/register', authLimiter, async (req, res, next) => {
  try {
    const db = await readDB();
    const username = String(req.body.username || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) {
      return res.status(400).json({ error: 'نام کاربری باید ۳ تا ۳۲ کاراکتر باشد.' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'رمز عبور حداقل باید ۶ کاراکتر باشد.' });
    }

    if (db.users.some(u => u.username === username)) {
      return res.status(409).json({ error: 'این نام کاربری قبلاً ثبت شده است.' });
    }

    const user = {
      id: crypto.randomUUID(),
      username,
      password: await hashPassword(password),
      role: 'customer',
      createdAt: new Date().toISOString()
    };

    db.users.push(user);
    await writeDB(db);

    req.session.regenerate(err => {
      if (err) return next(err);

      req.session.user = safeUser(user);

      req.session.save(saveErr => {
        if (saveErr) return next(saveErr);

        sendTelegram(`🆕 ثبت‌نام جدید\nکاربر: ${username}`).catch(() => {});
        res.json({ ok: true, user: safeUser(user) });
      });
    });
  } catch (e) {
    next(e);
  }
});

app.post('/api/login', authLimiter, async (req, res, next) => {
  try {
    const db = await readDB();
    const username = String(req.body.username || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const user = db.users.find(u => u.username === username);

    const isMatch = user ? await verifyPassword(password, user.password) : false;

    if (!user || !isMatch) {
      return res.status(401).json({ error: 'نام کاربری یا رمز عبور اشتباه است.' });
    }

    req.session.regenerate(err => {
      if (err) return next(err);

      req.session.user = safeUser(user);

      req.session.save(saveErr => {
        if (saveErr) return next(saveErr);
        res.json({ ok: true, user: safeUser(user) });
      });
    });
  } catch (e) {
    next(e);
  }
});

app.post('/api/logout', (req, res, next) => {
  if (!req.session) return res.json({ ok: true });

  req.session.destroy(err => {
    if (err) return next(err);
    res.clearCookie('emadnet.sid');
    res.json({ ok: true });
  });
});

app.get('/api/me', (req, res) => {
  if (!req.session?.user) return res.status(401).json({ loggedIn: false });
  res.json({ loggedIn: true, user: req.session.user });
});

app.post('/api/change-password', requireLogin, async (req, res) => {
  const db = await readDB();
  const user = db.users.find(u => u.id === req.session.user.id);
  const oldPassword = String(req.body.oldPassword || '');
  const newPassword = String(req.body.newPassword || '');

  const isMatch = user ? await verifyPassword(oldPassword, user.password) : false;

  if (!user || !isMatch) {
    return res.status(401).json({ error: 'رمز فعلی اشتباه است.' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'رمز جدید حداقل ۶ کاراکتر باشد.' });
  }

  user.password = await hashPassword(newPassword);
  await writeDB(db);

  res.json({ ok: true, message: 'رمز عبور با موفقیت تغییر کرد.' });
});

app.post('/api/recovery', authLimiter, async (req, res) => {
  const db = await readDB();
  const username = String(req.body.username || '').trim().toLowerCase();

  if (!username) {
    return res.status(400).json({ error: 'نام کاربری را وارد کنید.' });
  }

  const item = {
    id: crypto.randomUUID(),
    username,
    status: 'pending',
    createdAt: new Date().toISOString()
  };

  db.recoveryRequests.push(item);
  await writeDB(db);

  sendTelegram(`🔐 درخواست بازیابی رمز\nکاربر: ${username}\nوضعیت: pending`).catch(() => {});

  res.json({
    ok: true,
    message: 'درخواست بازیابی ثبت شد. ادمین آن را بررسی می‌کند.',
    contact: RECOVERY_CONTACT
  });
});

app.get('/api/recovery-status', requireLogin, async (req, res) => {
  const db = await readDB();

  const rows = db.recoveryRequests
    .filter(r => r.username === req.session.user.username)
    .slice(-10)
    .reverse();

  res.json(rows);
});

app.post('/api/orders', requireLogin, async (req, res, next) => {
  try {
    const db = await readDB();
    const plan = db.plans.find(
      p => p.id === Number(req.body.planId) && p.active !== false
    );

    if (!plan) {
      return res.status(404).json({ error: 'این پلن پیدا نشد.' });
    }

    let discount = 0;
    let couponCode = '';

    const code = String(req.body.coupon || '').trim().toUpperCase();

    if (code) {
      const c = db.coupons.find(
        c =>
          c.code === code &&
          c.active &&
          (!c.expiresAt || new Date(c.expiresAt) > new Date())
      );

      if (!c) {
        return res.status(400).json({ error: 'کد تخفیف معتبر نیست.' });
      }

      discount =
        c.type === 'percent'
          ? Math.floor(plan.price * c.value / 100)
          : Math.min(plan.price, c.value);

      couponCode = code;
    }

    const order = {
      id: crypto.randomUUID(),
      userId: req.session.user.id,
      username: req.session.user.username,
      planId: plan.id,
      planName: plan.name,
      gb: plan.gb,
      days: plan.days,
      price: plan.price,
      discount,
      finalPrice: plan.price - discount,
      coupon: couponCode,
      status: 'pending',
      supplierStatus: 'not_sent',
      createdAt: new Date().toISOString()
    };

    db.orders.push(order);
    await writeDB(db);

    sendTelegram(
      `🛒 سفارش جدید\nکاربر: ${order.username}\nپلن: ${order.planName}\nمبلغ: ${order.finalPrice.toLocaleString()} تومان\nوضعیت: pending`
    ).catch(() => {});

    const supplier = await supplierCreateOrder(order);

    const fresh = await readDB();
    const saved = fresh.orders.find(o => o.id === order.id);

    if (saved && supplier.configured) {
      saved.supplierStatus = supplier.ok ? 'sent' : 'error';
      saved.supplierResponse = supplier.ok
        ? supplier.data
        : (supplier.error || supplier.data);

      await writeDB(fresh);
    }

    res.json({
      ok: true,
      order: saved || order,
      supplier
    });
  } catch (e) {
    next(e);
  }
});

app.get('/api/dashboard', requireLogin, async (req, res) => {
  const db = await readDB();

  res.json({
    user: req.session.user,
    orders: db.orders.filter(o => o.userId === req.session.user.id)
  });
});

app.get('/api/admin/summary', requireAdmin, async (req, res) => {
  const db = await readDB();

  res.json({
    users: db.users.filter(u => u.role === 'customer').length,
    orders: db.orders.length,
    recovery: db.recoveryRequests.filter(r => r.status === 'pending').length,
    coupons: db.coupons.filter(c => c.active).length
  });
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const db = await readDB();
  res.json(db.users.filter(u => u.role === 'customer').map(safeUser));
});

app.get('/api/admin/orders', requireAdmin, async (req, res) => {
  const db = await readDB();
  res.json(db.orders);
});

app.get('/api/admin/recovery', requireAdmin, async (req, res) => {
  const db = await readDB();
  res.json(db.recoveryRequests);
});

app.post('/api/admin/reset-password', requireAdmin, async (req, res) => {
  const db = await readDB();
  const username = String(req.body.username || '').trim().toLowerCase();
  const newPassword = String(req.body.newPassword || '');
  const user = db.users.find(u => u.username === username);

  if (!user) {
    return res.status(404).json({ error: 'کاربر پیدا نشد.' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'رمز جدید حداقل ۶ کاراکتر باشد.' });
  }

  user.password = await hashPassword(newPassword);

  const r = db.recoveryRequests.find(
    x => x.username === username && x.status === 'pending'
  );

  if (r) {
    r.status = 'completed';
    r.completedAt = new Date().toISOString();
  }

  await writeDB(db);

  sendTelegram(`✅ رمز کاربر ریست شد\nکاربر: ${username}`).catch(() => {});

  res.json({
    ok: true,
    message: 'رمز کاربر تغییر کرد و درخواست بازیابی تکمیل شد.'
  });
});

app.post('/api/admin/recovery/:id/status', requireAdmin, async (req, res) => {
  const db = await readDB();
  const r = db.recoveryRequests.find(x => x.id === req.params.id);

  if (!r) {
    return res.status(404).json({ error: 'درخواست پیدا نشد.' });
  }

  r.status = String(req.body.status || 'reviewing');
  await writeDB(db);

  res.json({ ok: true, request: r });
});

app.post('/api/admin/coupons', requireAdmin, async (req, res) => {
  const db = await readDB();

  const code = String(req.body.code || '').trim().toUpperCase();
  const type = req.body.type === 'percent' ? 'percent' : 'fixed';
  const value = Number(req.body.value);

  if (
    !/^[A-Z0-9_-]{3,30}$/.test(code) ||
    !Number.isFinite(value) ||
    value <= 0
  ) {
    return res.status(400).json({
      error: 'کد یا مقدار تخفیف نامعتبر است.'
    });
  }

  if (db.coupons.some(c => c.code === code)) {
    return res.status(409).json({
      error: 'این کد قبلاً وجود دارد.'
    });
  }

  db.coupons.push({
    id: crypto.randomUUID(),
    code,
    type,
    value,
    active: true,
    createdAt: new Date().toISOString(),
    expiresAt: req.body.expiresAt || null
  });

  await writeDB(db);
  res.json({ ok: true });
});

app.get('/api/coupons/:code', async (req, res) => {
  const db = await readDB();
  const code = String(req.params.code).toUpperCase();

  const c = db.coupons.find(
    x =>
      x.code === code &&
      x.active &&
      (!x.expiresAt || new Date(x.expiresAt) > new Date())
  );

  if (!c) {
    return res.status(404).json({
      error: 'کد تخفیف معتبر نیست.'
    });
  }

  res.json({
    ok: true,
    type: c.type,
    value: c.value
  });
});

/* Static frontend */
if (fs.existsSync(PUBLIC_DIR)) {
  app.use(express.static(PUBLIC_DIR));
}

app.get('*', (req, res, next) => {
  if (
    req.path.startsWith('/api/') ||
    req.path.startsWith('/internal/')
  ) {
    return next();
  }

  const indexFile = path.join(PUBLIC_DIR, 'index.html');

  if (fs.existsSync(indexFile)) {
    return res.sendFile(indexFile);
  }

  return next();
});

app.use((req, res) => {
  res.status(404).json({ error: 'صفحه پیدا نشد' });
});

app.use((err, req, res, next) => {
  console.error('SERVER ERROR:', err);

  if (res.headersSent) return next(err);

  res.status(500).json({
    error: 'خطای داخلی سرور'
  });
});

ensureDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`EmadNet started on port ${PORT}`);
  });
});
