const express = require('express');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');

const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'emadnet-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

function defaultDatabase() {
  return {
    users: [],
    plans: [
      { id: 1, name: "پایه (یک ماهه)", price: 50000, gb: 30, days: 30, active: true },
      { id: 2, name: "حرفه‌ای (یک ماهه)", price: 90000, gb: 60, days: 30, active: true },
      { id: 3, name: "نامحدود (سه ماهه)", price: 220000, gb: 200, days: 90, active: true }
    ],
    coupons: [
      { code: "OFF20", percent: 20, active: true }
    ],
    orders: [],
    settings: {
      vpnUrl: "",
      vpnToken: "",
      gatewayId: "",
      gatewayActive: false
    }
  };
}

async function readDB() {
  try {
    const data = await fs.promises.readFile(DB_FILE, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    return defaultDatabase();
  }
}

async function writeDB(data) {
  await fs.promises.writeFile(DB_FILE, JSON.stringify(data, null, 2), 'utf8');
}

async function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

async function ensureDB() {
  await fs.promises.mkdir(DATA_DIR, { recursive: true });
  let db = await readDB();

  let adminUser = db.users.find(u => u.username === ADMIN_USER);
  const hashedPassword = await hashPassword(ADMIN_PASSWORD);

  if (!adminUser) {
    db.users.push({
      id: 'admin',
      username: ADMIN_USER,
      password: hashedPassword,
      role: 'admin'
    });
  } else {
    adminUser.password = hashedPassword;
  }
  await writeDB(db);
}

// Middleware برای احراز هویت ادمین
async function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'دسترسی غیرمجاز' });
  }
  next();
}

// APIs عمومی
app.get('/api/me', (req, res) => {
  if (req.session.user) {
    res.json({ loggedIn: true, user: req.session.user });
  } else {
    res.json({ loggedIn: false });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const db = await readDB();
  const hashedPassword = await hashPassword(password);
  const user = db.users.find(u => u.username === username && u.password === hashedPassword);

  if (!user) {
    return res.status(400).json({ error: 'نام کاربری یا رمز عبور اشتباه است.' });
  }

  req.session.user = { id: user.id, username: user.username, role: user.role };
  res.json({ success: true, user: req.session.user });
});

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  const db = await readDB();

  if (db.users.some(u => u.username === username)) {
    return res.status(400).json({ error: 'این نام کاربری قبلاً ثبت شده است.' });
  }

  const newUser = {
    id: Date.now().toString(),
    username,
    password: await hashPassword(password),
    role: 'user'
  };

  db.users.push(newUser);
  await writeDB(db);

  req.session.user = { id: newUser.id, username: newUser.username, role: newUser.role };
  res.json({ success: true, user: req.session.user });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/plans', async (req, res) => {
  const db = await readDB();
  res.json(db.plans.filter(p => p.active !== false));
});

app.post('/api/orders', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'ابتدا وارد شوید.' });
  const { planId, coupon } = req.body;
  const db = await readDB();

  const plan = db.plans.find(p => p.id === Number(planId));
  if (!plan) return res.status(404).json({ error: 'پلن یافت نشد.' });

  let finalPrice = plan.price;
  if (coupon) {
    const cp = db.coupons.find(c => c.code === coupon && c.active);
    if (cp) {
      finalPrice = finalPrice - (finalPrice * (cp.percent / 100));
    }
  }

  // ایجاد لینک اشتراک فرضی یا اتصال به API
  const vpnLink = db.settings.vpnUrl 
    ? `${db.settings.vpnUrl}/sub/${crypto.randomBytes(8).toString('hex')}`
    : `vless://${crypto.randomUUID()}@emadnet.server.com:443?type=ws#EmadNet-${req.session.user.username}`;

  const newOrder = {
    id: Date.now().toString(),
    userId: req.session.user.id,
    username: req.session.user.username,
    planName: plan.name,
    gb: plan.gb,
    days: plan.days,
    finalPrice,
    vpnLink,
    status: 'فعال',
    createdAt: new Date().toISOString()
  };

  db.orders.push(newOrder);
  await writeDB(db);
  res.json({ success: true, order: newOrder });
});

app.get('/api/dashboard', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'غیرمجاز' });
  const db = await readDB();
  const userOrders = db.orders.filter(o => o.userId === req.session.user.id);
  res.json({ orders: userOrders });
});

// APIs مدیریت ادمین
app.get('/api/admin/summary', requireAdmin, async (req, res) => {
  const db = await readDB();
  res.json({
    users: db.users.length,
    orders: db.orders.length,
    coupons: db.coupons.length,
    plans: db.plans.length
  });
});

app.get('/api/admin/orders', requireAdmin, async (req, res) => {
  const db = await readDB();
  res.json(db.orders);
});

// افزودن / ویرایش / حذف پلن‌ها
app.post('/api/admin/plans', requireAdmin, async (req, res) => {
  const { name, price, gb, days } = req.body;
  const db = await readDB();
  const newPlan = {
    id: Date.now(),
    name,
    price: Number(price),
    gb: Number(gb),
    days: Number(days),
    active: true
  };
  db.plans.push(newPlan);
  await writeDB(db);
  res.json({ success: true, plan: newPlan });
});

app.delete('/api/admin/plans/:id', requireAdmin, async (req, res) => {
  const db = await readDB();
  db.plans = db.plans.filter(p => p.id !== Number(req.params.id));
  await writeDB(db);
  res.json({ success: true });
});

// مدیریت کدهای تخفیف
app.get('/api/admin/coupons', requireAdmin, async (req, res) => {
  const db = await readDB();
  res.json(db.coupons);
});

app.post('/api/admin/coupons', requireAdmin, async (req, res) => {
  const { code, percent } = req.body;
  const db = await readDB();
  const newCoupon = { code, percent: Number(percent), active: true };
  db.coupons.push(newCoupon);
  await writeDB(db);
  res.json({ success: true, coupon: newCoupon });
});

app.delete('/api/admin/coupons/:code', requireAdmin, async (req, res) => {
  const db = await readDB();
  db.coupons = db.coupons.filter(c => c.code !== req.params.code);
  await writeDB(db);
  res.json({ success: true });
});

// ذخیره تنظیمات API و درگاه
app.get('/api/admin/settings', requireAdmin, async (req, res) => {
  const db = await readDB();
  res.json(db.settings || {});
});

app.post('/api/admin/settings', requireAdmin, async (req, res) => {
  const { vpnUrl, vpnToken, gatewayId, gatewayActive } = req.body;
  const db = await readDB();
  db.settings = { vpnUrl, vpnToken, gatewayId, gatewayActive };
  await writeDB(db);
  res.json({ success: true });
});

ensureDB().then(() => {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
});
