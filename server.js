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
  cookie: {
    secure: false,
    httpOnly: true,
    sameSite: 'lax'
  }
}));


/* =========================================================
   DATABASE
========================================================= */

function defaultDatabase() {
  return {
    users: [],

    plans: [
      {
        id: 1,
        name: "پایه (یک ماهه)",
        price: 50000,
        gb: 30,
        days: 30,
        active: true
      },
      {
        id: 2,
        name: "حرفه‌ای (یک ماهه)",
        price: 90000,
        gb: 60,
        days: 30,
        active: true
      },
      {
        id: 3,
        name: "نامحدود (سه ماهه)",
        price: 220000,
        gb: 200,
        days: 90,
        active: true
      }
    ],

    coupons: [
      {
        code: "OFF20",
        percent: 20,
        active: true
      }
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
  await fs.promises.mkdir(DATA_DIR, { recursive: true });

  await fs.promises.writeFile(
    DB_FILE,
    JSON.stringify(data, null, 2),
    'utf8'
  );
}


function hashPassword(password) {
  return crypto
    .createHash('sha256')
    .update(String(password))
    .digest('hex');
}


/* =========================================================
   CREATE / UPDATE ADMIN
========================================================= */

async function ensureDB() {

  await fs.promises.mkdir(DATA_DIR, {
    recursive: true
  });

  const db = await readDB();

  if (!Array.isArray(db.users)) {
    db.users = [];
  }

  const hashedPassword =
    hashPassword(ADMIN_PASSWORD);

  let adminUser =
    db.users.find(
      u =>
        u.username === ADMIN_USER &&
        u.role === 'admin'
    );

  if (!adminUser) {

    adminUser = {
      id: 'admin',
      username: ADMIN_USER,
      password: hashedPassword,
      role: 'admin'
    };

    db.users.push(adminUser);

    console.log(
      `Admin created: ${ADMIN_USER}`
    );

  } else {

    adminUser.password = hashedPassword;

    console.log(
      `Admin password synchronized: ${ADMIN_USER}`
    );
  }

  await writeDB(db);
}


/* =========================================================
   ADMIN AUTH MIDDLEWARE
========================================================= */

function requireAdmin(req, res, next) {

  if (
    !req.session.user ||
    req.session.user.role !== 'admin'
  ) {

    return res.status(403).json({
      error: 'دسترسی غیرمجاز'
    });
  }

  next();
}


/* =========================================================
   USER AUTH
========================================================= */

app.get('/api/me', (req, res) => {

  if (req.session.user) {

    return res.json({
      loggedIn: true,
      user: req.session.user
    });
  }

  res.json({
    loggedIn: false
  });
});


app.post('/api/login', async (req, res) => {

  try {

    const { username, password } =
      req.body || {};

    if (!username || !password) {

      return res.status(400).json({
        error: 'نام کاربری و رمز عبور را وارد کنید.'
      });
    }

    const db = await readDB();

    const hashedPassword =
      hashPassword(password);

    const user =
      db.users.find(
        u =>
          u.username === username &&
          u.password === hashedPassword &&
          u.role !== 'admin'
      );

    if (!user) {

      return res.status(401).json({
        error: 'نام کاربری یا رمز عبور اشتباه است.'
      });
    }

    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role
    };

    res.json({
      success: true,
      user: req.session.user
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: 'خطا در ورود.'
    });
  }
});


app.post('/api/register', async (req, res) => {

  try {

    const { username, password } =
      req.body || {};

    if (!username || !password) {

      return res.status(400).json({
        error: 'نام کاربری و رمز عبور را وارد کنید.'
      });
    }

    const db = await readDB();

    if (
      db.users.some(
        u => u.username === username
      )
    ) {

      return res.status(400).json({
        error: 'این نام کاربری قبلاً ثبت شده است.'
      });
    }

    const newUser = {

      id: Date.now().toString(),

      username,

      password:
        hashPassword(password),

      role: 'user'
    };

    db.users.push(newUser);

    await writeDB(db);

    req.session.user = {
      id: newUser.id,
      username: newUser.username,
      role: newUser.role
    };

    res.json({
      success: true,
      user: req.session.user
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: 'خطا در ثبت‌نام.'
    });
  }
});


app.post('/api/logout', (req, res) => {

  req.session.destroy(() => {

    res.json({
      success: true
    });

  });

});


/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post('/api/admin/login', async (req, res) => {

  try {

    const { username, password } =
      req.body || {};

    if (!username || !password) {

      return res.status(400).json({
        error: 'نام کاربری و رمز عبور ادمین را وارد کنید.'
      });
    }

    const db = await readDB();

    const hashedPassword =
      hashPassword(password);

    const admin =
      db.users.find(
        u =>
          u.username === username &&
          u.password === hashedPassword &&
          u.role === 'admin'
      );

    if (!admin) {

      return res.status(401).json({
        error: 'نام کاربری یا رمز عبور ادمین اشتباه است.'
      });
    }

    req.session.user = {
      id: admin.id,
      username: admin.username,
      role: 'admin'
    };

    res.json({
      success: true,
      authenticated: true,
      admin: true,
      user: req.session.user
    });

  } catch (error) {

    console.error(
      'ADMIN LOGIN ERROR:',
      error
    );

    res.status(500).json({
      error: 'خطا در ورود به پنل مدیریت.'
    });
  }
});


app.get('/api/admin/me', requireAdmin, (req, res) => {

  res.json({
    authenticated: true,
    admin: true,
    user: req.session.user
  });

});


app.post('/api/admin/logout', (req, res) => {

  req.session.destroy(() => {

    res.json({
      success: true
    });

  });

});


/* =========================================================
   PLANS
========================================================= */

app.get('/api/plans', async (req, res) => {

  const db = await readDB();

  res.json(
    db.plans.filter(
      p => p.active !== false
    )
  );

});


app.get(
  '/api/admin/plans',
  requireAdmin,
  async (req, res) => {

    const db = await readDB();

    res.json(db.plans);

  }
);


app.post(
  '/api/admin/plans',
  requireAdmin,
  async (req, res) => {

    const {
      name,
      price,
      gb,
      days
    } = req.body;

    if (
      !name ||
      !price ||
      !gb ||
      !days
    ) {

      return res.status(400).json({
        error: 'تمام اطلاعات پلن را وارد کنید.'
      });
    }

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

    res.json({
      success: true,
      plan: newPlan
    });

  }
);


app.delete(
  '/api/admin/plans/:id',
  requireAdmin,
  async (req, res) => {

    const db = await readDB();

    db.plans =
      db.plans.filter(
        p =>
          Number(p.id) !==
          Number(req.params.id)
      );

    await writeDB(db);

    res.json({
      success: true
    });

  }
);


/* =========================================================
   ORDERS
========================================================= */

app.post('/api/orders', async (req, res) => {

  try {

    if (!req.session.user) {

      return res.status(401).json({
        error: 'ابتدا وارد حساب شوید.'
      });
    }

    const {
      planId,
      coupon
    } = req.body;

    const db = await readDB();

    const plan =
      db.plans.find(
        p =>
          Number(p.id) ===
          Number(planId)
      );

    if (!plan) {

      return res.status(404).json({
        error: 'پلن یافت نشد.'
      });
    }

    let finalPrice =
      Number(plan.price);

    if (coupon) {

      const cp =
        db.coupons.find(
          c =>
            c.code === coupon &&
            c.active
        );

      if (cp) {

        finalPrice =
          finalPrice -
          (
            finalPrice *
            (Number(cp.percent) / 100)
          );
      }
    }

    const vpnLink =
      db.settings &&
      db.settings.vpnUrl
        ? `${db.settings.vpnUrl}/sub/${crypto.randomBytes(8).toString('hex')}`
        : `vless://${crypto.randomUUID()}@emadnet.server.com:443?type=ws#EmadNet-${req.session.user.username}`;

    const newOrder = {

      id: Date.now().toString(),

      userId:
        req.session.user.id,

      username:
        req.session.user.username,

      planName:
        plan.name,

      gb:
        plan.gb,

      days:
        plan.days,

      finalPrice,

      vpnLink,

      subscriptionUrl:
        vpnLink,

      status:
        'pending',

      createdAt:
        new Date().toISOString()
    };

    db.orders.push(newOrder);

    await writeDB(db);

    res.json({
      success: true,
      order: newOrder
    });

  } catch (error) {

    console.error(error);

    res.status(500).json({
      error: 'خطا در ایجاد سفارش.'
    });
  }

});


/* =========================================================
   USER ORDERS
========================================================= */

app.get('/api/my/orders', async (req, res) => {

  if (!req.session.user) {

    return res.status(401).json({
      error: 'ابتدا وارد حساب شوید.'
    });
  }

  const db = await readDB();

  const orders =
    db.orders.filter(
      o =>
        o.userId ===
        req.session.user.id
    );

  res.json({
    orders
  });

});


app.get('/api/dashboard', async (req, res) => {

  if (!req.session.user) {

    return res.status(401).json({
      error: 'غیرمجاز'
    });
  }

  const db = await readDB();

  const orders =
    db.orders.filter(
      o =>
        o.userId ===
        req.session.user.id
    );

  res.json({
    orders
  });

});


/* =========================================================
   USER SUBSCRIPTIONS
========================================================= */

app.get(
  '/api/my/subscriptions',
  async (req, res) => {

    if (!req.session.user) {

      return res.status(401).json({
        error: 'ابتدا وارد حساب شوید.'
      });
    }

    const db = await readDB();

    const subscriptions =
      db.orders
        .filter(
          o =>
            o.userId ===
            req.session.user.id &&
            (
              o.status === 'approved' ||
              o.status === 'paid' ||
              o.status === 'completed' ||
              o.status === 'فعال'
            )
        )
        .map(o => ({

          id: o.id,

          planName:
            o.planName,

          gb:
            o.gb,

          days:
            o.days,

          subscriptionUrl:
            o.subscriptionUrl ||
            o.vpnLink ||
            '',

          status:
            o.status,

          createdAt:
            o.createdAt

        }));

    res.json({
      subscriptions
    });

  }
);


/* =========================================================
   ADMIN DASHBOARD
========================================================= */

app.get(
  '/api/admin/dashboard',
  requireAdmin,
  async (req, res) => {

    const db = await readDB();

    const income =
      db.orders.reduce(
        (sum, order) =>
          sum +
          Number(
            order.finalPrice ||
            order.price ||
            0
          ),
        0
      );

    res.json({

      usersCount:
        db.users.filter(
          u => u.role !== 'admin'
        ).length,

      ordersCount:
        db.orders.length,

      plansCount:
        db.plans.length,

      income

    });

  }
);


/* =========================================================
   ADMIN SUMMARY
========================================================= */

app.get(
  '/api/admin/summary',
  requireAdmin,
  async (req, res) => {

    const db = await readDB();

    res.json({

      users:
        db.users.length,

      orders:
        db.orders.length,

      coupons:
        db.coupons.length,

      plans:
        db.plans.length

    });

  }
);


/* =========================================================
   ADMIN USERS
========================================================= */

app.get(
  '/api/admin/users',
  requireAdmin,
  async (req, res) => {

    const db = await readDB();

    const users =
      db.users.map(
        u => ({

          id: u.id,

          username:
            u.username,

          role:
            u.role

        })
      );

    res.json({
      users
    });

  }
);


/* =========================================================
   ADMIN ORDERS
========================================================= */

app.get(
  '/api/admin/orders',
  requireAdmin,
  async (req, res) => {

    const db = await readDB();

    res.json(db.orders);

  }
);


/* =========================================================
   APPROVE / REJECT ORDER
========================================================= */

app.patch(
  '/api/admin/orders/:id',
  requireAdmin,
  async (req, res) => {

    const {
      status
    } = req.body || {};

    if (
      ![
        'approved',
        'rejected'
      ].includes(status)
    ) {

      return res.status(400).json({
        error: 'وضعیت سفارش نامعتبر است.'
      });
    }

    const db = await readDB();

    const order =
      db.orders.find(
        o =>
          String(o.id) ===
          String(req.params.id)
      );

    if (!order) {

      return res.status(404).json({
        error: 'سفارش پیدا نشد.'
      });
    }

    order.status = status;

    if (status === 'approved') {

      order.subscriptionUrl =
        order.subscriptionUrl ||
        order.vpnLink ||
        '';

    }

    await writeDB(db);

    res.json({
      success: true,
      order
    });

  }
);


/* =========================================================
   COUPONS
========================================================= */

app.get(
  '/api/admin/coupons',
  requireAdmin,
  async (req, res) => {

    const db = await readDB();

    res.json(db.coupons);

  }
);


app.post(
  '/api/admin/coupons',
  requireAdmin,
  async (req, res) => {

    const {
      code,
      percent
    } = req.body;

    if (!code || !percent) {

      return res.status(400).json({
        error: 'کد و درصد تخفیف را وارد کنید.'
      });
    }

    const db = await readDB();

    const newCoupon = {

      code:
        String(code).trim(),

      percent:
        Number(percent),

      active:
        true

    };

    db.coupons.push(newCoupon);

    await writeDB(db);

    res.json({
      success: true,
      coupon: newCoupon
    });

  }
);


app.delete(
  '/api/admin/coupons/:code',
  requireAdmin,
  async (req, res) => {

    const db = await readDB();

    db.coupons =
      db.coupons.filter(
        c =>
          c.code !==
          req.params.code
      );

    await writeDB(db);

    res.json({
      success: true
    });

  }
);


/* =========================================================
   SETTINGS
========================================================= */

app.get(
  '/api/admin/settings',
  requireAdmin,
  async (req, res) => {

    const db = await readDB();

    res.json(
      db.settings || {}
    );

  }
);


app.post(
  '/api/admin/settings',
  requireAdmin,
  async (req, res) => {

    const {
      vpnUrl,
      vpnToken,
      gatewayId,
      gatewayActive
    } = req.body;

    const db = await readDB();

    db.settings = {

      vpnUrl:
        vpnUrl || '',

      vpnToken:
        vpnToken || '',

      gatewayId:
        gatewayId || '',

      gatewayActive:
        Boolean(gatewayActive)

    };

    await writeDB(db);

    res.json({
      success: true
    });

  }
);


/* =========================================================
   BACKUP PLACEHOLDER
========================================================= */

app.post(
  '/api/admin/backup',
  requireAdmin,
  async (req, res) => {

    res.json({
      success: true,
      message:
        'سیستم بکاپ آماده اتصال به Cloudflare R2 است.'
    });

  }
);


app.get(
  '/api/admin/backups',
  requireAdmin,
  async (req, res) => {

    res.json({
      backups: []
    });

  }
);


app.post(
  '/api/admin/backup/restore',
  requireAdmin,
  async (req, res) => {

    res.status(501).json({
      error:
        'سیستم بازیابی هنوز به Cloudflare R2 متصل نشده است.'
    });

  }
);


/* =========================================================
   START SERVER
========================================================= */

ensureDB()
  .then(() => {

    app.listen(
      PORT,
      '0.0.0.0',
      () => {

        console.log(
          `Emad Net server running on port ${PORT}`
        );

        console.log(
          `Admin username: ${ADMIN_USER}`
        );

      }
    );

  })
  .catch(error => {

    console.error(
      'SERVER START ERROR:',
      error
    );

    process.exit(1);

  });
