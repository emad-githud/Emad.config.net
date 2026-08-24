const express = require("express");
const session = require("express-session");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "db.json");

const ADMIN_USER = String(process.env.ADMIN_USER || "admin").trim();
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || "admin");

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "emadnet-session-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false,
      httpOnly: true,
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(String(password))
    .digest("hex");
}

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
    const raw = await fs.promises.readFile(DB_FILE, "utf8");
    return JSON.parse(raw);
  } catch {
    return defaultDatabase();
  }
}

async function writeDB(db) {
  await fs.promises.mkdir(DATA_DIR, { recursive: true });
  await fs.promises.writeFile(
    DB_FILE,
    JSON.stringify(db, null, 2),
    "utf8"
  );
}

async function ensureDB() {
  await fs.promises.mkdir(DATA_DIR, { recursive: true });

  const db = await readDB();

  if (!Array.isArray(db.users)) db.users = [];
  if (!Array.isArray(db.plans)) db.plans = [];
  if (!Array.isArray(db.coupons)) db.coupons = [];
  if (!Array.isArray(db.orders)) db.orders = [];

  if (!db.settings) {
    db.settings = {
      vpnUrl: "",
      vpnToken: "",
      gatewayId: "",
      gatewayActive: false
    };
  }

  const adminHash = hashPassword(ADMIN_PASSWORD);

  let admin = db.users.find(
    u => u.role === "admin" && u.username === ADMIN_USER
  );

  if (!admin) {
    admin = {
      id: "admin",
      username: ADMIN_USER,
      password: adminHash,
      role: "admin"
    };

    db.users.push(admin);
  } else {
    admin.password = adminHash;
    admin.role = "admin";
  }

  await writeDB(db);

  console.log("=================================");
  console.log("Emad Net");
  console.log("ADMIN USER:", ADMIN_USER);
  console.log("ADMIN PASSWORD: configured");
  console.log("=================================");
}

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      error: "ابتدا وارد حساب شوید."
    });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (
    !req.session.user ||
    req.session.user.role !== "admin"
  ) {
    return res.status(403).json({
      error: "دسترسی غیرمجاز."
    });
  }

  next();
}

/* =========================
   USER SESSION
========================= */

app.get("/api/me", (req, res) => {
  if (!req.session.user) {
    return res.json({
      loggedIn: false
    });
  }

  res.json({
    loggedIn: true,
    user: req.session.user
  });
});

/* =========================
   USER LOGIN
========================= */

app.post("/api/login", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    if (!username || !password) {
      return res.status(400).json({
        error: "نام کاربری و رمز عبور را وارد کنید."
      });
    }

    const db = await readDB();

    const user = db.users.find(
      u =>
        u.username === username &&
        u.password === hashPassword(password)
    );

    if (!user) {
      return res.status(401).json({
        error: "نام کاربری یا رمز عبور اشتباه است."
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
      error: "خطای داخلی سرور."
    });
  }
});

/* =========================
   ADMIN LOGIN
========================= */

app.post("/api/admin/login", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    if (!username || !password) {
      return res.status(400).json({
        error: "نام کاربری و رمز عبور ادمین را وارد کنید."
      });
    }

    const db = await readDB();

    const admin = db.users.find(
      u =>
        u.role === "admin" &&
        u.username === username
    );

    if (
      !admin ||
      admin.password !== hashPassword(password)
    ) {
      return res.status(401).json({
        error: "نام کاربری یا رمز عبور ادمین اشتباه است."
      });
    }

    req.session.user = {
      id: admin.id,
      username: admin.username,
      role: "admin"
    };

    res.json({
      success: true,
      admin: true,
      user: req.session.user
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "خطای داخلی سرور."
    });
  }
});

/* =========================
   ADMIN SESSION
========================= */

app.get("/api/admin/me", (req, res) => {
  const isAdmin =
    !!req.session.user &&
    req.session.user.role === "admin";

  res.json({
    authenticated: isAdmin,
    admin: isAdmin,
    user: isAdmin ? req.session.user : null
  });
});

/* =========================
   REGISTER
========================= */

app.post("/api/register", async (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "");

  if (username.length < 3) {
    return res.status(400).json({
      error: "نام کاربری باید حداقل ۳ کاراکتر باشد."
    });
  }

  if (password.length < 6) {
    return res.status(400).json({
      error: "رمز عبور باید حداقل ۶ کاراکتر باشد."
    });
  }

  const db = await readDB();

  if (
    db.users.some(
      u => u.username.toLowerCase() === username.toLowerCase()
    )
  ) {
    return res.status(400).json({
      error: "این نام کاربری قبلاً ثبت شده است."
    });
  }

  const user = {
    id: Date.now().toString(),
    username,
    password: hashPassword(password),
    role: "user"
  };

  db.users.push(user);

  await writeDB(db);

  req.session.user = {
    id: user.id,
    username: user.username,
    role: "user"
  };

  res.json({
    success: true,
    user: req.session.user
  });
});

/* =========================
   LOGOUT
========================= */

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({
      success: true
    });
  });
});

app.post("/api/admin/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({
      success: true
    });
  });
});

/* =========================
   PLANS
========================= */

app.get("/api/plans", async (req, res) => {
  const db = await readDB();

  res.json(
    db.plans.filter(p => p.active !== false)
  );
});

app.get(
  "/api/admin/plans",
  requireAdmin,
  async (req, res) => {
    const db = await readDB();
    res.json(db.plans);
  }
);

app.post(
  "/api/admin/plans",
  requireAdmin,
  async (req, res) => {
    const name = String(req.body.name || "").trim();
    const price = Number(req.body.price);
    const gb = Number(req.body.gb);
    const days = Number(req.body.days);

    if (!name || price <= 0 || gb <= 0 || days <= 0) {
      return res.status(400).json({
        error: "اطلاعات پلن صحیح نیست."
      });
    }

    const db = await readDB();

    const plan = {
      id: Date.now(),
      name,
      price,
      gb,
      days,
      active: true
    };

    db.plans.push(plan);

    await writeDB(db);

    res.json({
      success: true,
      plan
    });
  }
);

app.delete(
  "/api/admin/plans/:id",
  requireAdmin,
  async (req, res) => {
    const db = await readDB();

    db.plans = db.plans.filter(
      p => Number(p.id) !== Number(req.params.id)
    );

    await writeDB(db);

    res.json({
      success: true
    });
  }
);

/* =========================
   ORDERS
========================= */

app.post("/api/orders", requireLogin, async (req, res) => {
  const planId = Number(req.body.planId);
  const coupon = String(req.body.coupon || "")
    .trim()
    .toUpperCase();

  const db = await readDB();

  const plan = db.plans.find(
    p => Number(p.id) === planId
  );

  if (!plan) {
    return res.status(404).json({
      error: "پلن پیدا نشد."
    });
  }

  let finalPrice = Number(plan.price);

  if (coupon) {
    const cp = db.coupons.find(
      c =>
        String(c.code).toUpperCase() === coupon &&
        c.active !== false
    );

    if (cp) {
      finalPrice =
        finalPrice -
        finalPrice * (Number(cp.percent) / 100);
    }
  }

  const token = crypto.randomUUID();

  const vpnLink = db.settings.vpnUrl
    ? `${String(db.settings.vpnUrl).replace(/\/$/, "")}/sub/${token}`
    : `vless://${token}@emadnet.server.com:443?type=ws#EmadNet-${encodeURIComponent(
        req.session.user.username
      )}`;

  const order = {
    id: Date.now().toString(),
    userId: req.session.user.id,
    username: req.session.user.username,
    planId: plan.id,
    planName: plan.name,
    gb: plan.gb,
    days: plan.days,
    finalPrice,
    vpnLink,
    subscriptionUrl: vpnLink,
    status: "pending",
    createdAt: new Date().toISOString()
  };

  db.orders.push(order);

  await writeDB(db);

  res.json({
    success: true,
    order
  });
});

app.get(
  "/api/my/orders",
  requireLogin,
  async (req, res) => {
    const db = await readDB();

    const orders = db.orders.filter(
      o => o.userId === req.session.user.id
    );

    res.json({
      orders
    });
  }
);

app.get(
  "/api/my/subscriptions",
  requireLogin,
  async (req, res) => {
    const db = await readDB();

    const subscriptions = db.orders
      .filter(
        o =>
          o.userId === req.session.user.id &&
          o.status === "approved"
      )
      .map(o => ({
        id: o.id,
        planName: o.planName,
        gb: o.gb,
        days: o.days,
        subscriptionUrl:
          o.subscriptionUrl || o.vpnLink,
        status: o.status,
        createdAt: o.createdAt
      }));

    res.json({
      subscriptions
    });
  }
);

app.get(
  "/api/dashboard",
  requireLogin,
  async (req, res) => {
    const db = await readDB();

    res.json({
      orders: db.orders.filter(
        o => o.userId === req.session.user.id
      )
    });
  }
);

/* =========================
   ADMIN DASHBOARD
========================= */

app.get(
  "/api/admin/dashboard",
  requireAdmin,
  async (req, res) => {
    const db = await readDB();

    const income = db.orders
      .filter(o => o.status === "approved")
      .reduce(
        (sum, o) => sum + Number(o.finalPrice || 0),
        0
      );

    res.json({
      usersCount: db.users.filter(
        u => u.role !== "admin"
      ).length,

      ordersCount: db.orders.length,

      plansCount: db.plans.length,

      income
    });
  }
);

app.get(
  "/api/admin/summary",
  requireAdmin,
  async (req, res) => {
    const db = await readDB();

    res.json({
      users: db.users.length,
      orders: db.orders.length,
      coupons: db.coupons.length,
      plans: db.plans.length
    });
  }
);

/* =========================
   ADMIN USERS
========================= */

app.get(
  "/api/admin/users",
  requireAdmin,
  async (req, res) => {
    const db = await readDB();

    res.json({
      users: db.users
        .filter(u => u.role !== "admin")
        .map(u => ({
          id: u.id,
          username: u.username,
          role: u.role
        }))
    });
  }
);

/* =========================
   ADMIN ORDERS
========================= */

app.get(
  "/api/admin/orders",
  requireAdmin,
  async (req, res) => {
    const db = await readDB();

    res.json({
      orders: db.orders
    });
  }
);

app.patch(
  "/api/admin/orders/:id",
  requireAdmin,
  async (req, res) => {
    const status = String(req.body.status || "");

    const allowed = [
      "pending",
      "approved",
      "rejected",
      "cancelled"
    ];

    if (!allowed.includes(status)) {
      return res.status(400).json({
        error: "وضعیت سفارش نامعتبر است."
      });
    }

    const db = await readDB();

    const order = db.orders.find(
      o => String(o.id) === String(req.params.id)
    );

    if (!order) {
      return res.status(404).json({
        error: "سفارش پیدا نشد."
      });
    }

    order.status = status;

    await writeDB(db);

    res.json({
      success: true,
      order
    });
  }
);

/* =========================
   COUPONS
========================= */

app.get(
  "/api/admin/coupons",
  requireAdmin,
  async (req, res) => {
    const db = await readDB();
    res.json({
      coupons: db.coupons
    });
  }
);

app.post(
  "/api/admin/coupons",
  requireAdmin,
  async (req, res) => {
    const code = String(req.body.code || "")
      .trim()
      .toUpperCase();

    const percent = Number(req.body.percent);

    if (!code || percent <= 0 || percent > 100) {
      return res.status(400).json({
        error: "کد یا درصد تخفیف صحیح نیست."
      });
    }

    const db = await readDB();

    if (
      db.coupons.some(
        c => String(c.code).toUpperCase() === code
      )
    ) {
      return res.status(400).json({
        error: "این کد تخفیف وجود دارد."
      });
    }

    const coupon = {
      code,
      percent,
      active: true
    };

    db.coupons.push(coupon);

    await writeDB(db);

    res.json({
      success: true,
      coupon
    });
  }
);

app.delete(
  "/api/admin/coupons/:code",
  requireAdmin,
  async (req, res) => {
    const db = await readDB();

    db.coupons = db.coupons.filter(
      c =>
        String(c.code).toUpperCase() !==
        String(req.params.code).toUpperCase()
    );

    await writeDB(db);

    res.json({
      success: true
    });
  }
);

/* =========================
   SETTINGS
========================= */

app.get(
  "/api/admin/settings",
  requireAdmin,
  async (req, res) => {
    const db = await readDB();
    res.json(db.settings || {});
  }
);

app.post(
  "/api/admin/settings",
  requireAdmin,
  async (req, res) => {
    const db = await readDB();

    db.settings = {
      vpnUrl: String(req.body.vpnUrl || ""),
      vpnToken: String(req.body.vpnToken || ""),
      gatewayId: String(req.body.gatewayId || ""),
      gatewayActive: Boolean(req.body.gatewayActive)
    };

    await writeDB(db);

    res.json({
      success: true
    });
  }
);

/* =========================
   BACKUP
========================= */

app.post(
  "/api/admin/backup",
  requireAdmin,
  async (req, res) => {
    try {
      const db = await readDB();

      const backupDir = path.join(
        DATA_DIR,
        "backups"
      );

      await fs.promises.mkdir(
        backupDir,
        { recursive: true }
      );

      const name =
        `backup-${new Date()
          .toISOString()
          .replace(/[:.]/g, "-")}.json`;

      await fs.promises.writeFile(
        path.join(backupDir, name),
        JSON.stringify(db, null, 2),
        "utf8"
      );

      res.json({
        success: true,
        message: "بکاپ با موفقیت ساخته شد.",
        name
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "ساخت بکاپ ناموفق بود."
      });
    }
  }
);

app.get(
  "/api/admin/backups",
  requireAdmin,
  async (req, res) => {
    const backupDir = path.join(
      DATA_DIR,
      "backups"
    );

    try {
      const files = await fs.promises.readdir(
        backupDir
      );

      res.json({
        backups: files.map(name => ({
          name
        }))
      });
    } catch {
      res.json({
        backups: []
      });
    }
  }
);

app.post(
  "/api/admin/backup/restore",
  requireAdmin,
  async (req, res) => {
    return res.status(400).json({
      error:
        "برای جلوگیری از جایگزینی اشتباه اطلاعات، نام بکاپ باید مشخص شود."
    });
  }
);

/* =========================
   404 API
========================= */

app.use("/api", (req, res) => {
  res.status(404).json({
    error: "API پیدا نشد."
  });
});

/* =========================
   START
========================= */

ensureDB()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(
        `Emad Net server running on port ${PORT}`
      );
    });
  })
  .catch(error => {
    console.error(
      "Server startup failed:",
      error
    );
    process.exit(1);
  });
