const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin123";

const SUBSCRIPTION_BASE_URL =
  process.env.SUBSCRIPTION_BASE_URL || "https://example.com/sub";

const db = new Database("emadnet.db");

app.use(express.json());

app.use(
  session({
    secret:
      process.env.SESSION_SECRET ||
      "emad-net-change-this-secret-please",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 30
    }
  })
);

app.use(express.static(path.join(__dirname, "public")));

/* =========================================================
   DATABASE
========================================================= */

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS plans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  gb INTEGER NOT NULL,
  days INTEGER NOT NULL,
  price INTEGER NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS coupons (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT UNIQUE NOT NULL,
  percent INTEGER NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
  id TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  plan_id INTEGER NOT NULL,
  coupon_code TEXT,
  original_price INTEGER NOT NULL,
  final_price INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  subscription_url TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id),
  FOREIGN KEY(plan_id) REFERENCES plans(id)
);
`);


/* =========================================================
   HELPERS
========================================================= */

function requireUser(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      error: "ابتدا وارد حساب کاربری شوید."
    });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.admin) {
    return res.status(403).json({
      error: "دسترسی ادمین ندارید."
    });
  }

  next();
}

function generateOrderId() {
  return (
    Date.now().toString(36) +
    "-" +
    Math.random().toString(36).slice(2, 10)
  );
}

function generateSubscriptionUrl(orderId) {
  return `${SUBSCRIPTION_BASE_URL}/${encodeURIComponent(orderId)}`;
}


/* =========================================================
   USER REGISTER
========================================================= */

app.post("/api/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    if (!username || !password) {
      return res.status(400).json({
        error: "نام کاربری و رمز عبور را وارد کنید."
      });
    }

    if (username.length < 3) {
      return res.status(400).json({
        error: "نام کاربری حداقل ۳ کاراکتر باشد."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "رمز عبور حداقل ۶ کاراکتر باشد."
      });
    }

    const exists = db
      .prepare("SELECT id FROM users WHERE username = ?")
      .get(username);

    if (exists) {
      return res.status(409).json({
        error: "این نام کاربری قبلاً ثبت شده است."
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = db
      .prepare(
        "INSERT INTO users (username, password) VALUES (?, ?)"
      )
      .run(username, hash);

    req.session.userId = result.lastInsertRowid;
    req.session.admin = false;

    res.json({
      success: true,
      user: {
        id: result.lastInsertRowid,
        username
      }
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "خطا در ثبت‌نام."
    });
  }
});


/* =========================================================
   USER LOGIN
========================================================= */

app.post("/api/login", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    const user = db
      .prepare("SELECT * FROM users WHERE username = ?")
      .get(username);

    if (!user) {
      return res.status(401).json({
        error: "نام کاربری یا رمز عبور اشتباه است."
      });
    }

    const valid = await bcrypt.compare(
      password,
      user.password
    );

    if (!valid) {
      return res.status(401).json({
        error: "نام کاربری یا رمز عبور اشتباه است."
      });
    }

    req.session.userId = user.id;
    req.session.admin = false;

    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username
      }
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "خطا در ورود."
    });
  }
});


/* =========================================================
   USER SESSION
========================================================= */

app.get("/api/me", (req, res) => {
  if (!req.session.userId) {
    return res.json({
      loggedIn: false
    });
  }

  const user = db
    .prepare(
      "SELECT id, username, created_at FROM users WHERE id = ?"
    )
    .get(req.session.userId);

  if (!user) {
    req.session.destroy(() => {});

    return res.json({
      loggedIn: false
    });
  }

  res.json({
    loggedIn: true,
    user
  });
});


/* =========================================================
   USER LOGOUT
========================================================= */

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({
      success: true
    });
  });
});


/* =========================================================
   PUBLIC PLANS
========================================================= */

app.get("/api/plans", (req, res) => {
  try {
    const plans = db
      .prepare(
        `
        SELECT id, name, gb, days, price
        FROM plans
        ORDER BY id DESC
        `
      )
      .all();

    res.json(plans);
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "خطا در دریافت پلن‌ها."
    });
  }
});


/* =========================================================
   CREATE ORDER
========================================================= */

app.post("/api/orders", requireUser, (req, res) => {
  try {
    const planId = Number(req.body.planId);
    const couponCode = String(req.body.coupon || "")
      .trim()
      .toUpperCase();

    if (!planId) {
      return res.status(400).json({
        error: "پلن انتخاب نشده است."
      });
    }

    const plan = db
      .prepare("SELECT * FROM plans WHERE id = ?")
      .get(planId);

    if (!plan) {
      return res.status(404).json({
        error: "پلن پیدا نشد."
      });
    }

    let finalPrice = Number(plan.price);
    let appliedCoupon = null;

    if (couponCode) {
      const coupon = db
        .prepare(
          "SELECT * FROM coupons WHERE code = ?"
        )
        .get(couponCode);

      if (!coupon) {
        return res.status(400).json({
          error: "کد تخفیف معتبر نیست."
        });
      }

      const percent = Math.min(
        100,
        Math.max(0, Number(coupon.percent))
      );

      finalPrice = Math.round(
        finalPrice - (finalPrice * percent) / 100
      );

      appliedCoupon = coupon.code;
    }

    const orderId = generateOrderId();

    db.prepare(
      `
      INSERT INTO orders
      (
        id,
        user_id,
        plan_id,
        coupon_code,
        original_price,
        final_price,
        status
      )
      VALUES (?, ?, ?, ?, ?, ?, 'pending')
      `
    ).run(
      orderId,
      req.session.userId,
      plan.id,
      appliedCoupon,
      plan.price,
      finalPrice
    );

    res.json({
      success: true,
      order: {
        id: orderId,
        planId: plan.id,
        planName: plan.name,
        originalPrice: plan.price,
        finalPrice,
        status: "pending"
      }
    });
  } catch (err) {
    console.error(err);

    res.status(500).json({
      error: "خطا در ثبت سفارش."
    });
  }
});


/* =========================================================
   USER SUBSCRIPTIONS
========================================================= */

app.get(
  "/api/my/subscriptions",
  requireUser,
  (req, res) => {
    try {
      const subscriptions = db
        .prepare(
          `
          SELECT
            o.id,
            p.name AS planName,
            p.gb,
            p.days,
            o.subscription_url AS subscriptionUrl,
            o.created_at
          FROM orders o
          JOIN plans p ON p.id = o.plan_id
          WHERE
            o.user_id = ?
            AND o.status = 'approved'
            AND o.subscription_url IS NOT NULL
          ORDER BY o.created_at DESC
          `
        )
        .all(req.session.userId);

      res.json({
        subscriptions
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "خطا در دریافت اشتراک‌ها."
      });
    }
  }
);


/* =========================================================
   USER ORDERS
========================================================= */

app.get(
  "/api/my/orders",
  requireUser,
  (req, res) => {
    try {
      const orders = db
        .prepare(
          `
          SELECT
            o.id,
            p.name AS planName,
            o.final_price AS finalPrice,
            o.status,
            o.subscription_url AS subscriptionUrl,
            o.created_at
          FROM orders o
          JOIN plans p ON p.id = o.plan_id
          WHERE o.user_id = ?
          ORDER BY o.created_at DESC
          `
        )
        .all(req.session.userId);

      res.json({
        orders
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "خطا در دریافت سفارش‌ها."
      });
    }
  }
);


/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post("/api/admin/login", (req, res) => {
  const username = String(
    req.body.username || ""
  ).trim();

  const password = String(
    req.body.password || ""
  );

  if (
    username !== ADMIN_USERNAME ||
    password !== ADMIN_PASSWORD
  ) {
    return res.status(401).json({
      error: "نام کاربری یا رمز عبور ادمین اشتباه است."
    });
  }

  req.session.admin = true;
  req.session.userId = null;

  res.json({
    success: true,
    admin: true
  });
});


/* =========================================================
   ADMIN SESSION
========================================================= */

app.get("/api/admin/me", (req, res) => {
  res.json({
    authenticated: req.session.admin === true
  });
});


/* =========================================================
   ADMIN LOGOUT
========================================================= */

app.post("/api/admin/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({
      success: true
    });
  });
});


/* =========================================================
   ADMIN DASHBOARD
========================================================= */

app.get(
  "/api/admin/dashboard",
  requireAdmin,
  (req, res) => {
    try {
      const usersCount = db
        .prepare("SELECT COUNT(*) AS count FROM users")
        .get().count;

      const ordersCount = db
        .prepare("SELECT COUNT(*) AS count FROM orders")
        .get().count;

      const plansCount = db
        .prepare("SELECT COUNT(*) AS count FROM plans")
        .get().count;

      const income = db
        .prepare(
          `
          SELECT COALESCE(SUM(final_price), 0) AS total
          FROM orders
          WHERE status = 'approved'
          `
        )
        .get().total;

      res.json({
        usersCount,
        ordersCount,
        plansCount,
        income
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "خطا در دریافت داشبورد."
      });
    }
  }
);


/* =========================================================
   ADMIN PLANS
========================================================= */

app.get(
  "/api/admin/plans",
  requireAdmin,
  (req, res) => {
    const plans = db
      .prepare(
        `
        SELECT id, name, gb, days, price
        FROM plans
        ORDER BY id DESC
        `
      )
      .all();

    res.json({
      plans
    });
  }
);


app.post(
  "/api/admin/plans",
  requireAdmin,
  (req, res) => {
    try {
      const name = String(
        req.body.name || ""
      ).trim();

      const gb = Number(req.body.gb);
      const days = Number(req.body.days);
      const price = Number(req.body.price);

      if (
        !name ||
        !Number.isFinite(gb) ||
        gb <= 0 ||
        !Number.isFinite(days) ||
        days <= 0 ||
        !Number.isFinite(price) ||
        price <= 0
      ) {
        return res.status(400).json({
          error: "اطلاعات پلن صحیح نیست."
        });
      }

      const result = db
        .prepare(
          `
          INSERT INTO plans
          (name, gb, days, price)
          VALUES (?, ?, ?, ?)
          `
        )
        .run(
          name,
          Math.floor(gb),
          Math.floor(days),
          Math.floor(price)
        );

      res.json({
        success: true,
        id: result.lastInsertRowid
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "خطا در ساخت پلن."
      });
    }
  }
);


app.delete(
  "/api/admin/plans/:id",
  requireAdmin,
  (req, res) => {
    try {
      const id = Number(req.params.id);

      const result = db
        .prepare("DELETE FROM plans WHERE id = ?")
        .run(id);

      if (!result.changes) {
        return res.status(404).json({
          error: "پلن پیدا نشد."
        });
      }

      res.json({
        success: true
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "خطا در حذف پلن."
      });
    }
  }
);


/* =========================================================
   ADMIN USERS
========================================================= */

app.get(
  "/api/admin/users",
  requireAdmin,
  (req, res) => {
    try {
      const users = db
        .prepare(
          `
          SELECT id, username, created_at
          FROM users
          ORDER BY id DESC
          `
        )
        .all();

      res.json({
        users
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "خطا در دریافت کاربران."
      });
    }
  }
);


/* =========================================================
   ADMIN ORDERS
========================================================= */

app.get(
  "/api/admin/orders",
  requireAdmin,
  (req, res) => {
    try {
      const orders = db
        .prepare(
          `
          SELECT
            o.id,
            u.username,
            p.name AS planName,
            o.final_price AS finalPrice,
            o.status,
            o.subscription_url AS subscriptionUrl,
            o.created_at
          FROM orders o
          JOIN users u ON u.id = o.user_id
          JOIN plans p ON p.id = o.plan_id
          ORDER BY o.created_at DESC
          `
        )
        .all();

      res.json({
        orders
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "خطا در دریافت سفارش‌ها."
      });
    }
  }
);


/* =========================================================
   APPROVE / REJECT ORDER
========================================================= */

app.patch(
  "/api/admin/orders/:id",
  requireAdmin,
  (req, res) => {
    try {
      const orderId = req.params.id;
      const status = String(req.body.status || "");

      if (
        status !== "approved" &&
        status !== "rejected"
      ) {
        return res.status(400).json({
          error: "وضعیت سفارش نامعتبر است."
        });
      }

      const order = db
        .prepare(
          `
          SELECT *
          FROM orders
          WHERE id = ?
          `
        )
        .get(orderId);

      if (!order) {
        return res.status(404).json({
          error: "سفارش پیدا نشد."
        });
      }

      if (status === "approved") {
        const subscriptionUrl =
          generateSubscriptionUrl(order.id);

        db.prepare(
          `
          UPDATE orders
          SET
            status = 'approved',
            subscription_url = ?
          WHERE id = ?
          `
        ).run(subscriptionUrl, orderId);
      } else {
        db.prepare(
          `
          UPDATE orders
          SET
            status = 'rejected',
            subscription_url = NULL
          WHERE id = ?
          `
        ).run(orderId);
      }

      res.json({
        success: true,
        status
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "خطا در تغییر وضعیت سفارش."
      });
    }
  }
);


/* =========================================================
   ADMIN COUPONS
========================================================= */

app.get(
  "/api/admin/coupons",
  requireAdmin,
  (req, res) => {
    try {
      const coupons = db
        .prepare(
          `
          SELECT id, code, percent, created_at
          FROM coupons
          ORDER BY id DESC
          `
        )
        .all();

      res.json({
        coupons
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "خطا در دریافت کدهای تخفیف."
      });
    }
  }
);


app.post(
  "/api/admin/coupons",
  requireAdmin,
  (req, res) => {
    try {
      const code = String(
        req.body.code || ""
      )
        .trim()
        .toUpperCase();

      const percent = Number(req.body.percent);

      if (!code) {
        return res.status(400).json({
          error: "کد تخفیف را وارد کنید."
        });
      }

      if (
        !Number.isFinite(percent) ||
        percent <= 0 ||
        percent > 100
      ) {
        return res.status(400).json({
          error: "درصد تخفیف باید بین ۱ تا ۱۰۰ باشد."
        });
      }

      const exists = db
        .prepare(
          "SELECT id FROM coupons WHERE code = ?"
        )
        .get(code);

      if (exists) {
        return res.status(409).json({
          error: "این کد تخفیف قبلاً ساخته شده است."
        });
      }

      const result = db
        .prepare(
          `
          INSERT INTO coupons
          (code, percent)
          VALUES (?, ?)
          `
        )
        .run(code, Math.floor(percent));

      res.json({
        success: true,
        id: result.lastInsertRowid
      });
    } catch (err) {
      console.error(err);

      res.status(500).json({
        error: "خطا در ساخت کد تخفیف."
      });
    }
  }
);


/* =========================================================
   FALLBACK
========================================================= */

app.get("*", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});


/* =========================================================
   START
========================================================= */

app.listen(PORT, "0.0.0.0", () => {
  console.log("=================================");
  console.log("Emad Net Server Started");
  console.log(`Port: ${PORT}`);
  console.log("=================================");
});
