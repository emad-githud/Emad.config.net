const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const cors = require("cors");

const app = express();

const PORT = Number(process.env.PORT) || 3000;
const PROD = process.env.NODE_ENV === "production";

/* =====================================================
   MIDDLEWARE
===================================================== */

app.set("trust proxy", 1);
app.disable("x-powered-by");

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

/* =====================================================
   SESSION
===================================================== */

app.use(
  session({
    name: "emadnet.sid",

    secret:
      process.env.SESSION_SECRET ||
      "CHANGE_ME",

    resave: false,

    saveUninitialized: false,

    proxy: PROD,

    cookie: {
      httpOnly: true,

      secure: PROD,

      sameSite: PROD
        ? "none"
        : "lax",

      maxAge: 7 * 24 * 60 * 60 * 1000,
    },
  })
);

/* =====================================================
   DATABASE
===================================================== */

const dbPath =
  process.env.DB_PATH ||
  path.join(__dirname, "database.db");

const db =
  new sqlite3.Database(
    dbPath,
    (err) => {
      if (err) {
        console.error(
          "خطا در اتصال به دیتابیس:",
          err.message
        );
      } else {
        console.log(
          "SQLite database connected."
        );
      }
    }
  );

/* =====================================================
   SQLITE HELPERS
===================================================== */

const run = (query, params = []) =>
  new Promise((resolve, reject) => {
    db.run(
      query,
      params,
      function (err) {
        if (err) {
          reject(err);
        } else {
          resolve(this);
        }
      }
    );
  });

const get = (query, params = []) =>
  new Promise((resolve, reject) => {
    db.get(
      query,
      params,
      (err, row) => {
        if (err) {
          reject(err);
        } else {
          resolve(row);
        }
      }
    );
  });

const all = (query, params = []) =>
  new Promise((resolve, reject) => {
    db.all(
      query,
      params,
      (err, rows) => {
        if (err) {
          reject(err);
        } else {
          resolve(rows);
        }
      }
    );
  });

/* =====================================================
   DATABASE INIT
===================================================== */

async function initDatabase() {
  await run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS plans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      gb INTEGER NOT NULL,
      days INTEGER NOT NULL,
      price INTEGER NOT NULL,
      active INTEGER DEFAULT 1
    )
  `);

  await run(`
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      plan_id INTEGER NOT NULL,
      plan_name TEXT NOT NULL,
      final_price INTEGER NOT NULL,
      status TEXT DEFAULT 'pending',
      subscription_url TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  /*
    اگر دیتابیس قدیمی باشد و ستون active
    را نداشته باشد، آن را اضافه می‌کنیم.
  */

  try {
    await run(
      "ALTER TABLE plans ADD COLUMN active INTEGER DEFAULT 1"
    );
  } catch (error) {
    // ستون احتمالاً از قبل وجود دارد.
  }

  const count =
    await get(
      "SELECT COUNT(*) AS count FROM plans"
    );

  if (
    count &&
    Number(count.count) === 0
  ) {
    await run(
      `
      INSERT INTO plans
      (name, gb, days, price, active)
      VALUES (?, ?, ?, ?, 1)
      `,
      [
        "پلن اقتصادی ۱۰ گیگ",
        10,
        30,
        50000,
      ]
    );

    await run(
      `
      INSERT INTO plans
      (name, gb, days, price, active)
      VALUES (?, ?, ?, ?, 1)
      `,
      [
        "پلن استاندارد ۳۰ گیگ",
        30,
        30,
        120000,
      ]
    );

    await run(
      `
      INSERT INTO plans
      (name, gb, days, price, active)
      VALUES (?, ?, ?, ?, 1)
      `,
      [
        "پلن حرفه‌ای ۵۰ گیگ",
        50,
        60,
        200000,
      ]
    );

    console.log(
      "پلن‌های اولیه ایجاد شدند."
    );
  }
}

/* =====================================================
   AUTH
===================================================== */

function requireAuth(
  req,
  res,
  next
) {
  if (!req.session.userId) {
    return res.status(401).json({
      error:
        "برای این بخش ابتدا وارد حساب شوید.",
    });
  }

  next();
}

/* =====================================================
   REGISTER
===================================================== */

app.post(
  "/api/register",
  async (req, res) => {
    const username =
      String(
        req.body.username || ""
      ).trim();

    const password =
      String(
        req.body.password || ""
      );

    if (username.length < 3) {
      return res.status(400).json({
        error:
          "نام کاربری حداقل ۳ کاراکتر باشد.",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error:
          "رمز عبور حداقل ۶ کاراکتر باشد.",
      });
    }

    try {
      const existing =
        await get(
          `
          SELECT id
          FROM users
          WHERE lower(username) = lower(?)
          `,
          [username]
        );

      if (existing) {
        return res.status(409).json({
          error:
            "این نام کاربری قبلاً ثبت شده است.",
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const result =
        await run(
          `
          INSERT INTO users
          (username, password)
          VALUES (?, ?)
          `,
          [
            username,
            passwordHash,
          ]
        );

      req.session.regenerate(
        (err) => {
          if (err) {
            console.error(err);

            return res
              .status(500)
              .json({
                error:
                  "خطا در ایجاد نشست کاربری.",
              });
          }

          req.session.userId =
            result.lastID;

          req.session.username =
            username;

          res.json({
            success: true,

            user: {
              id: result.lastID,
              username,
            },
          });
        }
      );
    } catch (error) {
      console.error(
        "Register error:",
        error
      );

      res.status(500).json({
        error:
          "خطای داخلی سرور.",
      });
    }
  }
);

/* =====================================================
   LOGIN
===================================================== */

app.post(
  "/api/login",
  async (req, res) => {
    const username =
      String(
        req.body.username || ""
      ).trim();

    const password =
      String(
        req.body.password || ""
      );

    if (
      !username ||
      !password
    ) {
      return res.status(400).json({
        error:
          "نام کاربری و رمز عبور را وارد کنید.",
      });
    }

    try {
      const user =
        await get(
          `
          SELECT *
          FROM users
          WHERE lower(username) = lower(?)
          `,
          [username]
        );

      if (!user) {
        return res.status(401).json({
          error:
            "نام کاربری یا رمز عبور اشتباه است.",
        });
      }

      const valid =
        await bcrypt.compare(
          password,
          user.password
        );

      if (!valid) {
        return res.status(401).json({
          error:
            "نام کاربری یا رمز عبور اشتباه است.",
        });
      }

      req.session.regenerate(
        (err) => {
          if (err) {
            console.error(err);

            return res
              .status(500)
              .json({
                error:
                  "خطا در ورود.",
              });
          }

          req.session.userId =
            user.id;

          req.session.username =
            user.username;

          res.json({
            success: true,

            user: {
              id: user.id,
              username: user.username,
            },
          });
        }
      );
    } catch (error) {
      console.error(
        "Login error:",
        error
      );

      res.status(500).json({
        error:
          "خطای داخلی سرور.",
      });
    }
  }
);

/* =====================================================
   CURRENT USER
===================================================== */

app.get(
  "/api/me",
  (req, res) => {
    if (
      req.session.userId
    ) {
      return res.json({
        loggedIn: true,

        user: {
          id:
            req.session.userId,

          username:
            req.session.username,
        },
      });
    }

    res.json({
      loggedIn: false,
    });
  }
);

/* =====================================================
   LOGOUT
===================================================== */

app.post(
  "/api/logout",
  (req, res) => {
    req.session.destroy(
      (err) => {
        if (err) {
          return res
            .status(500)
            .json({
              error:
                "خطا در خروج.",
            });
        }

        res.clearCookie(
          "emadnet.sid"
        );

        res.json({
          success: true,
        });
      }
    );
  }
);

/* =====================================================
   SUPPORT
===================================================== */

app.get(
  "/api/support",
  (req, res) => {
    res.json({
      telegramUrl:
        process.env
          .SUPPORT_TELEGRAM_URL ||
        "https://t.me/",
    });
  }
);

/* =====================================================
   PRODUCTS
   مهم:
   مهمان به این API دسترسی ندارد.
===================================================== */

app.get(
  "/api/plans",
  requireAuth,
  async (req, res) => {
    try {
      const plans =
        await all(
          `
          SELECT
            id,
            name,
            gb,
            days,
            price
          FROM plans
          WHERE active = 1
          ORDER BY id
          `
        );

      res.json(plans);
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "خطا در دریافت محصولات.",
      });
    }
  }
);

/* =====================================================
   CREATE ORDER
===================================================== */

app.post(
  "/api/orders",
  requireAuth,
  async (req, res) => {
    const planId =
      Number(req.body.planId);

    if (
      !Number.isInteger(
        planId
      )
    ) {
      return res.status(400).json({
        error:
          "محصول نامعتبر است.",
      });
    }

    try {
      const plan =
        await get(
          `
          SELECT *
          FROM plans
          WHERE id = ?
          AND active = 1
          `,
          [planId]
        );

      if (!plan) {
        return res.status(404).json({
          error:
            "محصول پیدا نشد.",
        });
      }

      const result =
        await run(
          `
          INSERT INTO orders
          (
            user_id,
            plan_id,
            plan_name,
            final_price,
            status
          )
          VALUES
          (?, ?, ?, ?, 'pending')
          `,
          [
            req.session.userId,
            plan.id,
            plan.name,
            plan.price,
          ]
        );

      res.json({
        success: true,

        order: {
          id:
            result.lastID,

          planName:
            plan.name,

          finalPrice:
            plan.price,

          status:
            "pending",
        },
      });
    } catch (error) {
      console.error(
        "Order error:",
        error
      );

      res.status(500).json({
        error:
          "خطا در ثبت سفارش.",
      });
    }
  }
);

/* =====================================================
   MY ORDERS
===================================================== */

app.get(
  "/api/my/orders",
  requireAuth,
  async (req, res) => {
    try {
      const orders =
        await all(
          `
          SELECT
            id,
            plan_name AS planName,
            final_price AS finalPrice,
            status,
            subscription_url AS subscriptionUrl,
            created_at AS createdAt
          FROM orders
          WHERE user_id = ?
          ORDER BY id DESC
          `,
          [
            req.session.userId,
          ]
        );

      res.json({
        orders,
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "خطا در دریافت سفارش‌ها.",
      });
    }
  }
);

/* =====================================================
   MY SUBSCRIPTIONS
===================================================== */

app.get(
  "/api/my/subscriptions",
  requireAuth,
  async (req, res) => {
    try {
      const subscriptions =
        await all(
          `
          SELECT
            o.id,
            o.plan_name AS planName,
            o.subscription_url AS subscriptionUrl,
            p.gb,
            p.days,
            o.created_at AS createdAt
          FROM orders o

          LEFT JOIN plans p
            ON p.id = o.plan_id

          WHERE
            o.user_id = ?
            AND o.status = 'approved'

          ORDER BY o.id DESC
          `,
          [
            req.session.userId,
          ]
        );

      res.json({
        subscriptions,
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        error:
          "خطا در دریافت اشتراک‌ها.",
      });
    }
  }
);

/* =====================================================
   FORGOT PASSWORD
===================================================== */

app.post(
  "/api/forgot-password",
  (req, res) => {
    res.json({
      success: true,

      message:
        "درخواست ثبت شد. برای بازیابی با پشتیبانی تماس بگیرید.",
    });
  }
);

/* =====================================================
   STATIC FRONTEND
===================================================== */

app.use(
  express.static(
    path.join(
      __dirname,
      "public"
    )
  )
);

/* =====================================================
   SPA FALLBACK
===================================================== */

app.get(
  /.*/,
  (req, res) => {
    if (
      req.path.startsWith(
        "/api/"
      )
    ) {
      return res
        .status(404)
        .json({
          error:
            "API endpoint not found.",
        });
    }

    res.sendFile(
      path.join(
        __dirname,
        "public",
        "index.html"
      )
    );
  }
);

/* =====================================================
   START
===================================================== */

initDatabase()
  .then(() => {
    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `Emad Net running on port ${PORT}`
        );
      }
    );
  })
  .catch((error) => {
    console.error(
      "Database initialization failed:",
      error
    );

    process.exit(1);
  });
