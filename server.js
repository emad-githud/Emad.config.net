const express = require("express");
const path = require("path");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;

const ADMIN_USERNAME =
  process.env.ADMIN_USERNAME || "admin";

const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD || "change-this-password";

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  crypto.randomBytes(32).toString("hex");

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

/* =====================================================
   DATABASE
===================================================== */

let users = [];
let plans = [];
let orders = [];
let coupons = [];
let subscriptions = [];


/* =====================================================
   SIMPLE ID
===================================================== */

function id() {
  return crypto.randomUUID();
}


/* =====================================================
   PASSWORD HASH
===================================================== */

function hashPassword(password) {

  return crypto
    .createHash("sha256")
    .update(password + SESSION_SECRET)
    .digest("hex");

}


/* =====================================================
   SESSION
===================================================== */

const sessions = new Map();


function createSession(type, userId) {

  const token = crypto.randomBytes(32).toString("hex");

  sessions.set(token, {
    type,
    userId,
    createdAt: Date.now()
  });

  return token;
}


function getSession(req) {

  const cookie = req.headers.cookie || "";

  const match = cookie
    .split(";")
    .map(x => x.trim())
    .find(x => x.startsWith("session="));

  if (!match) return null;

  const token = match.substring("session=".length);

  return sessions.get(token) || null;

}


function setSession(res, token) {

  res.setHeader(
    "Set-Cookie",
    `session=${token}; Path=/; HttpOnly; SameSite=Lax`
  );

}


function clearSession(res) {

  res.setHeader(
    "Set-Cookie",
    "session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
  );

}


/* =====================================================
   AUTH MIDDLEWARE
===================================================== */

function requireUser(req, res, next) {

  const session = getSession(req);

  if (
    !session ||
    session.type !== "user"
  ) {

    return res.status(401).json({
      error: "ابتدا وارد حساب کاربری شوید."
    });

  }

  req.userId = session.userId;

  next();

}


function requireAdmin(req, res, next) {

  const session = getSession(req);

  if (
    !session ||
    session.type !== "admin"
  ) {

    return res.status(401).json({
      error: "دسترسی مدیریت نیازمند ورود ادمین است."
    });

  }

  next();

}


/* =====================================================
   PUBLIC PLANS
===================================================== */

app.get("/api/plans", (req, res) => {

  res.json(
    plans.filter(p => p.active !== false)
  );

});


/* =====================================================
   REGISTER
===================================================== */

app.post("/api/register", (req, res) => {

  const username =
    String(req.body.username || "")
      .trim();

  const password =
    String(req.body.password || "");


  if (!username || !password) {

    return res.status(400).json({
      error: "نام کاربری و رمز عبور الزامی است."
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


  const exists =
    users.some(
      u =>
        u.username.toLowerCase() ===
        username.toLowerCase()
    );


  if (exists) {

    return res.status(409).json({
      error: "این نام کاربری قبلاً ثبت شده است."
    });

  }


  const user = {

    id: id(),

    username,

    passwordHash:
      hashPassword(password),

    createdAt:
      new Date().toISOString()

  };


  users.push(user);


  const token =
    createSession("user", user.id);


  setSession(res, token);


  res.json({

    user: {
      id: user.id,
      username: user.username
    }

  });

});


/* =====================================================
   LOGIN
===================================================== */

app.post("/api/login", (req, res) => {

  const username =
    String(req.body.username || "")
      .trim();

  const password =
    String(req.body.password || "");


  const user =
    users.find(
      u =>
        u.username.toLowerCase() ===
        username.toLowerCase()
    );


  if (
    !user ||
    user.passwordHash !==
    hashPassword(password)
  ) {

    return res.status(401).json({
      error: "نام کاربری یا رمز عبور اشتباه است."
    });

  }


  const token =
    createSession("user", user.id);


  setSession(res, token);


  res.json({

    user: {
      id: user.id,
      username: user.username
    }

  });

});


/* =====================================================
   CURRENT USER
===================================================== */

app.get("/api/me", (req, res) => {

  const session = getSession(req);


  if (
    !session ||
    session.type !== "user"
  ) {

    return res.json({
      loggedIn: false
    });

  }


  const user =
    users.find(
      u => u.id === session.userId
    );


  if (!user) {

    return res.json({
      loggedIn: false
    });

  }


  res.json({

    loggedIn: true,

    user: {
      id: user.id,
      username: user.username
    }

  });

});


/* =====================================================
   LOGOUT
===================================================== */

app.post("/api/logout", (req, res) => {

  const cookie = req.headers.cookie || "";

  const match = cookie
    .split(";")
    .map(x => x.trim())
    .find(x => x.startsWith("session="));


  if (match) {

    const token =
      match.substring("session=".length);

    sessions.delete(token);

  }


  clearSession(res);


  res.json({
    success: true
  });

});


/* =====================================================
   FORGOT PASSWORD
===================================================== */

app.post(
  "/api/forgot-password",
  (req, res) => {

    const username =
      String(req.body.username || "")
        .trim();


    if (!username) {

      return res.status(400).json({
        error:
          "نام کاربری یا ایمیل را وارد کنید."
      });

    }


    /*
      برای امنیت، وجود یا عدم وجود
      حساب را اعلام نمی‌کنیم.
    */

    res.json({

      success: true,

      message:
        "اگر حسابی با این مشخصات وجود داشته باشد، درخواست بازیابی ثبت شد."

    });

  }
);


/* =====================================================
   CREATE ORDER
===================================================== */

app.post(
  "/api/orders",
  requireUser,
  (req, res) => {

    const planId =
      Number(req.body.planId);

    const couponCode =
      String(req.body.coupon || "")
        .trim()
        .toUpperCase();


    const plan =
      plans.find(
        p =>
          Number(p.id) === planId &&
          p.active !== false
      );


    if (!plan) {

      return res.status(404).json({
        error: "پلن پیدا نشد."
      });

    }


    let finalPrice =
      Number(plan.price);


    let discount = 0;


    if (couponCode) {

      const coupon =
        coupons.find(
          c =>
            c.code === couponCode &&
            c.active !== false
        );


      if (!coupon) {

        return res.status(400).json({
          error: "کد تخفیف معتبر نیست."
        });

      }


      discount =
        Math.floor(
          finalPrice *
          Number(coupon.percent) /
          100
        );


      finalPrice =
        Math.max(
          0,
          finalPrice - discount
        );

    }


    const order = {

      id: id(),

      userId: req.userId,

      planId: plan.id,

      planName: plan.name,

      price: Number(plan.price),

      discount,

      finalPrice,

      coupon:
        couponCode || null,

      status: "pending",

      createdAt:
        new Date().toISOString()

    };


    orders.unshift(order);


    res.json({

      success: true,

      order

    });

  }
);


/* =====================================================
   USER ORDERS
===================================================== */

app.get(
  "/api/my/orders",
  requireUser,
  (req, res) => {

    const result =
      orders
        .filter(
          o =>
            o.userId === req.userId
        )
        .map(order => {

          const subscription =
            subscriptions.find(
              s =>
                s.orderId === order.id
            );


          return {

            ...order,

            subscriptionUrl:
              subscription
                ? subscription.subscriptionUrl
                : null

          };

        });


    res.json({
      orders: result
    });

  }
);


/* =====================================================
   USER SUBSCRIPTIONS
===================================================== */

app.get(
  "/api/my/subscriptions",
  requireUser,
  (req, res) => {

    const result =
      subscriptions
        .filter(
          s =>
            s.userId === req.userId &&
            s.active !== false
        )
        .map(s => {

          const plan =
            plans.find(
              p =>
                Number(p.id) ===
                Number(s.planId)
            );


          return {

            ...s,

            planName:
              plan
                ? plan.name
                : s.planName,

            gb:
              plan
                ? plan.gb
                : s.gb,

            days:
              plan
                ? plan.days
                : s.days

          };

        });


    res.json({
      subscriptions: result
    });

  }
);


/* =====================================================
   ADMIN LOGIN
===================================================== */

app.post(
  "/api/admin/login",
  (req, res) => {

    const username =
      String(req.body.username || "")
        .trim();

    const password =
      String(req.body.password || "");


    if (
      username !== ADMIN_USERNAME ||
      password !== ADMIN_PASSWORD
    ) {

      return res.status(401).json({
        error:
          "نام کاربری یا رمز عبور ادمین اشتباه است."
      });

    }


    const token =
      createSession(
        "admin",
        "admin"
      );


    setSession(res, token);


    res.json({
      admin: true
    });

  }
);


/* =====================================================
   ADMIN SESSION
===================================================== */

app.get(
  "/api/admin/me",
  (req, res) => {

    const session =
      getSession(req);


    res.json({

      authenticated:
        !!(
          session &&
          session.type === "admin"
        )

    });

  }
);


/* =====================================================
   ADMIN LOGOUT
===================================================== */

app.post(
  "/api/admin/logout",
  (req, res) => {

    const cookie =
      req.headers.cookie || "";


    const match =
      cookie
        .split(";")
        .map(x => x.trim())
        .find(
          x =>
            x.startsWith("session=")
        );


    if (match) {

      const token =
        match.substring(
          "session=".length
        );

      sessions.delete(token);

    }


    clearSession(res);


    res.json({
      success: true
    });

  }
);


/* =====================================================
   ADMIN DASHBOARD
===================================================== */

app.get(
  "/api/admin/dashboard",
  requireAdmin,
  (req, res) => {

    const income =
      orders
        .filter(
          o =>
            o.status === "approved"
        )
        .reduce(
          (sum, o) =>
            sum + Number(o.finalPrice || 0),
          0
        );


    res.json({

      usersCount:
        users.length,

      ordersCount:
        orders.length,

      plansCount:
        plans.length,

      income

    });

  }
);


/* =====================================================
   ADMIN PLANS
===================================================== */

app.get(
  "/api/admin/plans",
  requireAdmin,
  (req, res) => {

    res.json({
      plans
    });

  }
);


/* =====================================================
   CREATE PLAN
===================================================== */

app.post(
  "/api/admin/plans",
  requireAdmin,
  (req, res) => {

    const name =
      String(req.body.name || "")
        .trim();

    const gb =
      Number(req.body.gb);

    const days =
      Number(req.body.days);

    const price =
      Number(req.body.price);


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
        error:
          "اطلاعات پلن صحیح نیست."
      });

    }


    const plan = {

      id:
        Date.now(),

      name,

      gb,

      days,

      price,

      active: true,

      createdAt:
        new Date().toISOString()

    };


    plans.push(plan);


    res.json({
      success: true,
      plan
    });

  }
);


/* =====================================================
   DELETE PLAN
===================================================== */

app.delete(
  "/api/admin/plans/:id",
  requireAdmin,
  (req, res) => {

    const planId =
      Number(req.params.id);


    const index =
      plans.findIndex(
        p =>
          Number(p.id) === planId
      );


    if (index === -1) {

      return res.status(404).json({
        error: "پلن پیدا نشد."
      });

    }


    plans.splice(index, 1);


    res.json({
      success: true
    });

  }
);


/* =====================================================
   ADMIN USERS
===================================================== */

app.get(
  "/api/admin/users",
  requireAdmin,
  (req, res) => {

    res.json({

      users:
        users.map(
          u => ({
            id: u.id,
            username: u.username,
            createdAt: u.createdAt
          })
        )

    });

  }
);


/* =====================================================
   ADMIN ORDERS
===================================================== */

app.get(
  "/api/admin/orders",
  requireAdmin,
  (req, res) => {

    const result =
      orders.map(order => {

        const user =
          users.find(
            u =>
              u.id === order.userId
          );


        const subscription =
          subscriptions.find(
            s =>
              s.orderId === order.id
          );


        return {

          ...order,

          username:
            user
              ? user.username
              : "نامشخص",

          subscriptionUrl:
            subscription
              ? subscription.subscriptionUrl
              : null

        };

      });


    res.json({
      orders: result
    });

  }
);


/* =====================================================
   APPROVE / REJECT ORDER
===================================================== */

app.patch(
  "/api/admin/orders/:id",
  requireAdmin,
  (req, res) => {

    const order =
      orders.find(
        o =>
          String(o.id) ===
          String(req.params.id)
      );


    if (!order) {

      return res.status(404).json({
        error: "سفارش پیدا نشد."
      });

    }


    const status =
      String(req.body.status || "");


    if (
      status !== "approved" &&
      status !== "rejected"
    ) {

      return res.status(400).json({
        error: "وضعیت سفارش نامعتبر است."
      });

    }


    order.status = status;

    order.updatedAt =
      new Date().toISOString();


    /*
      در صورت تأیید سفارش،
      یک Subscription ایجاد می‌کنیم.
    */

    if (status === "approved") {

      const old =
        subscriptions.find(
          s =>
            s.orderId === order.id
        );


      if (!old) {

        const plan =
          plans.find(
            p =>
              Number(p.id) ===
              Number(order.planId)
          );


        if (plan) {

          const subscriptionToken =
            crypto
              .randomBytes(24)
              .toString("hex");


          subscriptions.push({

            id: id(),

            orderId:
              order.id,

            userId:
              order.userId,

            planId:
              plan.id,

            planName:
              plan.name,

            gb:
              plan.gb,

            days:
              plan.days,

            active: true,

            subscriptionUrl:
              `/subscription/${subscriptionToken}`,

            createdAt:
              new Date().toISOString()

          });

        }

      }

    }


    if (status === "rejected") {

      subscriptions =
        subscriptions.filter(
          s =>
            s.orderId !== order.id
        );

    }


    res.json({

      success: true,

      order

    });

  }
);


/* =====================================================
   ADMIN COUPONS
===================================================== */

app.get(
  "/api/admin/coupons",
  requireAdmin,
  (req, res) => {

    res.json({
      coupons
    });

  }
);


/* =====================================================
   CREATE COUPON
===================================================== */

app.post(
  "/api/admin/coupons",
  requireAdmin,
  (req, res) => {

    const code =
      String(req.body.code || "")
        .trim()
        .toUpperCase();


    const percent =
      Number(req.body.percent);


    if (
      !code ||
      !Number.isFinite(percent) ||
      percent <= 0 ||
      percent > 100
    ) {

      return res.status(400).json({
        error:
          "کد تخفیف یا درصد تخفیف صحیح نیست."
      });

    }


    const exists =
      coupons.some(
        c =>
          c.code === code
      );


    if (exists) {

      return res.status(409).json({
        error:
          "این کد تخفیف قبلاً ساخته شده است."
      });

    }


    const coupon = {

      id: id(),

      code,

      percent,

      active: true,

      createdAt:
        new Date().toISOString()

    };


    coupons.push(coupon);


    res.json({

      success: true,

      coupon

    });

  }
);


/* =====================================================
   SUBSCRIPTION DEMO ENDPOINT
===================================================== */

app.get(
  "/subscription/:token",
  (req, res) => {

    const subscription =
      subscriptions.find(
        s =>
          s.subscriptionUrl ===
          `/subscription/${req.params.token}`
      );


    if (!subscription) {

      return res.status(404).send(
        "Subscription not found"
      );

    }


    res.type("text/plain").send(
      `Emad Net Subscription\n\n` +
      `Plan: ${subscription.planName}\n` +
      `Volume: ${subscription.gb} GB\n` +
      `Duration: ${subscription.days} days\n`
    );

  }
);


/* =====================================================
   HEALTH CHECK
===================================================== */

app.get("/health", (req, res) => {

  res.json({
    status: "ok",
    service: "Emad Net"
  });

});


/* =====================================================
   STATIC WEBSITE
===================================================== */

app.use(
  express.static(
    path.join(__dirname, "public")
  )
);


/* =====================================================
   SPA FALLBACK
===================================================== */

app.get("*", (req, res) => {

  res.sendFile(
    path.join(
      __dirname,
      "public",
      "index.html"
    )
  );

});


/* =====================================================
   ERROR HANDLER
===================================================== */

app.use(
  (err, req, res, next) => {

    console.error(err);

    res.status(500).json({

      error:
        "خطای داخلی سرور."

    });

  }
);


/* =====================================================
   START
===================================================== */

app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      `Emad Net server running on port ${PORT}`
    );

  }
);
