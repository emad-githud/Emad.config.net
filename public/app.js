let user = null;

/* =====================================================
   HELPERS
===================================================== */

const $ = (id) =>
  document.getElementById(id);


function toast(message) {

  const element =
    $("toast");

  element.textContent =
    message;

  element.classList.add(
    "show"
  );

  clearTimeout(
    window.toastTimer
  );

  window.toastTimer =
    setTimeout(() => {

      element.classList.remove(
        "show"
      );

    }, 3000);
}


/* =====================================================
   API
===================================================== */

async function api(
  url,
  options = {}
) {

  const response =
    await fetch(
      url,
      {
        credentials:
          "include",

        headers: {
          "Content-Type":
            "application/json",
        },

        ...options,
      }
    );

  let data = {};

  try {
    data =
      await response.json();
  } catch (_) {}

  if (!response.ok) {
    throw new Error(
      data.error ||
      "خطا"
    );
  }

  return data;
}


/* =====================================================
   PAGE NAVIGATION
===================================================== */

function go(page) {

  /*
    اگر کاربر روی حساب من بزند
    ولی لاگین نباشد، صفحه ورود باز می‌شود.
  */

  if (
    page === "account" &&
    !user
  ) {
    authMode("login");
    return;
  }

  document
    .querySelectorAll(".page")
    .forEach(
      (element) => {
        element.classList.remove(
          "active"
        );
      }
    );

  const target =
    $(page);

  if (!target) {
    return;
  }

  target.classList.add(
    "active"
  );

  if (
    page === "account"
  ) {
    renderAccount();

    loadPlans();
  }

  window.scrollTo({
    top: 0,
    behavior: "smooth",
  });
}


/* =====================================================
   AUTH MODE
===================================================== */

function authMode(mode) {

  $("auth")
    .classList
    .add("active");

  $("home")
    .classList
    .remove("active");

  $("account")
    .classList
    .remove("active");


  $("lf")
    .classList
    .toggle(
      "hidden",
      mode !== "login"
    );

  $("rf")
    .classList
    .toggle(
      "hidden",
      mode !== "register"
    );


  $("lt")
    .classList
    .toggle(
      "active",
      mode === "login"
    );

  $("rt")
    .classList
    .toggle(
      "active",
      mode === "register"
    );
}


/* =====================================================
   LOGIN
===================================================== */

async function login(event) {

  event.preventDefault();

  try {

    const data =
      await api(
        "/api/login",
        {
          method:
            "POST",

          body:
            JSON.stringify({
              username:
                $("lu")
                  .value
                  .trim(),

              password:
                $("lp")
                  .value,
            }),
        }
      );

    user =
      data.user;

    toast(
      "ورود موفق بود"
    );

    /*
      بعد از ورود مستقیم
      حساب کاربری باز می‌شود.
    */

    go("account");

  } catch (error) {

    toast(
      error.message
    );

  }
}


/* =====================================================
   REGISTER
===================================================== */

async function register(
  event
) {

  event.preventDefault();

  try {

    const data =
      await api(
        "/api/register",
        {
          method:
            "POST",

          body:
            JSON.stringify({
              username:
                $("ru")
                  .value
                  .trim(),

              password:
                $("rp")
                  .value,
            }),
        }
      );

    user =
      data.user;

    toast(
      "حساب با موفقیت ساخته شد"
    );

    go("account");

  } catch (error) {

    toast(
      error.message
    );

  }
}


/* =====================================================
   LOGOUT
===================================================== */

async function logout() {

  try {

    await api(
      "/api/logout",
      {
        method:
          "POST",
      }
    );

  } catch (_) {}

  user = null;

  $("acct").textContent =
    "حساب من";

  toast(
    "از حساب خارج شدید"
  );

  go("home");
}


/* =====================================================
   ACCOUNT
===================================================== */

function renderAccount() {

  $("guest")
    .classList
    .add("hidden");

  $("panel")
    .classList
    .remove("hidden");

  $("uname").textContent =
    user.username;

  $("acct").textContent =
    user.username;
}


/* =====================================================
   LOAD PRODUCTS
===================================================== */

async function loadPlans() {

  /*
    مهم:
    اگر کاربر لاگین نباشد،
    اصلاً درخواست محصولات ارسال نمی‌شود.
  */

  if (!user) {
    return;
  }

  try {

    const plans =
      await api(
        "/api/plans"
      );

    const container =
      $("plans");

    if (!plans.length) {

      container.innerHTML =
        "<p>محصولی موجود نیست.</p>";

      return;
    }

    container.innerHTML =
      plans
        .map(
          (plan) => `

          <article class="plan">

            <small>
              VPN PLAN
            </small>

            <h3>
              ${escapeHtml(
                plan.name
              )}
            </h3>

            <div class="price">
              ${formatPrice(
                plan.price
              )}
              تومان
            </div>

            <div>

              <span class="pill">
                ${plan.gb} GB
              </span>

              <span class="pill">
                ${plan.days} روز
              </span>

            </div>

            <button
              class="primary"
              onclick="buy(${plan.id})"
            >
              خرید این پلن
            </button>

          </article>

        `
        )
        .join("");

  } catch (error) {

    toast(
      error.message
    );
  }
}


/* =====================================================
   BUY
===================================================== */

async function buy(
  planId
) {

  if (
    !confirm(
      "سفارش ثبت شود؟"
    )
  ) {
    return;
  }

  try {

    const data =
      await api(
        "/api/orders",
        {
          method:
            "POST",

          body:
            JSON.stringify({
              planId,
            }),
        }
      );

    toast(
      "سفارش #" +
      data.order.id +
      " ثبت شد"
    );

    panel(
      "orders"
    );

    loadOrders();

  } catch (error) {

    toast(
      error.message
    );
  }
}


/* =====================================================
   ACCOUNT PANELS
===================================================== */

function panel(
  page,
  button
) {

  [
    "products",
    "orders",
    "subs",
    "settings",
  ].forEach(
    (id) => {

      $(id)
        .classList
        .toggle(
          "hidden",
          id !== page
        );

    }
  );


  document
    .querySelectorAll(
      ".menu button"
    )
    .forEach(
      (element) => {

        element.classList.remove(
          "selected"
        );

      }
    );


  if (button) {
    button.classList.add(
      "selected"
    );
  }


  if (
    page === "products"
  ) {
    loadPlans();
  }


  if (
    page === "orders"
  ) {
    loadOrders();
  }


  if (
    page === "subs"
  ) {
    loadSubscriptions();
  }
}


/* =====================================================
   ORDERS
===================================================== */

async function loadOrders() {

  try {

    const data =
      await api(
        "/api/my/orders"
      );

    const container =
      $("orderList");

    if (
      !data.orders.length
    ) {

      container.innerHTML =
        "<p>هنوز سفارشی ندارید.</p>";

      return;
    }


    container.innerHTML =
      data.orders
        .map(
          (order) => `

          <div class="item">

            <span>

              #${order.id}
              —
              ${escapeHtml(
                order.planName
              )}

              <br>

              <small>
                ${formatPrice(
                  order.finalPrice
                )}
                تومان
              </small>

            </span>

            <b>
              ${getStatus(
                order.status
              )}
            </b>

          </div>

        `
        )
        .join("");

  } catch (error) {

    toast(
      error.message
    );
  }
}


/* =====================================================
   SUBSCRIPTIONS
===================================================== */

async function loadSubscriptions() {

  try {

    const data =
      await api(
        "/api/my/subscriptions"
      );

    const container =
      $("subList");

    if (
      !data.subscriptions.length
    ) {

      container.innerHTML =
        "<p>اشتراک فعالی ندارید.</p>";

      return;
    }


    container.innerHTML =
      data.subscriptions
        .map(
          (subscription) => `

          <div class="item">

            <span>

              ${escapeHtml(
                subscription.planName
              )}

              <br>

              <small>
                ${subscription.gb || "-"}
                GB
                ·
                ${subscription.days || "-"}
                روز
              </small>

            </span>

            ${
              subscription.subscriptionUrl
                ? `
                  <a
                    class="primary"
                    href="${escapeHtml(
                      subscription.subscriptionUrl
                    )}"
                    target="_blank"
                    rel="noopener"
                  >
                    اشتراک
                  </a>
                `
                : ""
            }

          </div>

        `
        )
        .join("");

  } catch (error) {

    toast(
      error.message
    );
  }
}


/* =====================================================
   ORDER STATUS
===================================================== */

function getStatus(
  status
) {

  if (
    status ===
    "approved"
  ) {
    return "تأیید شده";
  }

  if (
    status ===
    "rejected"
  ) {
    return "رد شده";
  }

  return "در انتظار بررسی";
}


/* =====================================================
   FORGOT PASSWORD
===================================================== */

async function forgot() {

  const username =
    $("lu")
      .value
      .trim();

  if (!username) {

    toast(
      "نام کاربری را وارد کنید."
    );

    return;
  }

  try {

    const data =
      await api(
        "/api/forgot-password",
        {
          method:
            "POST",

          body:
            JSON.stringify({
              username,
            }),
        }
      );

    toast(
      data.message
    );

  } catch (error) {

    toast(
      error.message
    );
  }
}


/* =====================================================
   SUPPORT
===================================================== */

async function loadSupport() {

  try {

    const data =
      await api(
        "/api/support"
      );

    $("supportLink").href =
      data.telegramUrl;

  } catch (_) {}

}


/* =====================================================
   THEME
===================================================== */

function setTheme(
  theme
) {

  document.body
    .classList
    .toggle(
      "dark",
      theme === "dark"
    );

  localStorage.setItem(
    "theme",
    theme
  );

  $("theme").textContent =
    theme === "dark"
      ? "☀️"
      : "🌙";
}


function toggleTheme() {

  const dark =
    document.body
      .classList
      .contains("dark");

  setTheme(
    dark
      ? "light"
      : "dark"
  );
}


/* =====================================================
   FORMAT
===================================================== */

function formatPrice(
  value
) {

  return Number(
    value || 0
  ).toLocaleString(
    "fa-IR"
  );
}


function escapeHtml(
  value
) {

  return String(
    value ?? ""
  ).replace(
    /[&<>"']/g,
    (char) => {

      return {
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      }[char];

    }
  );
}


/* =====================================================
   INIT
===================================================== */

async function init() {

  setTheme(
    localStorage.getItem(
      "theme"
    ) || "light"
  );

  await loadSupport();


  try {

    const data =
      await api(
        "/api/me"
      );

    if (
      data.loggedIn
    ) {

      user =
        data.user;

      renderAccount();
    }

  } catch (_) {}


  go("home");
}


init();
