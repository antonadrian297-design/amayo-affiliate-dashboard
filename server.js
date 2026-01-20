const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { fetchAffiliateOrders } = require("./shopify");

const app = express();

app.set("trust proxy", 1);
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "change-this-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production"
    }
  })
);

const AFFILIATE_EMAIL = (process.env.AFFILIATE_EMAIL || "").trim().toLowerCase();
const AFFILIATE_PASSWORD = process.env.AFFILIATE_PASSWORD || "";
const AFFILIATE_PASSWORD_HASH = process.env.AFFILIATE_PASSWORD_HASH || "";

function requireAuth(req, res, next) {
  if (req.session?.user?.loggedIn) return next();
  return res.redirect("/login");
}

function getViewHtml(name) {
  const fs = require("fs");
  const path = require("path");
  return fs.readFileSync(path.join(__dirname, "views", name), "utf8");
}

function currencyFormat(amount, currency) {
  try {
    return new Intl.NumberFormat("ro-RO", { style: "currency", currency }).format(amount);
  } catch {
    return `${amount.toFixed(2)} ${currency || ""}`.trim();
  }
}

app.get("/", (req, res) => {
  if (req.session?.user?.loggedIn) return res.redirect("/dashboard");
  return res.redirect("/login");
});

app.get("/login", (req, res) => {
  let html = getViewHtml("login.html");
  const err = req.query.err ? "Email sau parolă greșite." : "";
  html = html.replace("{{ERROR}}", err);
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  return res.send(html);
});

app.post("/login", async (req, res) => {
  const email = (req.body.email || "").trim().toLowerCase();
  const password = (req.body.password || "").trim();

  if (!email || !password) return res.redirect("/login?err=1");
  if (email !== AFFILIATE_EMAIL) return res.redirect("/login?err=1");

  let ok = false;

  // Prefer hash dacă există
  if (AFFILIATE_PASSWORD_HASH) {
    ok = await bcrypt.compare(password, AFFILIATE_PASSWORD_HASH);
  } else {
    // fallback simplu (pentru început)
    ok = password === AFFILIATE_PASSWORD;
  }

  if (!ok) return res.redirect("/login?err=1");

  req.session.user = { loggedIn: true, email };
  return res.redirect("/dashboard");
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

app.get("/dashboard", requireAuth, async (req, res) => {
  try {
    const code = (process.env.AFFILIATE_CODE || "stiudelasorina").trim();
    const rate = Number(process.env.AFFILIATE_RATE || "0.10"); // 10%
    const days = Number(req.query.days || process.env.DAYS_LOOKBACK || "30");

    const data = await fetchAffiliateOrders({ code, rate, days });

    // Render HTML
    let html = getViewHtml("dashboard.html");

    html = html
      .replaceAll("{{CODE}}", code)
      .replaceAll("{{DAYS}}", String(days))
      .replaceAll("{{ORDERS_COUNT}}", String(data.orders.length))
      .replaceAll("{{TOTAL_COMMISSION}}", currencyFormat(data.totalCommission, data.currency))
      .replaceAll("{{TOTAL_REVENUE}}", currencyFormat(data.totalRevenue, data.currency));

    const rows = data.orders
      .map((o) => {
        const elig = o.eligible ? "DA" : "NU";
        const eligBadge = o.eligible
          ? `<span class="badge ok">Eligibil</span>`
          : `<span class="badge no">Neeligibil</span>`;

        return `
          <tr>
            <td>${o.name}</td>
            <td>${o.date}</td>
            <td>${o.customer || "-"}</td>
            <td>${currencyFormat(o.total, data.currency)}</td>
            <td>${currencyFormat(o.commission, data.currency)}</td>
            <td>${eligBadge} <span class="muted">(${elig})</span></td>
            <td class="muted">${o.fulfillmentStatus}</td>
            <td class="muted">${o.financialStatus}</td>
          </tr>
        `;
      })
      .join("");

    html = html.replace("{{ROWS}}", rows || `<tr><td colspan="8" class="muted">Nu există comenzi pentru criteriile selectate.</td></tr>`);

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    return res.send(html);
  } catch (e) {
    console.error(e);
    return res.status(500).send("Eroare la încărcarea datelor. Verifică variabilele de mediu (Shopify token / shop).");
  }
});

app.get("/export.csv", requireAuth, async (req, res) => {
  const code = (process.env.AFFILIATE_CODE || "stiudelasorina").trim();
  const rate = Number(process.env.AFFILIATE_RATE || "0.10");
  const days = Number(req.query.days || process.env.DAYS_LOOKBACK || "30");
  const data = await fetchAffiliateOrders({ code, rate, days });

  const header = [
    "order_name",
    "date",
    "customer",
    "total",
    "commission",
    "eligible",
    "fulfillment_status",
    "financial_status"
  ].join(",");

  const lines = data.orders.map((o) =>
    [
      `"${o.name}"`,
      `"${o.date}"`,
      `"${(o.customer || "").replaceAll('"', '""')}"`,
      o.total.toFixed(2),
      o.commission.toFixed(2),
      o.eligible ? "1" : "0",
      `"${o.fulfillmentStatus}"`,
      `"${o.financialStatus}"`
    ].join(",")
  );

  const csv = [header, ...lines].join("\n");
  res.setHeader("Content-Type", "text/csv; charset=utf-8");
  res.setHeader("Content-Disposition", `attachment; filename="affiliate_${code}_${days}d.csv"`);
  return res.send(csv);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on :${PORT}`));
