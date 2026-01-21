const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const { parse } = require("csv-parse/sync");

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

/**
 * =========================
 * CONFIG (ENV)
 * =========================
 * Render -> Environment:
 *  - SESSION_SECRET = ceva-lung
 *
 *  - ADMIN_USER = amayo
 *  - ADMIN_PASS = amayoadmin
 *
 *  - AFFILIATE_USER = sorinamincu
 *  - AFFILIATE_PASS = amayoSorina
 *  - AFFILIATE_MATCH = stiudelasorina
 *
 *  - COMMISSION_RATE = 0.10 (optional)
 */

const SESSION_SECRET = process.env.SESSION_SECRET || "change-me-in-render";

const ADMIN_USER = String(process.env.ADMIN_USER || "amayo").trim();
const ADMIN_PASS = String(process.env.ADMIN_PASS || "amayoadmin").trim();

const AFFILIATE_USER = String(process.env.AFFILIATE_USER || "sorinamincu").trim();
const AFFILIATE_PASS = String(process.env.AFFILIATE_PASS || "amayoSorina").trim();
const AFFILIATE_MATCH = String(process.env.AFFILIATE_MATCH || "stiudelasorina").trim().toLowerCase();

const COMMISSION_RATE = Number(process.env.COMMISSION_RATE || "0.10");

/**
 * =========================
 * SESSION
 * =========================
 */
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    },
  })
);

/**
 * =========================
 * STORAGE: orders cache
 * =========================
 */
const DATA_FILE = path.join("/tmp", "orders_cache.json");
let orders = [];

function loadOrdersFromDisk() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, "utf8");
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) orders = parsed;
    }
  } catch (e) {
    console.error("Failed to load orders cache:", e);
  }
}

function saveOrdersToDisk() {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(orders), "utf8");
  } catch (e) {
    console.error("Failed to save orders cache:", e);
  }
}

loadOrdersFromDisk();

/**
 * =========================
 * PASSWORD HASH CACHE
 * =========================
 */
async function hashPass(pass) {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(pass, salt);
}

let adminHashPromise = null;
let affiliateHashPromise = null;

function getAdminHash() {
  if (!adminHashPromise) adminHashPromise = hashPass(ADMIN_PASS);
  return adminHashPromise;
}
function getAffiliateHash() {
  if (!affiliateHashPromise) affiliateHashPromise = hashPass(AFFILIATE_PASS);
  return affiliateHashPromise;
}

/**
 * =========================
 * AUTH HELPERS
 * =========================
 */
function requireAuth(req, res, next) {
  if (req.session?.role) return next();
  return res.redirect("/login");
}

function requireAdmin(req, res, next) {
  if (req.session?.role === "admin") return next();
  return res.status(403).send("Forbidden");
}

/**
 * =========================
 * CSV UPLOAD
 * =========================
 */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});

/**
 * =========================
 * UTIL
 * =========================
 */
function normalizeKey(k) {
  return String(k || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, " ");
}

function pickFirstExistingKey(obj, candidates) {
  const keys = Object.keys(obj || {});
  const normMap = new Map(keys.map((k) => [normalizeKey(k), k]));
  for (const c of candidates) {
    const found = normMap.get(normalizeKey(c));
    if (found) return found;
  }
  return null;
}

function parseMoney(value) {
  const s = String(value ?? "").trim();
  if (!s) return 0;
  const cleaned = s.replace(/[^\d,.\-]/g, "");
  if (cleaned.includes(",") && !cleaned.includes(".")) {
    return Number(cleaned.replace(",", ".")) || 0;
  }
  if (cleaned.includes(",") && cleaned.includes(".")) {
    return Number(cleaned.replace(/,/g, "")) || 0;
  }
  return Number(cleaned) || 0;
}

function parseDate(value) {
  const s = String(value ?? "").trim();
  if (!s) return null;
  const d = new Date(s);
  if (!isNaN(d.getTime())) return d;

  const m = s.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (m) {
    const dd = new Date(`${m[1]}-${m[2]}-${m[3]}T00:00:00Z`);
    if (!isNaN(dd.getTime())) return dd;
  }
  return null;
}

function rowMatchesAffiliate(row) {
  const discountKey = pickFirstExistingKey(row, [
    "discount code",
    "discount_code",
    "discount codes",
    "discount_codes",
    "discount",
    "discounts",
  ]);

  if (discountKey) {
    const v = String(row[discountKey] || "").toLowerCase();
    return v.includes(AFFILIATE_MATCH);
  }

  const hay = Object.values(row)
    .map((v) => String(v || "").toLowerCase())
    .join(" | ");
  return hay.includes(AFFILIATE_MATCH);
}

function normalizeOrderRow(row) {
  const createdAtKey = pickFirstExistingKey(row, ["created at", "created_at", "created date", "date"]);
  const nameKey = pickFirstExistingKey(row, ["name", "order", "order name", "order_number", "order number"]);
  const totalKey = pickFirstExistingKey(row, [
    "total",
    "total price",
    "total_price",
    "total paid",
    "current total price",
    "current_total_price",
  ]);
  const financialKey = pickFirstExistingKey(row, ["financial status", "financial_status", "payment status", "paid"]);
  const discountKey = pickFirstExistingKey(row, [
    "discount code",
    "discount_code",
    "discount codes",
    "discount_codes",
    "discount",
    "discounts",
  ]);

  const createdAt = createdAtKey ? parseDate(row[createdAtKey]) : null;
  const total = totalKey ? parseMoney(row[totalKey]) : 0;

  return {
    raw: row,
    createdAtISO: createdAt ? createdAt.toISOString() : null,
    orderName: nameKey ? String(row[nameKey] || "").trim() : "",
    total,
    financialStatus: financialKey ? String(row[financialKey] || "").trim() : "",
    discount: discountKey ? String(row[discountKey] || "").trim() : "",
  };
}

function escapeHtml(str) {
  return String(str ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function pageLayout(title, bodyHtml) {
  return `<!doctype html>
<html lang="ro">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>${title}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 30px; }
    .box { max-width: 900px; margin: 0 auto; }
    .row { display:flex; gap: 12px; flex-wrap: wrap; align-items: end; }
    input, button { padding: 10px; font-size: 14px; }
    table { width: 100%; border-collapse: collapse; margin-top: 16px; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align:left; font-size: 13px; }
    th { background: #f5f5f5; }
    .muted { color:#666; font-size: 13px; }
    .topbar { display:flex; justify-content: space-between; align-items: center; margin-bottom: 18px; }
    .pill { display:inline-block; padding: 4px 10px; border:1px solid #ddd; border-radius: 999px; font-size: 12px; }
    .danger { color: #b00020; }
    .summary { display:flex; gap: 16px; flex-wrap: wrap; margin-top: 14px; }
    .card { border: 1px solid #eee; border-radius: 10px; padding: 12px 14px; min-width: 220px; }
    .card h3 { margin: 0 0 6px; font-size: 14px; color:#333; }
    .card .value { font-size: 20px; font-weight: 700; }
    .btnlink { text-decoration:none; border:1px solid #ddd; padding:8px 12px; border-radius:8px; color:#111; }
  </style>
</head>
<body>
  <div class="box">
    ${bodyHtml}
  </div>
</body>
</html>`;
}

/**
 * =========================
 * ROUTES
 * =========================
 */
app.get("/", (req, res) => {
  if (req.session?.role) return res.redirect("/dashboard");
  return res.redirect("/login");
});

app.get("/login", (req, res) => {
  const error = req.query.error ? `<div class="danger" style="margin-top:10px;">Email sau parolă greșită</div>` : "";
  res.send(
    pageLayout(
      "Login",
      `
      <div class="topbar">
        <h2>Login</h2>
        <span class="pill">AMAYO</span>
      </div>

      <form method="POST" action="/login">
        <div style="margin-bottom:10px;">
          <div class="muted">Email</div>
          <input name="email" type="text" style="width: 420px;" autocomplete="username" required />
        </div>
        <div style="margin-bottom:10px;">
          <div class="muted">Parolă</div>
          <input name="password" type="password" style="width: 420px;" autocomplete="current-password" required />
        </div>
        <button type="submit">Intră</button>
        ${error}
      </form>

      <div class="muted" style="margin-top:14px;">
        <b>Admin:</b> ${escapeHtml(ADMIN_USER)} / (parola din ENV) <br/>
        <b>Afiliat:</b> ${escapeHtml(AFFILIATE_USER)} / (parola din ENV)
      </div>
      `
    )
  );
});

app.post("/login", async (req, res) => {
  try {
    const email = String(req.body.email || "").trim();
    const password = String(req.body.password || "");

    if (email === ADMIN_USER) {
      const ok = await bcrypt.compare(password, await getAdminHash());
      if (!ok) return res.redirect("/login?error=1");
      req.session.role = "admin";
      req.session.user = ADMIN_USER;
      return res.redirect("/dashboard");
    }

    if (email === AFFILIATE_USER) {
      const ok = await bcrypt.compare(password, await getAffiliateHash());
      if (!ok) return res.redirect("/login?error=1");
      req.session.role = "affiliate";
      req.session.user = AFFILIATE_USER;
      return res.redirect("/dashboard");
    }

    return res.redirect("/login?error=1");
  } catch (e) {
    console.error(e);
    return res.redirect("/login?error=1");
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

app.get("/dashboard", requireAuth, (req, res) => {
  const from = String(req.query.from || "").trim();
  const to = String(req.query.to || "").trim();

  const fromDate = from ? new Date(`${from}T00:00:00Z`) : null;
  const toDate = to ? new Date(`${to}T23:59:59Z`) : null;

  const isAdmin = req.session.role === "admin";
  const canUpload = isAdmin;

  const filtered = orders
    .filter((o) => {
      // affiliate vede DOAR comenzile cu codul
      if (!isAdmin) {
        if (!rowMatchesAffiliate(o.raw || {})) return false;
      }

      // date filter (ambele roluri)
      if (!o.createdAtISO) return true;
      const d = new Date(o.createdAtISO);
      if (fromDate && d < fromDate) return false;
      if (toDate && d > toDate) return false;
      return true;
    })
    .sort((a, b) => {
      const da = a.createdAtISO ? new Date(a.createdAtISO).getTime() : 0;
      const db = b.createdAtISO ? new Date(b.createdAtISO).getTime() : 0;
      return db - da;
    });

  // sumar:
  const totalOrders = filtered.length;
  const totalRevenue = filtered.reduce((s, o) => s + (o.total || 0), 0);
  const totalCommission = totalRevenue * (isFinite(COMMISSION_RATE) ? COMMISSION_RATE : 0);

  const rowsHtml = filtered
    .slice(0, 500)
    .map((o) => {
      const dateStr = o.createdAtISO ? new Date(o.createdAtISO).toLocaleString("ro-RO") : "";
      const totalStr = (o.total || 0).toFixed(2);
      return `<tr>
        <td>${escapeHtml(o.orderName || "")}</td>
        <td>${escapeHtml(dateStr)}</td>
        <td>${escapeHtml(o.financialStatus || "")}</td>
        <td>${escapeHtml(o.discount || "")}</td>
        <td>${totalStr}</td>
      </tr>`;
    })
    .join("");

  // bloc upload doar pentru admin:
  const uploadBlock = canUpload
    ? `
      <hr style="margin:18px 0;"/>
      <h3>Încarcă CSV (export Shopify Orders)</h3>
      <form method="POST" action="/upload" enctype="multipart/form-data" class="row">
        <input type="file" name="csvfile" accept=".csv" required />
        <button type="submit">Upload</button>
        <span class="muted">Se salvează pe server (în /tmp cât timp rulează instanța)</span>
      </form>

      <div class="muted" style="margin-top:10px;">
        Total rânduri încărcate în sistem: <b>${orders.length}</b>
      </div>
    `
    : `
      <hr style="margin:18px 0;"/>
      <div class="muted">
        CSV-ul este încărcat de admin. Dacă nu vezi comenzi, așteaptă următorul import.
      </div>
    `;

  const titleLine = isAdmin
    ? `<div class="muted">Rol: <b>Admin</b> (vezi toate comenzile din CSV)</div>`
    : `<div class="muted">Rol: <b>Afiliat</b> — Filtrat strict pe cod reducere: <b>${escapeHtml(
        AFFILIATE_MATCH
      )}</b></div>`;

  res.send(
    pageLayout(
      "Dashboard",
      `
      <div class="topbar">
        <div>
          <h2 style="margin:0;">Dashboard</h2>
          ${titleLine}
        </div>
        <div class="row">
          <a class="btnlink" href="/logout">Logout</a>
        </div>
      </div>

      <form method="GET" action="/dashboard" class="row">
        <div>
          <div class="muted">De la (YYYY-MM-DD)</div>
          <input name="from" value="${escapeHtml(from)}" placeholder="2026-01-01" />
        </div>
        <div>
          <div class="muted">Până la (YYYY-MM-DD)</div>
          <input name="to" value="${escapeHtml(to)}" placeholder="2026-01-31" />
        </div>
        <div>
          <button type="submit">Aplică filtru</button>
        </div>
      </form>

      <div class="summary">
        <div class="card">
          <h3>Comenzi</h3>
          <div class="value">${totalOrders}</div>
        </div>
        <div class="card">
          <h3>Total vânzări (din CSV)</h3>
          <div class="value">${totalRevenue.toFixed(2)}</div>
        </div>
        <div class="card">
          <h3>Comision (${Math.round(COMMISSION_RATE * 100)}%)</h3>
          <div class="value">${totalCommission.toFixed(2)}</div>
        </div>
      </div>

      ${uploadBlock}

      <h3 style="margin-top:18px;">Comenzi (max 500 afișate)</h3>
      <table>
        <thead>
          <tr>
            <th>Order</th>
            <th>Created</th>
            <th>Status</th>
            <th>Discount</th>
            <th>Total</th>
          </tr>
        </thead>
        <tbody>
          ${rowsHtml || `<tr><td colspan="5" class="muted">Nu există comenzi pentru criteriile selectate.</td></tr>`}
        </tbody>
      </table>
      `
    )
  );
});

// Upload route — doar admin
app.post("/upload", requireAdmin, upload.single("csvfile"), (req, res) => {
  try {
    if (!req.file) return res.redirect("/dashboard");

    const csvText = req.file.buffer.toString("utf8");
    const records = parse(csvText, {
      columns: true,
      skip_empty_lines: true,
      relax_column_count: true,
      bom: true,
    });

    orders = records.map(normalizeOrderRow);
    saveOrdersToDisk();
    return res.redirect("/dashboard");
  } catch (e) {
    console.error("Upload failed:", e);
    return res.status(400).send("Eroare la procesarea CSV. Verifică formatul exportului Shopify.");
  }
});

const PORT = Number(process.env.PORT || 10000);
app.listen(PORT, () => console.log(`Server running on ${PORT}`));
