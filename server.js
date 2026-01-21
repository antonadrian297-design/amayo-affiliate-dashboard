const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const fs = require("fs");
const { parse } = require("csv-parse/sync");

const app = express();
const upload = multer({ dest: "/tmp" });

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "amayo-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax" },
  })
);

/* ================= USERS (hardcoded) =================
   Admin: amayo / amayoadmin
   Affiliate: sorinamincu / amayoSorina  (discount: stiudelasorina)
*/
const USERS = {
  admin: {
    username: "amayo",
    passwordHash: bcrypt.hashSync("amayoadmin", 10),
    role: "admin",
  },
  sorina: {
    username: "sorinamincu",
    passwordHash: bcrypt.hashSync("amayoSorina", 10),
    role: "affiliate",
    discountCode: "stiudelasorina",
  },
};

/* ================= STORAGE (in-memory) ================= */
let ORDERS = [];

/* ================= HELPERS ================= */

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function normalizeCode(s) {
  return String(s || "").trim().toLowerCase();
}

function toNumber(x) {
  const n = Number(String(x || "").replace(",", "."));
  return Number.isFinite(n) ? n : 0;
}

function parseDate(d) {
  const dt = new Date(d);
  return isNaN(dt.getTime()) ? null : dt;
}

function inRange(created, from, to) {
  const c = parseDate(created);
  if (!c) return false;
  if (from && c < from) return false;
  if (to && c > to) return false;
  return true;
}

function layout(title, body, user) {
  const who =
    user?.role === "admin"
      ? `<span class="badge admin">ADMIN</span>`
      : user?.role === "affiliate"
      ? `<span class="badge aff">AFILIAT</span>`
      : "";

  return `<!doctype html>
<html lang="ro">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>
    :root{
      --bg:#0b1220;
      --card:#0f1b33;
      --card2:#0c162b;
      --text:#e8eefc;
      --muted:#aab6d6;
      --line:rgba(255,255,255,.08);
      --accent:#ffd166;
      --accent2:#4cc9f0;
      --danger:#ff5c77;
      --ok:#32d583;
      --shadow: 0 18px 60px rgba(0,0,0,.35);
      --r:16px;
      --font: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      font-family:var(--font);
      color:var(--text);
      background:
        radial-gradient(1200px 600px at 20% 10%, rgba(76,201,240,.18), transparent 55%),
        radial-gradient(900px 500px at 80% 20%, rgba(255,209,102,.14), transparent 55%),
        radial-gradient(900px 500px at 60% 90%, rgba(50,213,131,.10), transparent 60%),
        var(--bg);
      min-height:100vh;
      padding:28px 14px;
    }
    a{color:inherit}
    .container{max-width:1040px;margin:0 auto}
    .top{
      display:flex;align-items:center;justify-content:space-between;gap:12px;
      margin-bottom:18px;
    }
    .brand{
      display:flex;align-items:center;gap:10px;
    }
    .logo{
      width:38px;height:38px;border-radius:12px;
      background: linear-gradient(135deg, var(--accent), var(--accent2));
      box-shadow: var(--shadow);
    }
    h1,h2,h3{margin:0}
    .subtitle{color:var(--muted);margin-top:4px;font-size:13px}
    .card{
      background: linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03));
      border:1px solid var(--line);
      border-radius: var(--r);
      box-shadow: var(--shadow);
      padding:18px;
    }
    .grid{
      display:grid;
      grid-template-columns: 1fr;
      gap:14px;
    }
    @media (min-width:900px){
      .grid{grid-template-columns: 1.1fr .9fr}
    }
    .btn{
      display:inline-flex;align-items:center;justify-content:center;
      padding:10px 14px;border-radius:12px;
      border:1px solid var(--line);
      background: rgba(255,255,255,.06);
      color:var(--text);
      cursor:pointer;
      text-decoration:none;
      font-weight:600;
      transition:.15s transform, .15s opacity;
    }
    .btn:hover{transform: translateY(-1px)}
    .btn.primary{
      background: linear-gradient(135deg, var(--accent), var(--accent2));
      color:#0b1220;border:none;
    }
    .btn.ghost{background:transparent}
    .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
    label{display:block;color:var(--muted);font-size:13px;margin:10px 0 6px}
    input[type="text"],input[type="password"],input[type="date"],input[type="file"]{
      width:100%;
      background: rgba(0,0,0,.18);
      border:1px solid var(--line);
      color:var(--text);
      padding:10px 12px;
      border-radius:12px;
      outline:none;
    }
    input[type="file"]{padding:10px}
    .center{min-height:calc(100vh - 60px);display:flex;align-items:center;justify-content:center}
    .login{
      width: min(520px, 100%);
      padding:22px;
    }
    .danger{
      margin-top:12px;
      background: rgba(255,92,119,.12);
      border:1px solid rgba(255,92,119,.25);
      color: #ffd7de;
      padding:10px 12px;border-radius:12px;
      font-size:13px;
    }
    .badge{
      padding:6px 10px;border-radius:999px;font-size:12px;font-weight:700;
      border:1px solid var(--line);
      background: rgba(255,255,255,.06);
    }
    .badge.admin{background: rgba(76,201,240,.12); border-color: rgba(76,201,240,.28)}
    .badge.aff{background: rgba(255,209,102,.12); border-color: rgba(255,209,102,.28)}
    .pill{
      display:inline-block;
      margin-top:10px;
      padding:8px 12px;
      border-radius:999px;
      background: rgba(50,213,131,.10);
      border:1px solid rgba(50,213,131,.25);
      color:#d6ffe9;
      font-size:13px;
      font-weight:650;
    }
    .stats{
      display:grid;
      grid-template-columns: repeat(1, 1fr);
      gap:12px;
      margin-top:12px;
    }
    @media (min-width:700px){
      .stats{grid-template-columns: repeat(3, 1fr);}
    }
    .stat{
      padding:14px;
      border-radius: var(--r);
      background: rgba(0,0,0,.16);
      border:1px solid var(--line);
    }
    .stat .k{color:var(--muted);font-size:12px;margin-bottom:8px}
    .stat .v{font-size:22px;font-weight:800}
    table{
      width:100%;
      border-collapse: collapse;
      margin-top:12px;
      overflow:hidden;
      border-radius: var(--r);
      border:1px solid var(--line);
      background: rgba(0,0,0,.12);
    }
    th,td{
      padding:10px 10px;
      border-bottom:1px solid var(--line);
      text-align:left;
      font-size:13px;
    }
    th{color:var(--muted);font-weight:700;background: rgba(255,255,255,.04)}
    tr:hover td{background: rgba(255,255,255,.03)}
    .muted{color:var(--muted);font-size:12px}
    .footer-note{margin-top:10px;color:var(--muted);font-size:12px}
  </style>
</head>
<body>
  <div class="container">
    <div class="top">
      <div class="brand">
        <div class="logo"></div>
        <div>
          <h2>AMAYO – Affiliate Dashboard ${who}</h2>
          <div class="subtitle">CSV Shopify Orders → filtru pe cod reducere + perioadă</div>
        </div>
      </div>
      ${
        user
          ? `<a class="btn ghost" href="/logout">Logout</a>`
          : `<a class="btn ghost" href="/login">Login</a>`
      }
    </div>
    ${body}
  </div>
</body>
</html>`;
}

/* ================= ROUTES ================= */

app.get("/", (req, res) => res.redirect("/login"));

app.get("/login", (req, res) => {
  const err = req.query.err ? `<div class="danger">User sau parolă incorecte.</div>` : "";

  res.send(
    layout(
      "Login",
      `
<div class="center">
  <div class="card login">
    <h2>Autentificare</h2>
    <div class="subtitle">Introdu user + parolă</div>

    <form method="post" action="/login">
      <label>User</label>
      <input type="text" name="username" required />

      <label>Parolă</label>
      <input type="password" name="password" required />

      <div style="margin-top:14px" class="row">
        <button class="btn primary" type="submit">Intră</button>
      </div>
      ${err}
    </form>
  </div>
</div>
`,
      null
    )
  );
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const user = Object.values(USERS).find((u) => u.username === username);
  if (!user) return res.redirect("/login?err=1");

  const ok = bcrypt.compareSync(password, user.passwordHash);
  if (!ok) return res.redirect("/login?err=1");

  req.session.user = {
    username: user.username,
    role: user.role,
    discountCode: user.discountCode || null,
  };

  res.redirect("/dashboard");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

/* ================= DASHBOARD ================= */

app.get("/dashboard", requireAuth, (req, res) => {
  const user = req.session.user;

  const from = req.query.from ? parseDate(req.query.from) : null;
  const to = req.query.to ? parseDate(req.query.to) : null;

  // Filter by role
  let data = [...ORDERS];
  if (user.role === "affiliate") {
    const code = normalizeCode(user.discountCode);
    data = data.filter((o) => normalizeCode(o.discount) === code);
  }

  // Filter by date range (if provided)
  if (from || to) {
    data = data.filter((o) => inRange(o.created, from, to));
  }

  // Metrics
  const total = data.reduce((s, o) => s + toNumber(o.total), 0);
  const commission = total * 0.1;

  const codPill =
    user.role === "affiliate" && user.discountCode
      ? `<div class="pill">Cod reducere: ${escapeHtml(user.discountCode)}</div>`
      : user.role === "admin"
      ? `<div class="pill">Admin: poți încărca CSV și gestiona datele</div>`
      : "";

  const uploadBox =
    user.role === "admin"
      ? `
<div class="card">
  <h3>Încarcă CSV (Shopify Orders export)</h3>
  <div class="muted">Încarcă exportul de comenzi din Shopify. Datele se păstrează în memorie cât rulează instanța.</div>

  <form method="post" action="/upload" enctype="multipart/form-data" style="margin-top:12px">
    <div class="row">
      <input type="file" name="file" accept=".csv,text/csv" required />
      <button class="btn primary" type="submit">Upload</button>
    </div>
  </form>

  <div class="footer-note">Tip: dacă nu apar comenzile, verificăm coloanele din CSV (Discount Code, Created at, Total, Name).</div>
</div>
`
      : "";

  const rows =
    data.length === 0
      ? `<tr><td colspan="5" class="muted">Nu există comenzi pentru criteriile selectate.</td></tr>`
      : data
          .slice(0, 500)
          .map(
            (o) => `
<tr>
  <td>${escapeHtml(o.order)}</td>
  <td>${escapeHtml(o.created)}</td>
  <td>${escapeHtml(o.status)}</td>
  <td>${escapeHtml(o.discount || "")}</td>
  <td>${escapeHtml(String(o.total))}</td>
</tr>`
          )
          .join("");

  const body = `
<div class="grid">
  <div class="card">
    <h3>Raport</h3>
    ${codPill}

    <form method="get" action="/dashboard" style="margin-top:12px">
      <div class="row">
        <div style="flex:1;min-width:190px">
          <label>De la</label>
          <input type="date" name="from" value="${escapeHtml(req.query.from || "")}" />
        </div>
        <div style="flex:1;min-width:190px">
          <label>Până la</label>
          <input type="date" name="to" value="${escapeHtml(req.query.to || "")}" />
        </div>
        <div style="align-self:flex-end">
          <button class="btn" type="submit">Aplică filtru</button>
        </div>
      </div>
    </form>

    <div class="stats">
      <div class="stat">
        <div class="k">Comenzi</div>
        <div class="v">${data.length}</div>
      </div>
      <div class="stat">
        <div class="k">Total vânzări (din CSV)</div>
        <div class="v">${total.toFixed(2)}</div>
      </div>
      <div class="stat">
        <div class="k">Comision (10%)</div>
        <div class="v">${commission.toFixed(2)}</div>
      </div>
    </div>
  </div>

  ${uploadBox}
</div>

<div class="card" style="margin-top:14px">
  <h3>Comenzi (max 500 afișate)</h3>
  <table>
    <tr>
      <th>Order</th>
      <th>Created</th>
      <th>Status</th>
      <th>Discount</th>
      <th>Total</th>
    </tr>
    ${rows}
  </table>
</div>
`;

  res.send(layout("Dashboard", body, user));
});

/* ================= CSV UPLOAD (ADMIN only) ================= */

app.post("/upload", requireAuth, upload.single("file"), (req, res) => {
  const user = req.session.user;
  if (user.role !== "admin") return res.sendStatus(403);

  try {
    const content = fs.readFileSync(req.file.path);
    fs.unlinkSync(req.file.path);

    const records = parse(content, { columns: true, skip_empty_lines: true });

    // Shopify Orders export: typical columns: Name, Created at, Financial Status, Discount Code, Total
    ORDERS = records.map((r) => ({
      order: r["Name"] || r["Order"] || "",
      created: r["Created at"] || r["Created"] || r["Created At"] || "",
      status: r["Financial Status"] || r["Status"] || "",
      discount: (r["Discount Code"] || r["Discount"] || "").trim(),
      total: toNumber(r["Total"] || r["Total price"] || r["Current total price"] || 0),
    }));

    res.redirect("/dashboard");
  } catch (e) {
    console.error("CSV upload error:", e);
    res.status(400).send(layout("Eroare", `<div class="card"><h3>Eroare la CSV</h3><div class="danger">${escapeHtml(e.message)}</div><a class="btn" href="/dashboard">Înapoi</a></div>`, req.session.user));
  }
});

/* ================= START ================= */

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("Server running on", PORT));
