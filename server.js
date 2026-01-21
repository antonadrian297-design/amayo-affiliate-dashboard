const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const fs = require("fs");
const csv = require("csv-parse/sync");

const app = express();
const upload = multer({ dest: "/tmp" });

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: "amayo-secret",
    resave: false,
    saveUninitialized: false,
  })
);

/* ================= USERS ================= */

const USERS = {
  admin: {
    username: "amayo",
    password: bcrypt.hashSync("amayoadmin", 10),
    role: "admin",
  },
  sorina: {
    username: "sorinamincu",
    password: bcrypt.hashSync("amayoSorina", 10),
    role: "affiliate",
    discountCode: "stiudelasorina",
  },
};

/* ================= STORAGE ================= */

let ORDERS = [];

/* ================= AUTH ================= */

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

/* ================= UI ================= */

function pageLayout(title, body) {
  return `
<!doctype html>
<html>
<head>
<title>${title}</title>
<meta name="viewport" content="width=device-width, initial-scale=1" />
<style>
${require("fs").readFileSync(__filename, "utf8").split("/* CSS */")[1]}
</style>
</head>
<body>
<div class="container">${body}</div>
</body>
</html>`;
}

/* CSS */
`
/* ================= ROUTES ================= */

app.get("/", (req, res) => res.redirect("/login"));

app.get("/login", (req, res) => {
  res.send(
    pageLayout(
      "Login",
      `
<div class="center-wrap">
  <div class="login-card">
    <h2>Login</h2>
    <form method="post">
      <label>Email / User</label>
      <input name="username" required />
      <label>Parolă</label>
      <input type="password" name="password" required />
      <br/><br/>
      <button>Intră</button>
      ${req.query.err ? `<div class="danger">Date incorecte</div>` : ""}
    </form>
  </div>
</div>
`
    )
  );
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = Object.values(USERS).find((u) => u.username === username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.redirect("/login?err=1");
  }
  req.session.user = user;
  res.redirect("/dashboard");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

/* ================= DASHBOARD ================= */

app.get("/dashboard", requireAuth, (req, res) => {
  const user = req.session.user;

  const from = req.query.from ? new Date(req.query.from) : null;
  const to = req.query.to ? new Date(req.query.to) : null;

  let data = ORDERS;

  if (user.role === "affiliate") {
    data = data.filter(
      (o) =>
        o.discount &&
        o.discount.toLowerCase() === user.discountCode.toLowerCase()
    );
  }

  if (from) data = data.filter((o) => new Date(o.created) >= from);
  if (to) data = data.filter((o) => new Date(o.created) <= to);

  const total = data.reduce((s, o) => s + o.total, 0);
  const commission = total * 0.1;

  res.send(
    pageLayout(
      "Dashboard",
      `
<div class="topbar">
  <h2>Dashboard afiliat</h2>
  <a class="btn-ghost" href="/logout">Logout</a>
</div>

${user.role === "affiliate" ? `<div class="pill">Cod: ${user.discountCode}</div>` : ""}

<form method="get">
  <input type="date" name="from" />
  <input type="date" name="to" />
  <button>Aplică filtru</button>
</form>

<div class="stats">
  <div class="stat"><div class="label">Comenzi</div><div class="value">${data.length}</div></div>
  <div class="stat"><div class="label">Total vânzări</div><div class="value">${total.toFixed(
    2
  )}</div></div>
  <div class="stat"><div class="label">Comision 10%</div><div class="value">${commission.toFixed(
    2
  )}</div></div>
</div>

${
  user.role === "admin"
    ? `
<div class="card">
<h3>Încarcă CSV Shopify</h3>
<form method="post" action="/upload" enctype="multipart/form-data">
  <input type="file" name="file" required />
  <button>Upload</button>
</form>
</div>
`
    : ""
}

<h3>Comenzi</h3>
<table>
<tr><th>Order</th><th>Data</th><th>Status</th><th>Discount</th><th>Total</th></tr>
${data
  .slice(0, 500)
  .map(
    (o) =>
      `<tr><td>${o.order}</td><td>${o.created}</td><td>${o.status}</td><td>${o.discount}</td><td>${o.total}</td></tr>`
  )
  .join("")}
</table>
`
    )
  );
});

/* ================= CSV ================= */

app.post("/upload", requireAuth, upload.single("file"), (req, res) => {
  if (req.session.user.role !== "admin") return res.sendStatus(403);

  const content = fs.readFileSync(req.file.path);
  const rows = csv.parse(content, { columns: true });

  ORDERS = rows.map((r) => ({
    order: r["Name"] || "",
    created: r["Created at"] || "",
    status: r["Financial Status"] || "",
    discount: (r["Discount Code"] || "").trim(),
    total: parseFloat(r["Total"] || 0),
  }));

  res.redirect("/dashboard");
});

/* ================= START ================= */

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log("Server running on", PORT));
