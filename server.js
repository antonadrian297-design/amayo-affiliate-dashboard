const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const { parse } = require("csv-parse");

const app = express();
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "change-me",
    resave: false,
    saveUninitialized: false,
  })
);

// ======= CONFIG =======
const AFFILIATE_CODE = "stiudelasorina"; // codul tău
const COMMISSION_RATE = 0.10;

// Login afiliat (demo) — schimbă ulterior cu DB
const USERS = [
  // parola: "parola123" (hash generat)
  { email: "afiliat@amayo.ro", passHash: bcrypt.hashSync("parola123", 10) },
];

// ======= AUTH MIDDLEWARE =======
function requireAuth(req, res, next) {
  if (req.session?.user) return next();
  res.redirect("/login");
}

// ======= PAGES =======
app.get("/", (req, res) => {
  if (!req.session.user) return res.redirect("/login");
  res.redirect("/dashboard");
});

app.get("/login", (req, res) => {
  res.send(`
    <html><head><meta name="viewport" content="width=device-width, initial-scale=1" /></head>
    <body style="font-family:Arial; padding:24px; max-width:420px; margin:auto;">
      <h2>Login afiliat</h2>
      <form method="POST" action="/login">
        <label>Email</label><br/>
        <input name="email" type="email" required style="width:100%; padding:12px; margin:8px 0;" />
        <label>Parolă</label><br/>
        <input name="password" type="password" required style="width:100%; padding:12px; margin:8px 0;" />
        <button type="submit" style="width:100%; padding:12px; font-weight:700;">Intră</button>
      </form>
      <p style="color:#666; margin-top:14px;">
        Demo: afiliat@amayo.ro / parola123
      </p>
    </body></html>
  `);
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const user = USERS.find((u) => u.email.toLowerCase() === String(email).toLowerCase());
  if (!user) return res.status(401).send("Email sau parolă greșită. <a href='/login'>Înapoi</a>");

  const ok = bcrypt.compareSync(password, user.passHash);
  if (!ok) return res.status(401).send("Email sau parolă greșită. <a href='/login'>Înapoi</a>");

  req.session.user = { email: user.email };
  res.redirect("/dashboard");
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

app.get("/dashboard", requireAuth, (req, res) => {
  res.send(`
    <html><head><meta name="viewport" content="width=device-width, initial-scale=1" /></head>
    <body style="font-family:Arial; padding:24px; max-width:900px; margin:auto;">
      <div style="display:flex; justify-content:space-between; align-items:center; gap:12px;">
        <h2>Dashboard afiliat</h2>
        <form method="POST" action="/logout"><button>Logout</button></form>
      </div>

      <p>Încarcă CSV-ul exportat din Shopify (Orders).</p>

      <form method="POST" action="/upload" enctype="multipart/form-data" style="padding:16px; border:1px solid #ddd; border-radius:12px;">
        <input type="file" name="csv" accept=".csv,text/csv" required />
        <button type="submit" style="margin-left:10px; padding:10px 16px; font-weight:700;">Generează raport</button>
        <div style="margin-top:10px; color:#666; font-size:14px;">
          Reguli: cod <b>${AFFILIATE_CODE}</b> (nu contează litere mari/mici), doar comenzi <b>executate</b>, fără rambursări, fără anulări. Comision: <b>${COMMISSION_RATE * 100}%</b> din Total.
        </div>
      </form>

      <div style="margin-top:18px; color:#666;">
        După upload, vei vedea totalul vânzărilor + comisionul și lista comenzilor eligibile.
      </div>
    </body></html>
  `);
});

// ======= CSV UPLOAD =======
const upload = multer({ storage: multer.memoryStorage() });

function normalize(str) {
  return String(str ?? "").trim();
}

function toLower(str) {
  return normalize(str).toLowerCase();
}

function parseMoney(value) {
  // Acceptă "142.20", "142,20", "142.2 RON"
  const s = normalize(value).replace(/[^\d,.\-]/g, "");
  if (!s) return 0;
  // dacă are virgulă și nu are punct -> interpretăm virgulă ca zecimal
  if (s.includes(",") && !s.includes(".")) return parseFloat(s.replace(",", ".")) || 0;
  // dacă are și punct și virgulă, eliminăm mii (virgulă) și păstrăm punct
  if (s.includes(",") && s.includes(".")) return parseFloat(s.replace(/,/g, "")) || 0;
  return parseFloat(s) || 0;
}

function pick(obj, keys) {
  for (const k of keys) {
    if (obj[k] !== undefined) return obj[k];
  }
  return "";
}

function looksFulfilled(v) {
  const s = toLower(v);
  // Shopify CSV: "fulfilled", "partial", "unfulfilled"
  // română uneori: "executată"
  return s.includes("fulfilled") || s.includes("executat") || s.includes("executată") || s.includes("executata");
}

function looksRefunded(v) {
  const s = toLower(v);
  return s.includes("refunded") || s.includes("ramburs") || s.includes("partially_refunded") || s.includes("partial refund");
}

function isCancelled(v) {
  // Cancelled at / Canceled at poate fi dată sau gol
  return normalize(v) !== "";
}

app.post("/upload", requireAuth, upload.single("csv"), (req, res) => {
  if (!req.file?.buffer) return res.status(400).send("Nu am primit fișierul CSV.");

  const rows = [];
  parse(req.file.buffer, { columns: true, skip_empty_lines: true }, (err, records) => {
    if (err) return res.status(400).send("CSV invalid. Încearcă exportul Shopify Orders CSV.");

    // Detectăm coloane “probabile”
    // (Shopify poate avea nume ușor diferite în funcție de export)
    const eligibleOrders = [];

    for (const r of records) {
      // încercăm multiple variante de titluri
      const orderName = pick(r, ["Name", "Order", "Număr", "Numar", "Order Name"]);
      const createdAt = pick(r, ["Created at", "Created At", "Data", "Date"]);
      const email = pick(r, ["Email", "Customer Email", "Email client"]);
      const discountCode = pick(r, ["Discount Code", "Discount code", "Cod reducere", "Cod discount"]);
      const total = pick(r, ["Total", "Total (incl tax)", "Total Price", "Total (RON)"]);
      const fulfillmentStatus = pick(r, ["Fulfillment Status", "Status îndeplinire", "Status indeplinire"]);
      const financialStatus = pick(r, ["Financial Status", "Status financiar", "Status plata"]);
      const cancelledAt = pick(r, ["Cancelled at", "Canceled at", "Anulat la", "Anulata la"]);

      const codeOk = toLower(discountCode) === AFFILIATE_CODE.toLowerCase();
      const fulfilledOk = looksFulfilled(fulfillmentStatus);
      const refundedNo = !looksRefunded(financialStatus);
      const cancelledNo = !isCancelled(cancelledAt);

      if (codeOk && fulfilledOk && refundedNo && cancelledNo) {
        const totalNum = parseMoney(total);
        const commission = +(totalNum * COMMISSION_RATE).toFixed(2);

        eligibleOrders.push({
          order: normalize(orderName),
          createdAt: normalize(createdAt),
          email: normalize(email),
          total: totalNum,
          commission,
          fulfillmentStatus: normalize(fulfillmentStatus),
          financialStatus: normalize(financialStatus),
        });
      }
    }

    // calcule
    const count = eligibleOrders.length;
    const sales = eligibleOrders.reduce((s, o) => s + (o.total || 0), 0);
    const comm = eligibleOrders.reduce((s, o) => s + (o.commission || 0), 0);

    // tabel HTML
    const rowsHtml = eligibleOrders
      .sort((a, b) => (a.order > b.order ? -1 : 1))
      .map(
        (o) => `
        <tr>
          <td style="padding:8px; border-bottom:1px solid #eee;">${o.order}</td>
          <td style="padding:8px; border-bottom:1px solid #eee;">${o.createdAt}</td>
          <td style="padding:8px; border-bottom:1px solid #eee;">${o.email}</td>
          <td style="padding:8px; border-bottom:1px solid #eee; text-align:right;">${o.total.toFixed(2)} lei</td>
          <td style="padding:8px; border-bottom:1px solid #eee; text-align:right;"><b>${o.commission.toFixed(2)} lei</b></td>
        </tr>
      `
      )
      .join("");

    res.send(`
      <html><head><meta name="viewport" content="width=device-width, initial-scale=1" /></head>
      <body style="font-family:Arial; padding:24px; max-width:1000px; margin:auto;">
        <div style="display:flex; justify-content:space-between; align-items:center; gap:12px;">
          <h2>Raport afiliat — ${AFFILIATE_CODE}</h2>
          <div style="display:flex; gap:10px;">
            <a href="/dashboard">Înapoi</a>
            <form method="POST" action="/logout"><button>Logout</button></form>
          </div>
        </div>

        <div style="display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:12px; margin:16px 0;">
          <div style="padding:14px; border:1px solid #ddd; border-radius:12px;">
            <div style="color:#666; font-size:13px;">Comenzi eligibile</div>
            <div style="font-size:28px; font-weight:800;">${count}</div>
          </div>
          <div style="padding:14px; border:1px solid #ddd; border-radius:12px;">
            <div style="color:#666; font-size:13px;">Vânzări totale (Total)</div>
            <div style="font-size:28px; font-weight:800;">${sales.toFixed(2)} lei</div>
          </div>
          <div style="padding:14px; border:1px solid #ddd; border-radius:12px;">
            <div style="color:#666; font-size:13px;">Comision (${COMMISSION_RATE * 100}%)</div>
            <div style="font-size:28px; font-weight:800;">${comm.toFixed(2)} lei</div>
          </div>
        </div>

        <div style="overflow:auto; border:1px solid #ddd; border-radius:12px;">
          <table style="width:100%; border-collapse:collapse;">
            <thead>
              <tr>
                <th style="text-align:left; padding:10px; border-bottom:1px solid #ddd;">Comandă</th>
                <th style="text-align:left; padding:10px; border-bottom:1px solid #ddd;">Data</th>
                <th style="text-align:left; padding:10px; border-bottom:1px solid #ddd;">Email</th>
                <th style="text-align:right; padding:10px; border-bottom:1px solid #ddd;">Total</th>
                <th style="text-align:right; padding:10px; border-bottom:1px solid #ddd;">Comision</th>
              </tr>
            </thead>
            <tbody>
              ${rowsHtml || `<tr><td colspan="5" style="padding:14px;">Nu am găsit comenzi eligibile în CSV (cod + executată + fără rambursări/anulări).</td></tr>`}
            </tbody>
          </table>
        </div>

        <p style="color:#666; margin-top:14px;">
          Notă: “Total” este luat din CSV ca valoare finală. Dacă vrei să includem explicit transport (când există) sau să calculăm din alte coloane, ajustăm ușor.
        </p>
      </body></html>
    `);
  });
});

// ======= RUN =======
const port = process.env.PORT || 3000;
app.listen(port, () => console.log("Server running on", port));
