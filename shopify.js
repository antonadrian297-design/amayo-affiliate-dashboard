const API_VERSION = process.env.SHOPIFY_API_VERSION || "2024-01";
const SHOP = process.env.SHOPIFY_SHOP; // ex: p1dbdq-34.myshopify.com
const TOKEN = process.env.SHOPIFY_ACCESS_TOKEN;

function mustEnv() {
  if (!SHOP || !TOKEN) {
    throw new Error("Missing SHOPIFY_SHOP or SHOPIFY_ACCESS_TOKEN");
  }
}

function isoDaysAgo(days) {
  const d = new Date();
  d.setDate(d.getDate() - days);
  return d.toISOString();
}

function getNextPageInfo(linkHeader) {
  if (!linkHeader) return null;
  // Link: <...page_info=XYZ...>; rel="next"
  const parts = linkHeader.split(",");
  for (const p of parts) {
    if (p.includes('rel="next"')) {
      const m = p.match(/<([^>]+)>/);
      if (!m) return null;
      const url = new URL(m[1]);
      return url.searchParams.get("page_info");
    }
  }
  return null;
}

async function shopifyGet(path) {
  mustEnv();
  const url = `https://${SHOP}${path}`;
  const res = await fetch(url, {
    headers: {
      "X-Shopify-Access-Token": TOKEN,
      "Content-Type": "application/json"
    }
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Shopify error ${res.status}: ${text}`);
  }

  const data = await res.json();
  const link = res.headers.get("link");
  return { data, link };
}

/**
 * Returnează toate comenzile (status=any) pe ultimele N zile, cu paginare.
 */
async function fetchOrdersLastDays(days) {
  const created_at_min = encodeURIComponent(isoDaysAgo(days));
  let pageInfo = null;
  let all = [];

  while (true) {
    const base = `/admin/api/${API_VERSION}/orders.json?status=any&limit=250&created_at_min=${created_at_min}&fields=id,name,created_at,total_price,currency,discount_codes,financial_status,fulfillment_status,cancelled_at,customer`;
    const path = pageInfo ? `${base}&page_info=${pageInfo}` : base;

    const { data, link } = await shopifyGet(path);
    const orders = data.orders || [];
    all = all.concat(orders);

    pageInfo = getNextPageInfo(link);
    if (!pageInfo) break;
  }

  return all;
}

function hasDiscountCode(order, code) {
  const target = (code || "").trim().toLowerCase();
  const codes = order.discount_codes || [];
  return codes.some((c) => (c.code || "").trim().toLowerCase() === target);
}

function isRefunded(order) {
  // simplu pentru început: excludem refunded / voided
  const st = (order.financial_status || "").toLowerCase();
  return st === "refunded" || st === "voided";
}

function formatDateRo(iso) {
  const d = new Date(iso);
  return d.toLocaleString("ro-RO", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

function getCustomerName(order) {
  const c = order.customer;
  if (!c) return "";
  return [c.first_name, c.last_name].filter(Boolean).join(" ").trim();
}

/**
 * Reguli cerute:
 * - cod: stiudelasorina (case-insensitive)
 * - eligibil dacă fulfillment_status == "fulfilled" (Executat în Shopify)
 * - excludem comenzi anulate (cancelled_at)
 * - excludem rambursate (financial_status refunded/voided)
 * - comision: 10% din totalul final plătit (total_price), după reducere, include transport dacă e în total
 */
async function fetchAffiliateOrders({ code, rate, days }) {
  const orders = await fetchOrdersLastDays(days);

  const filtered = orders
    .filter((o) => !o.cancelled_at)
    .filter((o) => hasDiscountCode(o, code))
    .filter((o) => !isRefunded(o));

  const currency = filtered[0]?.currency || "RON";

  const mapped = filtered.map((o) => {
    const total = Number(o.total_price || 0);
    const eligible = (o.fulfillment_status || "").toLowerCase() === "fulfilled";

    return {
      id: o.id,
      name: o.name,
      date: formatDateRo(o.created_at),
      customer: getCustomerName(o),
      total,
      commission: eligible ? total * rate : 0,
      eligible,
      fulfillmentStatus: o.fulfillment_status || "-",
      financialStatus: o.financial_status || "-"
    };
  });

  const totalRevenue = mapped.reduce((s, o) => s + o.total, 0);
  const totalCommission = mapped.reduce((s, o) => s + o.commission, 0);

  // Sort newest first
  mapped.sort((a, b) => (a.date < b.date ? 1 : -1));

  return {
    currency,
    orders: mapped,
    totalRevenue,
    totalCommission
  };
}

module.exports = { fetchAffiliateOrders };
