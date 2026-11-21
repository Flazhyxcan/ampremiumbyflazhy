const express = require("express");
const crypto = require("crypto");
const path = require("path");

const E = process.env;
const SECRET = E.SESSION_SECRET || "dev-secret";
const CREDITS = +E.DAILY_CREDITS || 3;
const DAY_S = 86400;
const RURL = E.UPSTASH_REDIS_REST_URL || E.KV_REST_API_URL;
const RTOK = E.UPSTASH_REDIS_REST_TOKEN || E.KV_REST_API_TOKEN;

// Redis (Upstash REST) — data tetap ada di Vercel serverless
const R = async (...cmd) => {
  const r = await fetch(RURL, { method: "POST", headers: { Authorization: "Bearer " + RTOK }, body: JSON.stringify(cmd) });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
};

const hash = (pw, salt = crypto.randomBytes(16).toString("hex")) => salt + ":" + crypto.scryptSync(pw, salt, 32).toString("hex");
const check = (pw, h) => crypto.timingSafeEqual(Buffer.from(hash(pw, h.split(":")[0])), Buffer.from(h));
const sign = u => { const p = Buffer.from(JSON.stringify({ u, t: Date.now() })).toString("base64url"); return p + "." + crypto.createHmac("sha256", SECRET).update(p).digest("base64url"); };
const unsign = tok => { if (!tok) return null; const [p, s] = tok.split("."); if (!s || s !== crypto.createHmac("sha256", SECRET).update(p).digest("base64url")) return null; const d = JSON.parse(Buffer.from(p, "base64url")); return Date.now() - d.t < 7 * DAY_S * 1000 ? d.u : null; };
const ipOf = req => (String(req.headers["cf-connecting-ip"] || (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.headers["x-real-ip"] || req.socket.remoteAddress || "").replace("::ffff:", "").replace(/[^0-9a-fA-F:.]/g, "").slice(0, 45)) || "unknown";
const DUMMY = hash("dummy-password");
const str = (v, max) => typeof v === "string" && v.length <= max;

// Kredit: key dengan TTL 24 jam -> reset otomatis, atomic (anti spam paralel)
const ensure = k => R("SET", k, CREDITS, "EX", DAY_S, "NX");
async function spend(k) { await ensure(k); const n = await R("DECR", k); if (n < 0) { await R("INCR", k); return false; } return true; }
const refund = k => R("INCR", k);
async function view(name, ip) {
  const ku = "cr:u:" + name, ki = "cr:ip:" + ip;
  await Promise.all([ensure(ku), ensure(ki)]);
  const [a, b, ta, tb] = await Promise.all([R("GET", ku), R("GET", ki), R("TTL", ku), R("TTL", ki)]);
  const cu = +a, ci = +b;
  return { username: name, credits: Math.max(0, Math.min(cu, ci)), resetIn: Math.max(0, (cu < ci ? ta : ci < cu ? tb : Math.max(ta, tb))) * 1000 };
}

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", true);
app.use((req, res, next) => {
  res.set({
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains", "Cache-Control": "no-store",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
  });
  next();
});
app.use(express.json({ limit: "4kb", type: "application/json" }));
app.use(express.static(path.join(__dirname, "..", "public"), { dotfiles: "ignore", index: "index.html" }));

// Anti CSRF: hanya POST dari origin sendiri + header custom
app.use("/api", (req, res, next) => {
  if (req.method !== "POST") return next();
  const o = req.headers.origin;
  try { if (o && new URL(o).host !== req.headers.host) throw 0; } catch { return res.status(403).json({ error: "Akses ditolak." }); }
  if (req.headers["x-requested-with"] !== "am") return res.status(403).json({ error: "Akses ditolak." });
  next();
});

// Rate limit (Redis): per IP dan per username
const limit = (name, max, sec, by = req => ipOf(req)) => async (req, res, next) => {
  try {
    const k = `rl:${name}:${by(req)}`;
    const n = await R("INCR", k);
    if (n === 1) await R("EXPIRE", k, sec);
    if (n > max) return res.status(429).json({ error: "Terlalu banyak percobaan. Coba lagi nanti." });
    next();
  } catch { res.status(500).json({ error: "Server error." }); }
};
app.use("/api", limit("all", 60, 60));
const wrap = fn => (req, res) => fn(req, res).catch(e => { console.error(e); res.status(500).json({ error: "Server error. Cek koneksi database." }); });

const setCookie = (res, n) => res.setHeader("Set-Cookie", `s=${sign(n)}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${7 * DAY_S}`);
const auth = (req, res, next) => {
  const c = (req.headers.cookie || "").split(";").map(s => s.trim()).find(s => s.startsWith("s="));
  const n = unsign(c && c.slice(2));
  if (!n) return res.status(401).json({ error: "Login dulu." });
  req.name = n; req.ip4 = ipOf(req); next();
};

app.post("/api/register", limit("reg", 5, 3600), wrap(async (req, res) => {
  const { username, password } = req.body || {};
  if (!str(username, 40) || !str(password, 128)) return res.status(400).json({ error: "Input tidak valid." });
  const n = username.trim().toLowerCase(), ip = ipOf(req);
  if (!/^[a-z0-9_]{3,20}$/.test(n)) return res.status(400).json({ error: "Username 3-20 karakter: huruf, angka, underscore." });
  if (password.length < 6) return res.status(400).json({ error: "Password minimal 6 karakter." });
  if (await R("SET", "ipacc:" + ip, n, "NX") === null) return res.status(403).json({ error: "Satu IP hanya boleh punya 1 akun. Login ke akun lama lu." });
  if (await R("SET", "user:" + n, JSON.stringify({ pw: hash(password) }), "NX") === null) { await R("DEL", "ipacc:" + ip); return res.status(409).json({ error: "Username sudah dipakai." }); }
  setCookie(res, n); res.json(await view(n, ip));
}));

app.post("/api/login", limit("login", 15, 900), limit("lu", 8, 900, req => String((req.body && req.body.username) || "").toLowerCase().replace(/[^a-z0-9_]/g, "").slice(0, 20)), wrap(async (req, res) => {
  const { username, password } = req.body || {};
  if (!str(username, 40) || !str(password, 128)) return res.status(400).json({ error: "Input tidak valid." });
  const n = username.trim().toLowerCase();
  if (!/^[a-z0-9_]{3,20}$/.test(n)) return res.status(401).json({ error: "Username atau password salah." });
  const raw = await R("GET", "user:" + n);
  const good = check(password, raw ? JSON.parse(raw).pw : DUMMY);
  if (!raw || !good) return res.status(401).json({ error: "Username atau password salah." });
  setCookie(res, n); res.json(await view(n, ipOf(req)));
}));

app.post("/api/logout", (req, res) => { res.setHeader("Set-Cookie", "s=; Path=/; Max-Age=0"); res.json({ ok: true }); });
app.get("/api/me", auth, wrap(async (req, res) => res.json(await view(req.name, req.ip4))));

async function gen(url, body) {
  const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json", Accept: "application/json", [E.GENCIPTA_KEY_HEADER || "x-api-key"]: E.GENCIPTA_API_KEY }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  return { ok: r.ok && j.success !== false, j };
}
const okEmail = e => str(e, 254) && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

// Step 1: kirim email verifikasi (1 kredit akun + 1 kredit IP, dikembalikan kalau gagal)
app.post("/api/send", auth, limit("send", 10, 60), wrap(async (req, res) => {
  const email = str(req.body && req.body.email, 254) ? req.body.email.trim() : "";
  if (!okEmail(email)) return res.status(400).json({ error: "Email tidak valid." });
  const ku = "cr:u:" + req.name, ki = "cr:ip:" + req.ip4;
  if (!(await spend(ku))) return res.status(429).json({ error: "Kredit habis. Reset otomatis tiap 24 jam.", ...(await view(req.name, req.ip4)) });
  if (!(await spend(ki))) { await refund(ku); return res.status(429).json({ error: "Kredit IP habis. Reset otomatis tiap 24 jam.", ...(await view(req.name, req.ip4)) }); }
  const back = async msg => { await refund(ku); await refund(ki); res.status(502).json({ error: msg, ...(await view(req.name, req.ip4)) }); };
  try {
    const { ok, j } = await gen(E.GENCIPTA_SEND_URL, { email });
    if (!ok) return back(j.message || j.error || "Gagal kirim email.");
    res.json({ message: j.message || "Link dikirim. Cek inbox / spam.", ...(await view(req.name, req.ip4)) });
  } catch { back("Server API tidak merespons."); }
}));

// Step 2: kirim link / oobCode dari email
app.post("/api/verify", auth, limit("verify", 10, 60), wrap(async (req, res) => {
  const b = req.body || {};
  const email = str(b.email, 254) ? b.email.trim() : "", link = str(b.link, 2048) ? b.link.trim() : "";
  if (!okEmail(email) || !link) return res.status(400).json({ error: "Email dan link verifikasi wajib diisi." });
  try {
    const { ok, j } = await gen(E.GENCIPTA_VERIFY_URL, { email, link });
    if (!ok) return res.status(502).json({ error: j.message || j.error || "Verifikasi gagal." });
    res.json({ message: j.message || "Premium aktif. Buka ulang Alight Motion." });
  } catch { res.status(502).json({ error: "Server API tidak merespons." }); }
}));

// semua route /api lain (termasuk GET langsung) -> 404 polos
app.all("/api/*", (req, res) => res.status(404).json({ error: "Tidak ditemukan." }));
app.use((err, req, res, next) => res.status(err.status === 413 ? 413 : 400).json({ error: "Request tidak valid." }));

if (require.main === module) app.listen(E.PORT || 3000, () => console.log("http://localhost:" + (E.PORT || 3000)));
module.exports = app;
