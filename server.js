const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

if (!DATABASE_URL) { console.error("Missing DATABASE_URL"); process.exit(1); }
if (!JWT_SECRET) { console.error("Missing JWT_SECRET"); process.exit(1); }

const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      account_code VARCHAR(30) UNIQUE NOT NULL,
      display_name VARCHAR(100) NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) DEFAULT 'user',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS user_data (
      id SERIAL PRIMARY KEY,
      user_id INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      learned JSONB DEFAULT '[]',
      favorites JSONB DEFAULT '[]',
      progress JSONB DEFAULT '{}',
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS invite_codes (
      id SERIAL PRIMARY KEY,
      code VARCHAR(40) UNIQUE NOT NULL,
      created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      max_uses INTEGER NOT NULL DEFAULT 1 CHECK (max_uses >= 0),
      uses INTEGER NOT NULL DEFAULT 0 CHECK (uses >= 0),
      expires_at TIMESTAMP NULL,
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_invite_codes_code ON invite_codes(code);
  `);
  console.log("Database initialized");
}

function generateAccountCode() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let result = "HS4-";
  for (let i = 0; i < 6; i++) result += chars[Math.floor(Math.random() * chars.length)];
  return result;
}

function generateInviteCode() {
  return "KT-" + crypto.randomBytes(8).toString("hex").toUpperCase();
}

function createToken(user) {
  return jwt.sign({ id: user.id, accountCode: user.account_code, role: user.role }, JWT_SECRET, { expiresIn: "30d" });
}

function auth(req, res, next) {
  try {
    const header = req.headers.authorization;
    if (!header || !header.startsWith("Bearer ")) return res.status(401).json({ success: false, message: "Chưa đăng nhập" });
    req.user = jwt.verify(header.substring(7), JWT_SECRET);
    next();
  } catch { return res.status(401).json({ success: false, message: "Phiên đăng nhập không hợp lệ" }); }
}

function adminAuth(req, res, next) {
  auth(req, res, () => {
    if (req.user.role !== "admin") return res.status(403).json({ success: false, message: "Không có quyền admin" });
    next();
  });
}

app.get("/", (req, res) => res.json({ success: true, message: "开心 HSK Server đang hoạt động!", version: "2.2.0" }));

app.get("/api/health", async (req, res) => {
  try { await pool.query("SELECT 1"); res.json({ success: true, status: "online", database: "connected" }); }
  catch (error) { console.error(error); res.status(500).json({ success: false, status: "online", database: "error" }); }
});

// REGISTER: only an active invite code created by an admin can be used.
app.post("/api/register", async (req, res) => {
  const client = await pool.connect();
  try {
    const { displayName, password, inviteCode } = req.body;
    if (!displayName || !password || !inviteCode) return res.status(400).json({ success: false, message: "Thiếu tên, mật khẩu hoặc mã mời" });
    if (String(displayName).trim().length < 1) return res.status(400).json({ success: false, message: "Tên hiển thị không hợp lệ" });
    if (password.length < 4) return res.status(400).json({ success: false, message: "Mật khẩu phải có ít nhất 4 ký tự" });

    await client.query("BEGIN");
    const inviteResult = await client.query(
      `SELECT id, code, max_uses, uses, expires_at, active FROM invite_codes WHERE code = $1 FOR UPDATE`,
      [String(inviteCode).trim().toUpperCase()]
    );
    if (inviteResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(403).json({ success: false, message: "Mã mời không tồn tại hoặc chưa được cấp" });
    }
    const invite = inviteResult.rows[0];
    const expired = invite.expires_at && new Date(invite.expires_at) <= new Date();
    const exhausted = Number(invite.max_uses) > 0 && Number(invite.uses) >= Number(invite.max_uses);
    if (!invite.active || expired || exhausted) {
      await client.query("ROLLBACK");
      return res.status(403).json({ success: false, message: !invite.active ? "Mã mời đã bị khóa" : expired ? "Mã mời đã hết hạn" : "Mã mời đã hết lượt sử dụng" });
    }

    let accountCode;
    for (;;) {
      accountCode = generateAccountCode();
      const check = await client.query("SELECT id FROM users WHERE account_code = $1", [accountCode]);
      if (check.rows.length === 0) break;
    }
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await client.query(
      `INSERT INTO users (account_code, display_name, password_hash) VALUES ($1, $2, $3) RETURNING id, account_code, display_name, role`,
      [accountCode, String(displayName).trim(), passwordHash]
    );
    const user = result.rows[0];
    await client.query(`INSERT INTO user_data (user_id, learned, favorites, progress) VALUES ($1, '[]', '[]', '{}')`, [user.id]);
    await client.query(`UPDATE invite_codes SET uses = uses + 1, updated_at = CURRENT_TIMESTAMP WHERE id = $1`, [invite.id]);
    await client.query("COMMIT");

    res.json({ success: true, message: "Tạo tài khoản thành công", user: { accountCode: user.account_code, displayName: user.display_name, role: user.role }, token: createToken(user) });
  } catch (error) {
    try { await client.query("ROLLBACK"); } catch {}
    console.error(error);
    res.status(500).json({ success: false, message: "Không thể tạo tài khoản" });
  } finally { client.release(); }
});

app.post("/api/login", async (req, res) => {
  try {
    const { accountCode, password } = req.body;
    if (!accountCode || !password) return res.status(400).json({ success: false, message: "Thiếu mã tài khoản hoặc mật khẩu" });
    const result = await pool.query("SELECT * FROM users WHERE account_code = $1", [String(accountCode).trim().toUpperCase()]);
    if (result.rows.length === 0) return res.status(401).json({ success: false, message: "Sai tài khoản hoặc mật khẩu" });
    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ success: false, message: "Sai tài khoản hoặc mật khẩu" });
    res.json({ success: true, user: { accountCode: user.account_code, displayName: user.display_name, role: user.role }, token: createToken(user) });
  } catch (error) { console.error(error); res.status(500).json({ success: false, message: "Lỗi đăng nhập" }); }
});

app.post("/api/reset-password", async (req, res) => {
  try {
    const { accountCode, inviteCode, newPassword } = req.body;
    if (!accountCode || !inviteCode || !newPassword) return res.status(400).json({ success: false, message: "Thiếu thông tin" });
    if (newPassword.length < 4) return res.status(400).json({ success: false, message: "Mật khẩu phải có ít nhất 4 ký tự" });
    const invite = await pool.query(`SELECT id, active, max_uses, uses, expires_at FROM invite_codes WHERE code = $1`, [String(inviteCode).trim().toUpperCase()]);
    if (!invite.rows.length) return res.status(403).json({ success: false, message: "Mã xác nhận không tồn tại" });
    const i = invite.rows[0];
    const expired = i.expires_at && new Date(i.expires_at) <= new Date();
    const exhausted = Number(i.max_uses) > 0 && Number(i.uses) >= Number(i.max_uses);
    if (!i.active || expired || exhausted) return res.status(403).json({ success: false, message: "Mã xác nhận không còn hiệu lực" });
    const passwordHash = await bcrypt.hash(newPassword, 12);
    const result = await pool.query(`UPDATE users SET password_hash = $1, updated_at = CURRENT_TIMESTAMP WHERE account_code = $2 RETURNING id`, [passwordHash, String(accountCode).trim().toUpperCase()]);
    if (!result.rows.length) return res.status(404).json({ success: false, message: "Không tìm thấy tài khoản" });
    res.json({ success: true, message: "Đổi mật khẩu thành công" });
  } catch (error) { console.error(error); res.status(500).json({ success: false, message: "Không thể đổi mật khẩu" }); }
});

app.get("/api/me/data", auth, async (req, res) => {
  try {
    const result = await pool.query(`SELECT learned, favorites, progress FROM user_data WHERE user_id = $1`, [req.user.id]);
    if (!result.rows.length) return res.status(404).json({ success: false, message: "Không tìm thấy dữ liệu" });
    res.json({ success: true, data: result.rows[0] });
  } catch (error) { console.error(error); res.status(500).json({ success: false, message: "Không thể lấy dữ liệu" }); }
});

app.put("/api/me/data", auth, async (req, res) => {
  try {
    const { learned = [], favorites = [], progress = {} } = req.body;
    await pool.query(
      `INSERT INTO user_data (user_id, learned, favorites, progress) VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id) DO UPDATE SET learned = EXCLUDED.learned, favorites = EXCLUDED.favorites, progress = EXCLUDED.progress, updated_at = CURRENT_TIMESTAMP`,
      [req.user.id, JSON.stringify(learned), JSON.stringify(favorites), JSON.stringify(progress)]
    );
    res.json({ success: true, message: "Đã lưu dữ liệu" });
  } catch (error) { console.error(error); res.status(500).json({ success: false, message: "Không thể lưu dữ liệu" }); }
});

app.get("/api/admin/users", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(`SELECT id, account_code, display_name, role, created_at, updated_at FROM users ORDER BY created_at DESC`);
    res.json({ success: true, users: result.rows });
  } catch (error) { console.error(error); res.status(500).json({ success: false, message: "Không thể lấy danh sách tài khoản" }); }
});

// ADMIN INVITE CODES
app.post("/api/admin/invite-codes", adminAuth, async (req, res) => {
  try {
    const maxUses = Number.isInteger(Number(req.body.maxUses)) && Number(req.body.maxUses) >= 0 ? Number(req.body.maxUses) : 1;
    const days = Number.isInteger(Number(req.body.expiresInDays)) && Number(req.body.expiresInDays) >= 0 ? Number(req.body.expiresInDays) : 7;
    let code;
    for (;;) {
      code = generateInviteCode();
      const exists = await pool.query("SELECT id FROM invite_codes WHERE code = $1", [code]);
      if (!exists.rows.length) break;
    }
    const expiresAt = days === 0 ? null : new Date(Date.now() + days * 86400000);
    const result = await pool.query(
      `INSERT INTO invite_codes (code, created_by, max_uses, expires_at) VALUES ($1, $2, $3, $4)
       RETURNING id, code, max_uses, uses, expires_at, active, created_at`,
      [code, req.user.id, maxUses, expiresAt]
    );
    res.json({ success: true, message: "Đã tạo mã mời", invite: result.rows[0] });
  } catch (error) { console.error(error); res.status(500).json({ success: false, message: "Không thể tạo mã mời" }); }
});

app.get("/api/admin/invite-codes", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(`SELECT id, code, max_uses, uses, expires_at, active, created_at, updated_at FROM invite_codes ORDER BY created_at DESC`);
    res.json({ success: true, invites: result.rows });
  } catch (error) { console.error(error); res.status(500).json({ success: false, message: "Không thể lấy danh sách mã mời" }); }
});

app.delete("/api/admin/invite-codes/:id", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(`UPDATE invite_codes SET active = FALSE, updated_at = CURRENT_TIMESTAMP WHERE id = $1 RETURNING id`, [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ success: false, message: "Không tìm thấy mã mời" });
    res.json({ success: true, message: "Đã khóa mã mời" });
  } catch (error) { console.error(error); res.status(500).json({ success: false, message: "Không thể khóa mã mời" }); }
});

app.put("/api/admin/users/:id/reset-data", adminAuth, async (req, res) => {
  try {
    await pool.query(`INSERT INTO user_data (user_id, learned, favorites, progress) VALUES ($1, '[]', '[]', '{}') ON CONFLICT (user_id) DO UPDATE SET learned='[]', favorites='[]', progress='{}', updated_at=CURRENT_TIMESTAMP`, [req.params.id]);
    res.json({ success: true, message: "Đã reset dữ liệu người dùng" });
  } catch (error) { console.error(error); res.status(500).json({ success: false, message: "Không thể reset dữ liệu" }); }
});

app.delete("/api/admin/users/:id", adminAuth, async (req, res) => {
  try {
    if (Number(req.params.id) === Number(req.user.id)) return res.status(400).json({ success: false, message: "Không thể tự xoá tài khoản admin đang đăng nhập" });
    const result = await pool.query("DELETE FROM users WHERE id = $1 RETURNING id", [req.params.id]);
    if (!result.rows.length) return res.status(404).json({ success: false, message: "Không tìm thấy tài khoản" });
    res.json({ success: true, message: "Đã xoá tài khoản" });
  } catch (error) { console.error(error); res.status(500).json({ success: false, message: "Không thể xoá tài khoản" }); }
});

initDatabase().then(() => app.listen(PORT, "0.0.0.0", () => console.log(`开心 HSK Server running on port ${PORT}`))).catch(error => { console.error("Database initialization failed:", error); process.exit(1); });
