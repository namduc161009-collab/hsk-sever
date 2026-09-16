const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

if (!DATABASE_URL) {
  console.error("Missing DATABASE_URL");
  process.exit(1);
}

if (!JWT_SECRET) {
  console.error("Missing JWT_SECRET");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// DATABASE
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
  `);

  console.log("Database initialized");
}

// ACCOUNT CODE
function generateAccountCode() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let result = "HS4-";

  for (let i = 0; i < 6; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }

  return result;
}

// TOKEN
function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      accountCode: user.account_code,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: "30d" }
  );
}

// AUTH
function auth(req, res, next) {
  try {
    const header = req.headers.authorization;

    if (!header || !header.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        message: "Chưa đăng nhập"
      });
    }

    const token = header.substring(7);
    req.user = jwt.verify(token, JWT_SECRET);

    next();
  } catch {
    return res.status(401).json({
      success: false,
      message: "Phiên đăng nhập không hợp lệ"
    });
  }
}

// SERVER
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "开心 HSK Server đang hoạt động!",
    version: "2.0.0"
  });
});

// HEALTH
app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      success: true,
      status: "online",
      database: "connected"
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      status: "online",
      database: "error"
    });
  }
});

// REGISTER
app.post("/api/register", async (req, res) => {
  try {
    const { displayName, password } = req.body;

    if (!displayName || !password) {
      return res.status(400).json({
        success: false,
        message: "Thiếu tên hoặc mật khẩu"
      });
    }

    if (password.length < 4) {
      return res.status(400).json({
        success: false,
        message: "Mật khẩu phải có ít nhất 4 ký tự"
      });
    }

    let accountCode;
    let exists = true;

    while (exists) {
      accountCode = generateAccountCode();

      const check = await pool.query(
        "SELECT id FROM users WHERE account_code = $1",
        [accountCode]
      );

      exists = check.rows.length > 0;
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users
       (account_code, display_name, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, account_code, display_name, role`,
      [accountCode, displayName, passwordHash]
    );

    const user = result.rows[0];

    await pool.query(
      `INSERT INTO user_data
       (user_id, learned, favorites, progress)
       VALUES ($1, '[]', '[]', '{}')`,
      [user.id]
    );

    const token = createToken(user);

    res.json({
      success: true,
      message: "Tạo tài khoản thành công",
      user: {
        accountCode: user.account_code,
        displayName: user.display_name,
        role: user.role
      },
      token
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Không thể tạo tài khoản"
    });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  try {
    const { accountCode, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE account_code = $1",
      [accountCode]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        message: "Sai tài khoản hoặc mật khẩu"
      });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        success: false,
        message: "Sai tài khoản hoặc mật khẩu"
      });
    }

    const token = createToken(user);

    res.json({
      success: true,
      user: {
        accountCode: user.account_code,
        displayName: user.display_name,
        role: user.role
      },
      token
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Lỗi đăng nhập"
    });
  }
});

// GET USER DATA
app.get("/api/me/data", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT learned, favorites, progress
       FROM user_data
       WHERE user_id = $1`,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: "Không tìm thấy dữ liệu"
      });
    }

    res.json({
      success: true,
      data: result.rows[0]
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Không thể lấy dữ liệu"
    });
  }
});

// SAVE USER DATA
app.put("/api/me/data", auth, async (req, res) => {
  try {
    const {
      learned = [],
      favorites = [],
      progress = {}
    } = req.body;

    await pool.query(
      `UPDATE user_data
       SET learned = $1,
           favorites = $2,
           progress = $3,
           updated_at = CURRENT_TIMESTAMP
       WHERE user_id = $4`,
      [
        JSON.stringify(learned),
        JSON.stringify(favorites),
        JSON.stringify(progress),
        req.user.id
      ]
    );

    res.json({
      success: true,
      message: "Đã lưu dữ liệu"
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Không thể lưu dữ liệu"
    });
  }
});

// ADMIN AUTH
function adminAuth(req, res, next) {
  auth(req, res, () => {
    if (req.user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Không có quyền admin"
      });
    }

    next();
  });
}

// ADMIN USERS
app.get("/api/admin/users", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, account_code, display_name, role,
              created_at, updated_at
       FROM users
       ORDER BY created_at DESC`
    );

    res.json({
      success: true,
      users: result.rows
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      message: "Không thể lấy danh sách tài khoản"
    });
  }
});

// START
initDatabase()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(
        `开心 HSK Server running on port ${PORT}`
      );
    });
  })
  .catch((error) => {
    console.error(
      "Database initialization failed:",
      error
    );

    process.exit(1);
  });
