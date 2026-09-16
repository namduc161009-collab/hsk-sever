const express = require("express");
const cors = require("cors");

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// Kiểm tra server
app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "开心 HSK Server đang hoạt động!",
    version: "1.0.0"
  });
});

// Kiểm tra API
app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      success: true,
      status: "online",
      database: "connected"
    });
  } catch {
    res.status(500).json({
      success: false,
      status: "online",
      database: "error"
    });
  }
});
  res.json({
    success: true,
    status: "online"
  });
});

app.listen(PORT, "0.0.0.0", () => {
console.log(`开心 HSK Server running on port ${PORT}`);
});
