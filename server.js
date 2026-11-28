const express = require(”express“);

const helmet = require(”helmet“);

const rateLimit = require(”express-rate-limit“);

const jwt = require(”jsonwebtoken“);

const crypto = require(”crypto“);

require(”dotenv“).config();

const app = express();

app.use(helmet());

app.use(express.json({ limit: ”10kb“ }));

app.set(”trust proxy“, 1);

const PORT = process.env.PORT || 3000;

const ADMIN_USERNAME = process.env.ADMIN_USERNAME;

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

const JWT_SECRET = process.env.JWT_SECRET;

if (!ADMIN_USERNAME  !ADMIN_PASSWORD  !JWT_SECRET) {

  throw new Error(”Missing required server environment variables“);

}

const loginLimiter = rateLimit({

  windowMs: 15 * 60 * 1000,

  limit: 5,

  standardHeaders: ”draft-7“,

  legacyHeaders: false

});

function safeEqual(a, b) {

  const first = Buffer.from(String(a));

  const second = Buffer.from(String(b));

  return first.length === second.length &&

    crypto.timingSafeEqual(first, second);

}

app.get(”/health“, (req, res) => {

  res.json({ status: ”ok“ });

});

app.post(”/api/admin/login“, loginLimiter, (req, res) => {

  const { username, password } = req.body || {};

  if (

    typeof username !== ”string“ ||

    typeof password !== ”string“ ||

    !safeEqual(username, ADMIN_USERNAME) ||

    !safeEqual(password, ADMIN_PASSWORD)

  ) {

    return res.status(401).json({

      error: ”Invalid username or password“

    });

  }

  const token = jwt.sign(

    { role: ”admin“, username: ADMIN_USERNAME },

    JWT_SECRET,

    { expiresIn: ”2h“ }

  );

  res.json({

    message: ”Login successful“,

    token,

    expiresIn: 7200

  });

});

function requireAdmin(req, res, next) {

  const header = req.headers.authorization || ”“;

  const token = header.startsWith(”Bearer “)

    ? header.slice(7)

    : ”“;

  try {

    const data = jwt.verify(token, JWT_SECRET);

    if (

      data.role !== ”admin“ ||

      data.username !== ADMIN_USERNAME

    ) {

      return res.status(403).json({ error: ”Forbidden“ });

    }

    req.admin = data;

    next();

  } catch {

    return res.status(401).json({ error: ”Unauthorized“ });

  }

}

app.get(”/api/admin/me“, requireAdmin, (req, res) => {

  res.json({

    authenticated: true,

    username: req.admin.username

  });

});

app.listen(PORT, () => {

  console.log(`AA International backend running on port ${PORT}`);

});
