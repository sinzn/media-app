require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const session = require("express-session");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcrypt");
const app = express();

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static("uploads"));
app.use(
  session({
    secret: process.env.SESSION_SECRET || "secret",
    resave: false,
    saveUninitialized: true,
  })
);

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// File upload setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({ storage });

// Middleware
function isAuth(req, res, next) {
  if (req.session.user) return next();
  res.redirect("/login");
}

function isAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === "admin") return next();
  res.redirect("/dashboard");
}

// Routes
app.get("/", (req, res) => res.redirect("/login"));

app.get("/register", (req, res) => res.render("register"));
app.post("/register", async (req, res) => {
  const { username, password, role } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  db.query(
    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
    [username, hashed, role],
    () => res.redirect("/login")
  );
});

app.get("/login", (req, res) => res.render("login"));
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.query("SELECT * FROM users WHERE username = ?", [username], async (err, results) => {
    if (results.length > 0 && await bcrypt.compare(password, results[0].password)) {
      req.session.user = results[0];
      res.redirect("/dashboard");
    } else {
      res.send("Invalid credentials");
    }
  });
});

app.get("/reset", (req, res) => res.render("reset"));
app.post("/reset", async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  db.query("UPDATE users SET password = ? WHERE username = ?", [hashed, username], () => {
    res.redirect("/login");
  });
});

app.get("/dashboard", isAuth, (req, res) => {
  db.query("SELECT * FROM files ORDER BY id DESC", (err, files) => {
    files.forEach(file => {
      file.uploaded_at = new Date(file.uploaded_at);
    });
    res.render("dashboard", { user: req.session.user, files });
  });
});

app.get("/upload", isAdmin, (req, res) => res.render("upload"));
app.post("/upload", isAdmin, upload.single("media"), (req, res) => {
  if (!req.file) {
    return res.send("File upload failed.");
  }
  db.query(
    "INSERT INTO files (filename, originalname, uploaded_at) VALUES (?, ?, NOW())",
    [req.file.filename, req.file.originalname],
    (err) => {
      if (err) {
        console.error("DB Insert Error:", err);
        return res.send("Database error during file upload.");
      }
      res.redirect("/dashboard");
    }
  );
});

app.get("/delete/:id", isAdmin, (req, res) => {
  db.query("SELECT * FROM files WHERE id = ?", [req.params.id], (err, results) => {
    if (results.length > 0) {
      fs.unlinkSync(path.join(__dirname, "uploads", results[0].filename));
      db.query("DELETE FROM files WHERE id = ?", [req.params.id], () => res.redirect("/dashboard"));
    }
  });
});

app.get("/play/:filename", isAuth, (req, res) => {
  const filePath = path.join(__dirname, "uploads", req.params.filename);
  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      return res.status(404).send("File not found");
    }

    const contentType = req.params.filename.endsWith(".mp4")
      ? "video/mp4"
      : "audio/mpeg";

    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>Now Playing: ${req.params.filename}</title>
      </head>
      <body style="text-align: center;">
          <h2>Now Playing: ${req.params.filename}</h2>
          ${req.params.filename.endsWith('.mp4')
              ? `<video width="100%" controls>
                  <source src="/${req.params.filename}" type="video/mp4">
                  Your browser does not support the video tag.
              </video>`
              : `<audio controls>
                  <source src="/${req.params.filename}" type="audio/mpeg">
                  Your browser does not support the audio tag.
              </audio>`
          }
      </body>
      </html>
    `);
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
