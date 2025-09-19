import express from "express";
import cors from "cors";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import Database from "better-sqlite3";
import { randomBytes } from "crypto";
import { v4 as uuidv4 } from "uuid";
import dotenv from "dotenv";
import fs from "fs";

dotenv.config();

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || "secret_dev_change_me";
const ACCESS_TOKEN_EXPIRES = process.env.ACCESS_TOKEN_EXPIRES || "15m";
const REFRESH_TOKEN_EXPIRES_DAYS = parseInt(process.env.REFRESH_TOKEN_EXPIRES_DAYS || "7", 10);
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS || "12", 10);
const DB_FILE = process.env.DB_FILE || "./data/auth.sqlite";

// Crée dossier data si pas là
if (!fs.existsSync("./data")) fs.mkdirSync("./data", { recursive: true });

// Base SQLite
const db = new Database(DB_FILE);
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT,
  email TEXT UNIQUE,
  password_hash TEXT,
  created_at INTEGER
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  token_hash TEXT,
  expires_at INTEGER,
  revoked INTEGER DEFAULT 0,
  created_at INTEGER,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

const app = express();
app.use(cors({ origin: true })); // en dev, accepte tout. En prod, configure ton domaine.
app.use(express.json());

// Helpers
const nowTs = () => Math.floor(Date.now() / 1000);
const daysToSeconds = (d) => d * 24 * 60 * 60;

function generateAccessToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRES,
  });
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Non authentifié" });
  }
  try {
    const payload = jwt.verify(auth.slice(7), JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Token invalide ou expiré" });
  }
}

// ========================
// ROUTES
// ========================

// Register
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Email et mot de passe requis" });

  const exists = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (exists) return res.status(400).json({ error: "Email déjà utilisé" });

  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  db.prepare("INSERT INTO users (id, username, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)").run(
    uuidv4(),
    username || null,
    email,
    hash,
    nowTs()
  );

  res.json({ message: "Compte créé avec succès" });
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Champs manquants" });

  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  if (!user) return res.status(400).json({ error: "Utilisateur introuvable" });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: "Mot de passe incorrect" });

  const accessToken = generateAccessToken(user);
  const refreshPlain = randomBytes(64).toString("hex");
  const refreshHash = await bcrypt.hash(refreshPlain, BCRYPT_ROUNDS);

  db.prepare("INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)")
    .run(uuidv4(), user.id, refreshHash, nowTs() + daysToSeconds(REFRESH_TOKEN_EXPIRES_DAYS), nowTs());

  res.json({ message: "Connecté", accessToken, refreshToken: refreshPlain });
});

// Refresh
app.post("/refresh", async (req, res) => {
  const { email, refreshToken } = req.body || {};
  if (!email || !refreshToken) return res.status(400).json({ error: "email + refreshToken requis" });

  const user = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (!user) return res.status(400).json({ error: "Utilisateur introuvable" });

  const tokens = db.prepare("SELECT * FROM refresh_tokens WHERE user_id = ?").all(user.id);
  let match = null;
  for (const t of tokens) {
    if (await bcrypt.compare(refreshToken, t.token_hash)) {
      match = t;
      break;
    }
  }
  if (!match) return res.status(401).json({ error: "Refresh token invalide" });
  if (match.revoked) return res.status(401).json({ error: "Token révoqué" });
  if (match.expires_at < nowTs()) return res.status(401).json({ error: "Token expiré" });

  const accessToken = generateAccessToken(user);
  res.json({ accessToken });
});

// Profil protégé
app.get("/me", authMiddleware, (req, res) => {
  const user = db.prepare("SELECT id, username, email, created_at FROM users WHERE id = ?").get(req.user.id);
  if (!user) return res.status(404).json({ error: "Utilisateur introuvable" });
  res.json({ user });
});

// Logout (révoque refresh token)
app.post("/logout", async (req, res) => {
  const { email, refreshToken } = req.body || {};
  if (!email || !refreshToken) return res.status(400).json({ error: "email + refreshToken requis" });

  const user = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (!user) return res.status(400).json({ error: "Utilisateur introuvable" });

  const tokens = db.prepare("SELECT id, token_hash FROM refresh_tokens WHERE user_id = ?").all(user.id);
  for (const t of tokens) {
    if (await bcrypt.compare(refreshToken, t.token_hash)) {
      db.prepare("UPDATE refresh_tokens SET revoked = 1 WHERE id = ?").run(t.id);
      return res.json({ message: "Déconnecté" });
    }
  }
  res.status(400).json({ error: "Refresh token non reconnu" });
});

// ========================
// START
// ========================
app.listen(PORT, () => {
  console.log(`✅ Serveur d'auth lancé sur http://localhost:${PORT}`);
});
