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

if (!fs.existsSync("./data")) fs.mkdirSync("./data", { recursive: true });

const db = new Database(DB_FILE);

// Init tables if not exists
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
app.use(cors({ origin: true })); // en dev, autorise localhost front. En prod, configurer strictement
app.use(express.json());

// Helpers
function nowTs() { return Math.floor(Date.now() / 1000); }
function daysToSeconds(d) { return d * 24 * 60 * 60; }

// Générer access token (JWT)
function generateAccessToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRES });
}

// Vérifier token middleware
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) return res.status(401).json({ error: "Non authentifié" });
  const token = auth.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Token invalide ou expiré" });
  }
}

// Endpoints

// Register
app.post("/register", async (req, res) => {
  const { username, email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Email et mot de passe requis" });

  const userExists = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (userExists) return res.status(400).json({ error: "Email déjà utilisé" });

  const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
  const id = uuidv4();
  const created_at = nowTs();

  const stmt = db.prepare("INSERT INTO users (id, username, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)");
  stmt.run(id, username || null, email, hash, created_at);

  return res.json({ message: "Compte créé avec succès" });
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: "Email et mot de passe requis" });

  const user = db.prepare("SELECT id, username, email, password_hash, created_at FROM users WHERE email = ?").get(email);
  if (!user) return res.status(400).json({ error: "Utilisateur introuvable" });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: "Mot de passe incorrect" });

  // Générer tokens
  const accessToken = generateAccessToken(user);
  const refreshTokenPlain = randomBytes(64).toString("hex");
  const refreshTokenHash = await bcrypt.hash(refreshTokenPlain, BCRYPT_ROUNDS);
  const refreshId = uuidv4();
  const expires_at = nowTs() + daysToSeconds(REFRESH_TOKEN_EXPIRES_DAYS);

  db.prepare("INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)")
    .run(refreshId, user.id, refreshTokenHash, expires_at, nowTs());

  // Renvoie access + refresh (en dev). En production, stocker refresh token en HttpOnly cookie.
  return res.json({
    message: "Connecté avec succès",
    accessToken,
    refreshToken: refreshTokenPlain
  });
});

// Refresh token
app.post("/refresh", async (req, res) => {
  const { email, refreshToken } = req.body || {};
  if (!email || !refreshToken) return res.status(400).json({ error: "email + refreshToken requis" });

  const user = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (!user) return res.status(400).json({ error: "Utilisateur introuvable" });

  const tokens = db.prepare("SELECT id, token_hash, expires_at, revoked FROM refresh_tokens WHERE user_id = ?").all(user.id);
  if (!tokens || tokens.length === 0) return res.status(401).json({ error: "Refresh token invalide" });

  // Cherche un token qui matche
  let found = null;
  for (const row of tokens) {
    const match = await bcrypt.compare(refreshToken, row.token_hash);
    if (match) { found = row; break; }
  }
  if (!found) return res.status(401).json({ error: "Refresh token invalide" });
  if (found.revoked) return res.status(401).json({ error: "Refresh token révoqué" });
  if (found.expires_at < nowTs()) return res.status(401).json({ error: "Refresh token expiré" });

  // OK -> générer nouvel access token (et optionnellement nouveau refresh token)
  const userRow = db.prepare("SELECT id, username, email, created_at FROM users WHERE id = ?").get(user.id);
  const newAccess = generateAccessToken(userRow);

  return res.json({ accessToken: newAccess });
});

// Protected route example
app.get("/me", authMiddleware, (req, res) => {
  const user = db.prepare("SELECT id, username, email, created_at FROM users WHERE id = ?").get(req.user.id);
  if (!user) return res.status(404).json({ error: "Utilisateur introuvable" });
  return res.json({ user });
});

// Logout (révoquer refresh token côté serveur) - optionnel
app.post("/logout", async (req, res) => {
  const { email, refreshToken } = req.body || {};
  if (!email || !refreshToken) return res.status(400).json({ error: "email + refreshToken requis" });
  const user = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (!user) return res.status(400).json({ error: "Utilisateur introuvable" });

  const tokens = db.prepare("SELECT id, token_hash FROM refresh_tokens WHERE user_id = ?").all(user.id);
  for (const row of tokens) {
    const match = await bcrypt.compare(refreshToken, row.token_hash);
    if (match) {
      db.prepare("UPDATE refresh_tokens SET revoked = 1 WHERE id = ?").run(row.id);
      return res.json({ message: "Déconnecté et token révoqué" });
    }
  }
  return res.status(400).json({ error: "Refresh token non reconnu" });
});

app.listen(PORT, () => {
  console.log(`✅ Auth server running on http://localhost:${PORT}`);
});
