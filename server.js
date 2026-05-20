import "dotenv/config";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { createClient } from "@supabase/supabase-js";

// ---------- Supabase ----------
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY // service role key → bypasses RLS for server-side ops
);

// ---------- App ----------
const app = express();
const PORT = process.env.PORT || 8000;
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_ALGORITHM = "HS256";

app.use(cookieParser());
app.use(express.json());

const originsEnv = (process.env.CORS_ORIGINS || "").trim();
const origins = originsEnv
  ? originsEnv.split(",").map((o) => o.trim()).filter(Boolean)
  : ["http://localhost:8000"];

app.use(
  cors({
    origin: origins,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

// ---------- Auth helpers ----------
function hashPassword(pw) {
  return bcrypt.hashSync(pw, 10);
}

function verifyPassword(pw, hashed) {
  try {
    return bcrypt.compareSync(pw, hashed);
  } catch {
    return false;
  }
}

function createAccessToken(userId, email) {
  return jwt.sign(
    { sub: userId, email, type: "access" },
    JWT_SECRET,
    { algorithm: JWT_ALGORITHM, expiresIn: "7d" }
  );
}

function setAuthCookie(res, token) {
  res.cookie("access_token", token, {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    maxAge: 7 * 24 * 3600 * 1000, // ms
    path: "/",
  });
}

async function getCurrentUser(req, res, next) {
  let token = req.cookies?.access_token;
  if (!token) {
    const auth = req.headers.authorization || "";
    if (auth.startsWith("Bearer ")) token = auth.slice(7);
  }
  if (!token) return res.status(401).json({ detail: "Not authenticated" });

  try {
    const payload = jwt.verify(token, JWT_SECRET, { algorithms: [JWT_ALGORITHM] });
    if (payload.type !== "access")
      return res.status(401).json({ detail: "Invalid token type" });

    const { data: user, error } = await supabase
      .from("users")
      .select("id, email, name")
      .eq("id", payload.sub)
      .single();

    if (error || !user) return res.status(401).json({ detail: "User not found" });
    req.user = user;
    next();
  } catch (err) {
    if (err.name === "TokenExpiredError")
      return res.status(401).json({ detail: "Token expired" });
    return res.status(401).json({ detail: "Invalid token" });
  }
}

// ---------- Validation helpers ----------
function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ---------- Router ----------
const api = express.Router();

// ---------- Auth endpoints ----------
api.post("/auth/register", async (req, res) => {
  const { email: rawEmail, password, name } = req.body;
  if (!rawEmail || !validateEmail(rawEmail))
    return res.status(422).json({ detail: "Invalid email" });
  if (!password || password.length < 6 || password.length > 128)
    return res.status(422).json({ detail: "Password must be 6–128 characters" });

  const email = rawEmail.toLowerCase().trim();

  const { data: existing } = await supabase
    .from("users")
    .select("id")
    .eq("email", email)
    .maybeSingle();

  if (existing) return res.status(400).json({ detail: "Email already registered" });

  const displayName = name || email.split("@")[0];
  const { data: newUser, error } = await supabase
    .from("users")
    .insert({ email, password_hash: hashPassword(password), name: displayName })
    .select("id, email, name")
    .single();

  if (error) return res.status(500).json({ detail: error });

  const token = createAccessToken(newUser.id, email);
  setAuthCookie(res, token);
  res.json({ id: newUser.id, email: newUser.email, name: newUser.name });
});

api.post("/auth/login", async (req, res) => {
  const { email: rawEmail, password } = req.body;
  if (!rawEmail || !password)
    return res.status(422).json({ detail: "Email and password required" });

  const email = rawEmail.toLowerCase().trim();

  const { data: user } = await supabase
    .from("users")
    .select("id, email, name, password_hash")
    .eq("email", email)
    .maybeSingle();

  if (!user || !verifyPassword(password, user.password_hash))
    return res.status(401).json({ detail: "Invalid credentials" });

  const token = createAccessToken(user.id, email);
  setAuthCookie(res, token);
  res.json({ id: user.id, email: user.email, name: user.name });
});

api.post("/auth/logout", (_req, res) => {
  res.clearCookie("access_token", { path: "/" });
  res.json({ ok: true });
});

api.get("/auth/me", getCurrentUser, (req, res) => {
  const { id, email, name } = req.user;
  res.json({ id, email, name });
});

// ---------- Data endpoints ----------
api.get("/data", getCurrentUser, async (req, res) => {
  const uid = req.user.id;

  const [files, budgets, goals, settings] = await Promise.all([
    supabase.from("files").select("name, rows, autoCount").eq("user_id", uid),
    supabase.from("budgets").select("categoria, limite").eq("user_id", uid),
    supabase.from("goals").select("id, nombre, objetivo, ahorrado, fecha").eq("user_id", uid),
    supabase.from("settings").select("lang, currency, activeFile").eq("user_id", uid).maybeSingle(),
  ]);

  res.json({
    files: files.data || [],
    budgets: budgets.data || [],
    goals: goals.data || [],
    settings: settings.data || {},
  });
});

api.put("/files", getCurrentUser, async (req, res) => {
  const uid = req.user.id;
  const payload = req.body; // array of { name, rows, autoCount }

  if (!Array.isArray(payload))
    return res.status(422).json({ detail: "Body must be an array" });

  await supabase.from("files").delete().eq("user_id", uid);

  if (payload.length) {
    const docs = payload.map(({ name, rows, autoCount = 0 }) => ({
      user_id: uid,
      name,
      rows,
      autoCount,
    }));
    const { error } = await supabase.from("files").insert(docs);
    if (error) return res.status(500).json({ detail: "Failed to save files" });
  }

  res.json({ ok: true, count: payload.length });
});

api.put("/budgets", getCurrentUser, async (req, res) => {
  const uid = req.user.id;
  const payload = req.body;

  if (!Array.isArray(payload))
    return res.status(422).json({ detail: "Body must be an array" });

  await supabase.from("budgets").delete().eq("user_id", uid);

  if (payload.length) {
    const docs = payload.map(({ categoria, limite }) => ({ user_id: uid, categoria, limite }));
    const { error } = await supabase.from("budgets").insert(docs);
    if (error) return res.status(500).json({ detail: "Failed to save budgets" });
  }

  res.json({ ok: true });
});

api.put("/goals", getCurrentUser, async (req, res) => {
  const uid = req.user.id;
  const payload = req.body;

  if (!Array.isArray(payload))
    return res.status(422).json({ detail: "Body must be an array" });

  await supabase.from("goals").delete().eq("user_id", uid);

  if (payload.length) {
    const docs = payload.map(({ id, nombre, objetivo, ahorrado = 0, fecha }) => ({
      user_id: uid,
      ...(id ? { id } : {}),
      nombre,
      objetivo,
      ahorrado,
      fecha,
    }));
    const { error } = await supabase.from("goals").insert(docs);
    if (error) return res.status(500).json({ detail: "Failed to save goals" });
  }

  res.json({ ok: true });
});

api.put("/settings", getCurrentUser, async (req, res) => {
  const uid = req.user.id;
  const { lang = "es", currency = "EUR", activeFile = null } = req.body;

  const { error } = await supabase.from("settings").upsert(
    { user_id: uid, lang, currency, activeFile },
    { onConflict: "user_id" }
  );

  if (error) return res.status(500).json({ detail: "Failed to save settings" });
  res.json({ ok: true });
});

api.delete("/data", getCurrentUser, async (req, res) => {
  const uid = req.user.id;

  await Promise.all([
    supabase.from("files").delete().eq("user_id", uid),
    supabase.from("budgets").delete().eq("user_id", uid),
    supabase.from("goals").delete().eq("user_id", uid),
    supabase.from("settings").delete().eq("user_id", uid),
  ]);

  res.json({ ok: true });
});

api.get("/health", (_req, res) => res.json({ status: "ok" }));

// ---------- Mount & Listen ----------
app.use("/api", api);

app.listen(PORT, () => {
  console.log(`Finanzas API running on port ${PORT}`);
});
