require('dotenv').config();
const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");
const helmet = require("helmet");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const APP_VERSION = "2.0.0";

const GROQ_MODEL = process.env.GROQ_MODEL || "llama-3.1-8b-instant";
const GROQ_BASE_URL = "https://api.groq.com/openai/v1";
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');

// Optional Supabase - only use if configured
let supabase = null;
if (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_KEY) {
  try {
    const { createClient } = require("@supabase/supabase-js");
    supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
  } catch (e) {
    console.log('Supabase not available:', e.message);
  }
}

const MAX_SCAN_CHARS = 200000;
const GROQ_TIMEOUT_MS = 120000;

// In-memory rate limiting
const rateBuckets = new Map();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "10mb" }));
app.use(express.static(path.join(__dirname, ".")));

// Request ID middleware
app.use("/api", (req, res, next) => {
  const requestId = crypto.randomUUID();
  res.locals.requestId = requestId;
  res.setHeader("X-Request-Id", requestId);
  next();
});

function getClientIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (typeof xf === "string" && xf.length) return xf.split(",")[0].trim();
  return req.socket?.remoteAddress || req.ip || "unknown";
}

function rateLimitScan(req, res, next) {
  const ip = getClientIp(req);
  const now = Date.now();
  let bucket = rateBuckets.get(ip);
  if (!bucket || now > bucket.resetAt) {
    bucket = { count: 0, resetAt: now + 15 * 60 * 1000 };
    rateBuckets.set(ip, bucket);
  }
  bucket.count++;
  res.setHeader("X-RateLimit-Limit", "60");
  res.setHeader("X-RateLimit-Remaining", Math.max(0, 60 - bucket.count).toString());
  if (bucket.count > 60) {
    return res.status(429).json({ error: "Too many requests", requestId: res.locals.requestId });
  }
  next();
}

function abortAfter(ms) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  return { src: c.signal, done: () => clearTimeout(t) };
}

app.get("/api/health", (req, res) => {
  res.json({ ok: true, version: APP_VERSION, groqConfigured: !!process.env.GROQ_API_KEY, requestId: res.locals.requestId });
});

// Auth endpoints for GitHub OAuth via Supabase
app.get("/api/auth/github", async (req, res) => {
  if (!supabase) {
    return res.status(503).json({ error: "Supabase not configured", requestId: res.locals.requestId });
  }
  try {
    const { data, error } = await supabase.auth.signInWithOAuth({
      provider: 'github',
      options: {
        redirectTo: `${req.protocol}://${req.get('host')}/auth/callback`
      }
    });
    if (error) throw error;
    res.json({ url: data.url, requestId: res.locals.requestId });
  } catch (e) {
    res.status(500).json({ error: e.message, requestId: res.locals.requestId });
  }
});

app.get("/auth/callback", async (req, res) => {
  // Handle OAuth callback - exchange code for session
  const { code } = req.query;
  if (!code) {
    return res.redirect('/?error=oauth_failed');
  }
  // Redirect to frontend with code for exchange
  res.redirect(`/?code=${code}&provider=github`);
});

app.post("/api/auth/session", async (req, res) => {
  if (!supabase) {
    return res.status(503).json({ error: "Supabase not configured", requestId: res.locals.requestId });
  }
  const { code } = req.body;
  if (!code) {
    return res.status(400).json({ error: "Missing code", requestId: res.locals.requestId });
  }
  try {
    const { data, error } = await supabase.auth.exchangeCodeForSession(code);
    if (error) throw error;
    res.json({ 
      user: data.user,
      session: { access_token: data.session.access_token, expires_at: data.session.expires_at },
      requestId: res.locals.requestId 
    });
  } catch (e) {
    res.status(500).json({ error: e.message, requestId: res.locals.requestId });
  }
});

app.get("/api/auth/user", async (req, res) => {
  if (!supabase) {
    return res.status(503).json({ error: "Supabase not configured", requestId: res.locals.requestId });
  }
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.json({ user: null, requestId: res.locals.requestId });
  }
  const token = authHeader.split(' ')[1];
  try {
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error) throw error;
    res.json({ user, requestId: res.locals.requestId });
  } catch (e) {
    res.json({ user: null, error: e.message, requestId: res.locals.requestId });
  }
});

app.post("/api/auth/logout", async (req, res) => {
  if (!supabase) {
    return res.status(503).json({ error: "Supabase not configured", requestId: res.locals.requestId });
  }
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.split(' ')[1];
    try {
      await supabase.auth.signOut({ scope: 'local', access_token: token });
    } catch (e) {
      // Ignore signout errors
    }
  }
  res.json({ success: true, requestId: res.locals.requestId });
});

// Scan history endpoints (authenticated users only)
app.get("/api/scans", async (req, res) => {
  if (!supabase) {
    return res.json({ scans: [], source: 'local', requestId: res.locals.requestId });
  }
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.json({ scans: [], source: 'local', requestId: res.locals.requestId });
  }
  const token = authHeader.split(' ')[1];
  try {
    const { data: { user } } = await supabase.auth.getUser(token);
    if (!user) {
      return res.json({ scans: [], source: 'local', requestId: res.locals.requestId });
    }
    const { data: scans, error } = await supabase
      .from('scans')
      .select('*')
      .eq('user_id', user.id)
      .order('created_at', { ascending: false })
      .limit(20);
    if (error) throw error;
    res.json({ scans: scans || [], source: 'cloud', requestId: res.locals.requestId });
  } catch (e) {
    res.json({ scans: [], source: 'local', error: e.message, requestId: res.locals.requestId });
  }
});

app.post("/api/scans", rateLimitScan, async (req, res) => {
  // Public scan endpoint - works for guests and logged-in users
  try {
    const { content, scanContext, compareBaseline } = req.body || {};
    if (!content || typeof content !== "string") {
      return res.status(400).json({ error: "Missing content", requestId: res.locals.requestId });
    }
    if (content.length > MAX_SCAN_CHARS) {
      return res.status(400).json({ error: "Content too large", requestId: res.locals.requestId });
    }

    const groqApiKey = process.env.GROQ_API_KEY;
    if (!groqApiKey) {
      return res.status(503).json({ error: "GROQ_API_KEY not configured", requestId: res.locals.requestId });
    }

    const result = await performScan(content, scanContext, compareBaseline, groqApiKey);
    
    // Save to Supabase if user is logged in
    const authHeader = req.headers.authorization;
    if (supabase && authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.split(' ')[1];
      try {
        const { data: { user } } = await supabase.auth.getUser(token);
        if (user) {
          await supabase.from('scans').insert({
            user_id: user.id,
            content_preview: content.slice(0, 500),
            result_score: result.parsed.score,
            result_label: result.parsed.label,
            result_summary: result.parsed.summary,
            full_result: result.parsed,
            scan_context: scanContext,
            compare_mode: !!compareBaseline
          });
        }
      } catch (e) {
        // Ignore save errors, still return scan result
      }
    }
    
    res.json({
      outputText: result.outputText,
      parsed: result.parsed,
      provider: result.provider,
      model: result.model,
      compareMode: !!compareBaseline,
      requestId: res.locals.requestId,
      version: APP_VERSION
    });
  } catch (error) {
    console.error('Scan error:', error);
    res.status(500).json({ error: error.message || "Scan failed", requestId: res.locals.requestId });
  }
});

// Serve index.html for root
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Catch-all for SPA
app.get("*", (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({ error: "API not found" });
  res.sendFile(path.join(__dirname, "index.html"));
});

module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`🚀 AI Security Copilot v${APP_VERSION} on port ${PORT}`);
    console.log(`🤖 Groq: ${process.env.GROQ_API_KEY ? '✅' : '❌'}`);
    console.log(`🔐 Supabase Auth: ${supabase ? '✅' : '❌'}`);
  });
}
