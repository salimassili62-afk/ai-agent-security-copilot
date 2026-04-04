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

app.use(helmet());
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

// PUBLIC SCAN - NO AUTH REQUIRED
app.post("/api/scan", rateLimitScan, async (req, res) => {
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

async function performScan(content, scanContext, compareBaseline, groqApiKey) {
  const baseline = typeof compareBaseline === "string" ? compareBaseline.trim() : "";
  const contextLine = typeof scanContext === "string" && scanContext.trim() ? `[Scan context: ${scanContext.trim()}]\n\n` : "";
  const wrappedContent = baseline
    ? `${contextLine}[Compare mode]\nBASELINE:\n${baseline}\n\nCANDIDATE:\n${content}`
    : `${contextLine}${content}`;
  const compareSystem = baseline ? "\n\nCompare mode active. Score CANDIDATE vs BASELINE." : "";

  const systemPrompt = `You are an AI security analyst. Analyze for: prompt injection, jailbreaks, data exfiltration, secrets leaks, social engineering, improper output handling, excessive agency, supply-chain issues, RAG poisoning, system prompt leakage, misinformation, resource abuse.

Map to OWASP LLM Top 10 (2025): LLM01-10.

Respond ONLY with JSON (no markdown fences):
{
  "score": 0-100,
  "label": "LOW|MEDIUM|HIGH",
  "confidence": "LOW|MEDIUM|HIGH",
  "summary": "one sentence",
  "reasons": ["string array"],
  "fixes": ["string array"],
  "owasp": [{"id":"LLM01","title":"Prompt Injection","severity":"LOW|MEDIUM|HIGH","note":"explanation"}],
  "triage": {"action":"ALLOW|REVIEW|BLOCK|ESCALATE","rationale":"reason"},
  "soc_note": "single line",
  "false_positive_risk": "LOW|MEDIUM|HIGH",
  "red_team_followups": ["3-6 test ideas"]
}${compareSystem}`;

  const timeout = abortAfter(GROQ_TIMEOUT_MS);
  try {
    const response = await fetch(`${GROQ_BASE_URL}/chat/completions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${groqApiKey}` },
      signal: timeout.src,
      body: JSON.stringify({ model: GROQ_MODEL, max_tokens: 1500, temperature: 0.1, messages: [{ role: "system", content: systemPrompt }, { role: "user", content: wrappedContent }] })
    });
    timeout.done();

    if (!response.ok) throw new Error(`Groq API error: ${await response.text()}`);
    const data = await response.json();
    const outputText = data.choices?.[0]?.message?.content?.trim() || "";
    if (!outputText) throw new Error("Empty AI response");

    let parsed;
    try {
      const jsonMatch = outputText.match(/\{[\s\S]*\}/);
      parsed = JSON.parse(jsonMatch ? jsonMatch[0] : outputText);
    } catch {
      parsed = { score: 0, label: "UNKNOWN", confidence: "LOW", summary: "Parse failed", reasons: ["AI format invalid"], fixes: ["Retry"], owasp: [], triage: { action: "REVIEW", rationale: "Parse error" }, soc_note: "Parse failed", false_positive_risk: "HIGH", red_team_followups: [] };
    }
    return { outputText, parsed, provider: "groq", model: GROQ_MODEL };
  } catch (e) {
    timeout.done();
    throw e;
  }
}

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
  });
}
