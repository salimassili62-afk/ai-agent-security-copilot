require('dotenv').config();
const express = require("express");
const crypto = require("crypto");
const helmet = require("helmet");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const APP_VERSION = "1.2.0";

const GROQ_MODEL = process.env.GROQ_MODEL || "llama-3.1-8b-instant";
const GROQ_BASE_URL = "https://api.groq.com/openai/v1";
const MAX_SCAN_CHARS = 10000;
const GROQ_TIMEOUT_MS = 30000;
const SCAN_CACHE_MS = 60000;

// Optional Supabase
let supabase = null;
if (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_KEY) {
  try {
    const { createClient } = require("@supabase/supabase-js");
    supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
    console.log('[INIT] Supabase connected');
  } catch (e) {
    console.log('[INIT] Supabase not available:', e.message);
  }
}

// Request cache for identical scans
const scanCache = new Map();

// In-memory rate limiting
const rateBuckets = new Map();

// Logging helper
function log(level, message, meta = {}) {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] [${level}] ${message}`, Object.keys(meta).length ? JSON.stringify(meta) : '');
}

// Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ 
  origin: true, 
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-Id']
}));
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, ".")));

// Request ID middleware
app.use("/api", (req, res, next) => {
  try {
    const requestId = crypto.randomUUID();
    res.locals.requestId = requestId;
    res.setHeader("X-Request-Id", requestId);
    log('INFO', `${req.method} ${req.path}`, { requestId, ip: getClientIp(req) });
    next();
  } catch (e) {
    log('ERROR', 'Request ID middleware failed', { error: e.message });
    next();
  }
});

function getClientIp(req) {
  try {
    const xf = req.headers["x-forwarded-for"];
    if (typeof xf === "string" && xf.length) return xf.split(",")[0].trim();
    return req.socket?.remoteAddress || req.ip || "unknown";
  } catch (e) {
    return "unknown";
  }
}

function sanitizeInput(input) {
  if (typeof input !== 'string') return '';
  return input.replace(/\x00/g, '').slice(0, MAX_SCAN_CHARS).trim();
}

function rateLimitScan(req, res, next) {
  try {
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
      log('WARN', 'Rate limit exceeded', { ip, count: bucket.count });
      return res.status(429).json({ 
        ok: false,
        error: "You've reached the limit of 60 scans per 15 minutes. Please wait a moment and try again.", 
        requestId: res.locals.requestId 
      });
    }
    next();
  } catch (e) {
    log('ERROR', 'Rate limiting failed', { error: e.message });
    next();
  }
}

function abortAfter(ms) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  return { src: c.signal, done: () => clearTimeout(t) };
}

// Cache key generator
function getCacheKey(content, scanContext, compareBaseline) {
  const hash = crypto.createHash('md5');
  hash.update(content + '|' + (scanContext || '') + '|' + (compareBaseline || ''));
  return hash.digest('hex');
}

// Health check with Groq status
app.get("/api/health", async (req, res) => {
  try {
    const groqKey = process.env.GROQ_API_KEY;
    let groqStatus = 'not_configured';
    
    if (groqKey) {
      try {
        const testRes = await fetch(`${GROQ_BASE_URL}/models`, {
          headers: { "Authorization": `Bearer ${groqKey}` },
          signal: abortAfter(5000).src
        });
        groqStatus = testRes.ok ? 'connected' : 'error';
      } catch (e) {
        groqStatus = 'unreachable';
      }
    }
    
    res.json({ 
      ok: true, 
      version: APP_VERSION, 
      groqStatus,
      supabaseStatus: supabase ? 'connected' : 'not_configured',
      requestId: res.locals.requestId 
    });
  } catch (e) {
    log('ERROR', 'Health check failed', { error: e.message });
    res.status(500).json({ ok: false, error: e.message, requestId: res.locals.requestId });
  }
});

// Auth endpoints
app.get("/api/auth/github", async (req, res) => {
  if (!supabase) {
    return res.status(503).json({ ok: false, error: "Authentication not available", requestId: res.locals.requestId });
  }
  try {
    const { data, error } = await supabase.auth.signInWithOAuth({
      provider: 'github',
      options: {
        redirectTo: `${req.protocol}://${req.get('host')}/auth/callback`
      }
    });
    if (error) throw error;
    res.json({ ok: true, url: data.url, requestId: res.locals.requestId });
  } catch (e) {
    log('ERROR', 'GitHub auth failed', { error: e.message });
    res.status(500).json({ ok: false, error: e.message, requestId: res.locals.requestId });
  }
});

app.get("/auth/callback", async (req, res) => {
  const { code, error } = req.query;
  if (error || !code) {
    return res.redirect('/?auth=failed');
  }
  res.redirect(`/?code=${code}&provider=github`);
});

app.post("/api/auth/session", async (req, res) => {
  if (!supabase) {
    return res.status(503).json({ ok: false, error: "Authentication not available", requestId: res.locals.requestId });
  }
  try {
    const { code } = req.body || {};
    if (!code) {
      return res.status(400).json({ ok: false, error: "Missing authentication code", requestId: res.locals.requestId });
    }
    const { data, error } = await supabase.auth.exchangeCodeForSession(code);
    if (error) throw error;
    res.json({ 
      ok: true,
      user: data.user,
      session: { access_token: data.session.access_token, expires_at: data.session.expires_at },
      requestId: res.locals.requestId 
    });
  } catch (e) {
    log('ERROR', 'Session exchange failed', { error: e.message });
    res.status(500).json({ ok: false, error: e.message, requestId: res.locals.requestId });
  }
});

app.get("/api/auth/user", async (req, res) => {
  if (!supabase) {
    return res.json({ ok: true, user: null, requestId: res.locals.requestId });
  }
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.json({ ok: true, user: null, requestId: res.locals.requestId });
    }
    const token = authHeader.split(' ')[1];
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error) throw error;
    res.json({ ok: true, user, requestId: res.locals.requestId });
  } catch (e) {
    res.json({ ok: true, user: null, error: e.message, requestId: res.locals.requestId });
  }
});

app.post("/api/auth/logout", async (req, res) => {
  if (!supabase) {
    return res.json({ ok: true, requestId: res.locals.requestId });
  }
  try {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.split(' ')[1];
      await supabase.auth.signOut({ scope: 'local', access_token: token });
    }
    res.json({ ok: true, requestId: res.locals.requestId });
  } catch (e) {
    res.json({ ok: true, requestId: res.locals.requestId });
  }
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

// Optimized system prompt (20% shorter)
const SYSTEM_PROMPT = `Analyze for: prompt injection, jailbreaks, data exfiltration, secrets leaks, social engineering, improper output handling, excessive agency, supply-chain issues, RAG poisoning, system prompt leakage, misinformation, resource abuse.

Map to OWASP LLM Top 10 (2025): LLM01-10.

Respond ONLY with JSON:
{"score":0-100,"label":"LOW|MEDIUM|HIGH","confidence":"LOW|MEDIUM|HIGH","summary":"one sentence","reasons":["string array"],"fixes":["string array"],"owasp":[{"id":"LLM01","title":"Prompt Injection","severity":"LOW|MEDIUM|HIGH","note":"explanation"}],"triage":{"action":"ALLOW|REVIEW|BLOCK|ESCALATE","rationale":"reason"},"soc_note":"single line","false_positive_risk":"LOW|MEDIUM|HIGH","red_team_followups":["3-6 test ideas"]}`;

// Perform scan with retry logic
async function performScan(content, scanContext, compareBaseline, groqApiKey, attempt = 1) {
  const MAX_RETRIES = 2;
  
  try {
    const baseline = sanitizeInput(compareBaseline || '');
    const contextLine = scanContext ? `[Scan context: ${scanContext}]\n\n` : '';
    const wrappedContent = baseline
      ? `${contextLine}[Compare]\nBASELINE:\n${baseline}\n\nCANDIDATE:\n${content}`
      : `${contextLine}${content}`;
    
    const systemPrompt = baseline 
      ? SYSTEM_PROMPT + "\n\nCompare mode: Score CANDIDATE vs BASELINE."
      : SYSTEM_PROMPT;

    const timeout = abortAfter(GROQ_TIMEOUT_MS);
    
    const response = await fetch(`${GROQ_BASE_URL}/chat/completions`, {
      method: "POST",
      headers: { 
        "Content-Type": "application/json", 
        "Authorization": `Bearer ${groqApiKey}` 
      },
      signal: timeout.src,
      body: JSON.stringify({ 
        model: GROQ_MODEL, 
        max_tokens: 1200, 
        temperature: 0.1, 
        messages: [
          { role: "system", content: systemPrompt }, 
          { role: "user", content: wrappedContent }
        ] 
      })
    });
    
    timeout.done();

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Groq API error ${response.status}: ${errorText}`);
    }
    
    const data = await response.json();
    const outputText = data.choices?.[0]?.message?.content?.trim() || "";
    
    if (!outputText) {
      throw new Error("Empty AI response");
    }

    // Parse JSON
    let parsed;
    try {
      const jsonMatch = outputText.match(/\{[\s\S]*\}/);
      parsed = JSON.parse(jsonMatch ? jsonMatch[0] : outputText);
    } catch {
      // If parsing fails and we haven't retried, try with simplified prompt
      if (attempt < MAX_RETRIES) {
        log('WARN', 'JSON parse failed, retrying with simplified prompt', { attempt });
        return performScan(content.slice(0, 5000), scanContext, compareBaseline, groqApiKey, attempt + 1);
      }
      parsed = getFallbackResponse("Parse failed after retries");
    }
    
    return { outputText, parsed, provider: "groq", model: GROQ_MODEL };
    
  } catch (e) {
    // Retry on failure
    if (attempt < MAX_RETRIES) {
      log('WARN', `Scan failed, retrying (${attempt}/${MAX_RETRIES})`, { error: e.message });
      await new Promise(r => setTimeout(r, 1000 * attempt)); // Exponential backoff
      return performScan(content, scanContext, compareBaseline, groqApiKey, attempt + 1);
    }
    
    log('ERROR', 'Scan failed after retries', { error: e.message, attempts: MAX_RETRIES });
    throw e;
  }
}

function getFallbackResponse(reason) {
  return {
    score: 50,
    label: "UNKNOWN",
    confidence: "LOW",
    summary: `Analysis incomplete: ${reason}`,
    reasons: ["AI service temporarily unavailable"],
    fixes: ["Please try again in a moment"],
    owasp: [],
    triage: { action: "REVIEW", rationale: "Analysis incomplete" },
    soc_note: "Security scan incomplete - manual review required",
    false_positive_risk: "HIGH",
    red_team_followups: ["Re-run scan when service is available"]
  };
}

// Main scan endpoint - NEVER returns 500
app.post("/api/scans", rateLimitScan, async (req, res) => {
  const requestId = res.locals.requestId;
  
  try {
    // Validate input
    const { content, scanContext, compareBaseline } = req.body || {};
    
    if (!content || typeof content !== "string") {
      return res.status(400).json({ 
        ok: false,
        error: "Please provide text content to scan.", 
        requestId 
      });
    }
    
    if (content.length > MAX_SCAN_CHARS) {
      return res.status(400).json({ 
        ok: false,
        error: `Text is too long (${content.length} characters). Maximum is ${MAX_SCAN_CHARS} characters.`, 
        requestId 
      });
    }

    const groqApiKey = process.env.GROQ_API_KEY;
    if (!groqApiKey) {
      return res.status(503).json({ 
        ok: false,
        error: "Service temporarily unavailable. Please try again later.", 
        requestId 
      });
    }

    // Check cache
    const cacheKey = getCacheKey(content, scanContext, compareBaseline);
    const cached = scanCache.get(cacheKey);
    if (cached && (Date.now() - cached.timestamp) < SCAN_CACHE_MS) {
      log('INFO', 'Cache hit', { requestId });
      return res.json({
        ok: true,
        ...cached.result,
        cached: true,
        requestId,
        version: APP_VERSION
      });
    }

    // Perform scan
    log('INFO', 'Starting scan', { requestId, contentLength: content.length });
    const scanResult = await performScan(content, scanContext, compareBaseline, groqApiKey);
    
    // Cache result
    scanCache.set(cacheKey, { result: scanResult, timestamp: Date.now() });
    
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
            result_score: scanResult.parsed.score,
            result_label: scanResult.parsed.label,
            result_summary: scanResult.parsed.summary,
            full_result: scanResult.parsed,
            scan_context: scanContext,
            compare_mode: !!compareBaseline
          });
        }
      } catch (e) {
        log('WARN', 'Failed to save scan history', { error: e.message });
      }
    }
    
    log('INFO', 'Scan completed', { requestId, score: scanResult.parsed.score });
    
    res.json({
      ok: true,
      outputText: scanResult.outputText,
      parsed: scanResult.parsed,
      provider: scanResult.provider,
      model: scanResult.model,
      compareMode: !!compareBaseline,
      requestId,
      version: APP_VERSION
    });
    
  } catch (error) {
    log('ERROR', 'Scan endpoint error', { requestId, error: error.message });
    
    // NEVER return 500 - always return structured response
    res.status(200).json({
      ok: true,
      parsed: getFallbackResponse(error.message),
      provider: "groq",
      model: GROQ_MODEL,
      compareMode: false,
      requestId,
      version: APP_VERSION,
      fallback: true
    });
  }
});

// Clean expired cache entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of scanCache.entries()) {
    if (now - value.timestamp > SCAN_CACHE_MS) {
      scanCache.delete(key);
    }
  }
}, SCAN_CACHE_MS);

// Serve index.html for root
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Catch-all for SPA
app.get("*", (req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ ok: false, error: "API endpoint not found", requestId: res.locals.requestId });
  }
  res.sendFile(path.join(__dirname, "index.html"));
});

module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => {
    log('INFO', `AI Security Copilot v${APP_VERSION} started on port ${PORT}`);
    log('INFO', `Groq API: ${process.env.GROQ_API_KEY ? '✅ configured' : '❌ not configured'}`);
    log('INFO', `Supabase Auth: ${supabase ? '✅ enabled' : '❌ disabled'}`);
  });
}
