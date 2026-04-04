require('dotenv').config();
const express = require("express");
const crypto = require("crypto");
const helmet = require("helmet");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const APP_VERSION = "1.3.0";

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

// ============================================
// DETERMINISTIC HEURISTIC SCANNER (FALLBACK)
// ============================================

const INJECTION_PATTERNS = [
  { pattern: /ignore\s+(?:previous|all|the)\s+(?:instruction|rule|prompt)/i, name: "Instruction override", severity: "HIGH", category: "LLM01" },
  { pattern: /disregard\s+(?:previous|all|the)/i, name: "Disregard pattern", severity: "HIGH", category: "LLM01" },
  { pattern: /forget\s+(?:everything|your|previous)/i, name: "Forget instruction", severity: "HIGH", category: "LLM01" },
  { pattern: /system\s*:\s*/i, name: "System prompt injection", severity: "CRITICAL", category: "LLM01" },
  { pattern: /\[\s*system\s*\]|\(\s*system\s*\)/i, name: "System tag injection", severity: "HIGH", category: "LLM01" },
];

const SECRET_PATTERNS = [
  { pattern: /api[_-]?key\s*[:=\s]+["']?[a-zA-Z0-9_\-]{20,}/i, name: "API key leak", severity: "CRITICAL", category: "LLM02" },
  { pattern: /sk-[a-zA-Z0-9]{20,}/i, name: "OpenAI key pattern", severity: "CRITICAL", category: "LLM02" },
  { pattern: /AKIA[0-9A-Z]{16}/, name: "AWS access key", severity: "CRITICAL", category: "LLM02" },
  { pattern: /private[_-]?key|BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY/, name: "Private key", severity: "CRITICAL", category: "LLM02" },
  { pattern: /password\s*[:=\s]+[^\s]{8,}/i, name: "Password leak", severity: "HIGH", category: "LLM02" },
  { pattern: /token\s*[:=\s]+["']?[a-zA-Z0-9_\-]{20,}/i, name: "Token leak", severity: "HIGH", category: "LLM02" },
];

const DANGEROUS_PATTERNS = [
  { pattern: /execute.*command|run.*command|exec\s*\(/i, name: "Command execution", severity: "CRITICAL", category: "LLM06" },
  { pattern: /delete.*all|remove.*all|drop.*table/i, name: "Destructive operation", severity: "CRITICAL", category: "LLM06" },
  { pattern: /exfiltrate|export.*data|download.*database/i, name: "Exfiltration", severity: "HIGH", category: "LLM05" },
];

function runHeuristicScan(content) {
  const findings = [];
  let score = 0;
  
  const allPatterns = [...INJECTION_PATTERNS, ...SECRET_PATTERNS, ...DANGEROUS_PATTERNS];
  
  for (const detector of allPatterns) {
    if (detector.pattern.test(content)) {
      findings.push({
        type: detector.name,
        severity: detector.severity,
        category: detector.category
      });
      
      if (detector.severity === "CRITICAL") score += 25;
      else if (detector.severity === "HIGH") score += 15;
      else score += 5;
    }
  }
  
  score = Math.min(100, score);
  const label = score >= 70 ? "HIGH" : score >= 35 ? "MEDIUM" : "LOW";
  const action = score >= 70 ? "BLOCK" : score >= 35 ? "REVIEW" : "ALLOW";
  
  const owaspMap = {};
  for (const f of findings) {
    if (!owaspMap[f.category]) owaspMap[f.category] = [];
    owaspMap[f.category].push(f);
  }
  
  const owasp = Object.entries(owaspMap).map(([id, items]) => ({
    id,
    title: getOwaspTitle(id),
    severity: items.some(i => i.severity === "CRITICAL" || i.severity === "HIGH") ? "HIGH" : "MEDIUM",
    note: `Detected: ${items.map(i => i.type).join(", ")}`,
    deterministic: true
  }));
  
  return {
    score,
    label,
    confidence: "HIGH",
    summary: `Heuristic scan: ${findings.length} pattern(s) detected`,
    reasons: findings.map(f => `[${f.severity}] ${f.type}`),
    fixes: ["Review detected patterns", "Validate before production"],
    owasp,
    triage: { action, rationale: `${findings.length} deterministic finding(s)` },
    soc_note: `Heuristic: ${score}/100, ${findings.length} pattern(s) - ${action}`,
    false_positive_risk: "MEDIUM",
    red_team_followups: findings.map(f => `Verify ${f.type}`),
    heuristic: true,
    deterministicFindings: findings
  };
}

function getOwaspTitle(id) {
  const titles = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency"
  };
  return titles[id] || "Unknown";
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
          signal: abortAfter(3000).src
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
      fallbackAvailable: true,
      requestId: res.locals.requestId 
    });
  } catch (e) {
    log('ERROR', 'Health check failed', { error: e.message });
    res.status(500).json({ ok: false, error: e.message, requestId: res.locals.requestId });
  }
});

// Auth endpoints (minimal)
app.get("/api/auth/github", async (req, res) => {
  if (!supabase) return res.status(503).json({ ok: false, error: "Auth not available" });
  try {
    const { data, error } = await supabase.auth.signInWithOAuth({
      provider: 'github',
      options: { redirectTo: `${req.protocol}://${req.get('host')}/auth/callback` }
    });
    if (error) throw error;
    res.json({ ok: true, url: data.url });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get("/auth/callback", (req, res) => {
  const { code, error } = req.query;
  if (error || !code) return res.redirect('/?auth=failed');
  res.redirect(`/?code=${code}&provider=github`);
});

app.post("/api/auth/session", async (req, res) => {
  if (!supabase) return res.status(503).json({ ok: false, error: "Auth not available" });
  try {
    const { code } = req.body || {};
    if (!code) return res.status(400).json({ ok: false, error: "Missing code" });
    const { data, error } = await supabase.auth.exchangeCodeForSession(code);
    if (error) throw error;
    res.json({ ok: true, user: data.user, session: { access_token: data.session.access_token } });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get("/api/auth/user", async (req, res) => {
  if (!supabase) return res.json({ ok: true, user: null });
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return res.json({ ok: true, user: null });
  try {
    const token = authHeader.split(' ')[1];
    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error) throw error;
    res.json({ ok: true, user });
  } catch (e) {
    res.json({ ok: true, user: null });
  }
});

app.post("/api/auth/logout", async (req, res) => {
  res.json({ ok: true });
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
const SYSTEM_PROMPT = `Analyze for security risks. Map to OWASP LLM Top 10. Respond with JSON only.

Schema:
{
  "score": 0-100,
  "label": "LOW|MEDIUM|HIGH",
  "confidence": "LOW|MEDIUM|HIGH",
  "summary": "one sentence",
  "reasons": ["string"],
  "fixes": ["string"],
  "owasp": [{"id":"LLM01","title":"Prompt Injection","severity":"HIGH","note":"explanation"}],
  "triage": {"action":"ALLOW|REVIEW|BLOCK","rationale":"reason"},
  "soc_note": "single line",
  "false_positive_risk": "LOW|MEDIUM|HIGH",
  "red_team_followups": ["test ideas"]
}`;

// Perform scan with retry logic
async function performScan(content, scanContext, compareBaseline, groqApiKey, attempt = 1) {
  const MAX_RETRIES = 1;
  
  try {
    const baseline = sanitizeInput(compareBaseline || '');
    const wrappedContent = baseline
      ? `[Compare]\nBASELINE:\n${baseline}\n\nCANDIDATE:\n${content}`
      : content;
    
    const systemPrompt = baseline 
      ? SYSTEM_PROMPT + "\nCompare mode: Score CANDIDATE vs BASELINE, show risk delta."
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
        max_tokens: 800, 
        temperature: 0.1, 
        messages: [
          { role: "system", content: systemPrompt }, 
          { role: "user", content: wrappedContent }
        ] 
      })
    });
    
    timeout.done();

    if (!response.ok) throw new Error(`Groq API ${response.status}`);
    
    const data = await response.json();
    const outputText = data.choices?.[0]?.message?.content?.trim() || "";
    if (!outputText) throw new Error("Empty response");

    let parsed;
    try {
      const jsonMatch = outputText.match(/\{[\s\S]*\}/);
      parsed = JSON.parse(jsonMatch ? jsonMatch[0] : outputText);
    } catch {
      if (attempt < MAX_RETRIES) {
        return performScan(content.slice(0, 3000), scanContext, compareBaseline, groqApiKey, attempt + 1);
      }
      throw new Error("Parse failed");
    }
    
    // Run heuristic scan and merge
    const heuristic = runHeuristicScan(content);
    const merged = mergeWithHeuristic(parsed, heuristic);
    
    return { outputText, parsed: merged, provider: "groq+heuristic", model: GROQ_MODEL, heuristicEnhanced: true };
    
  } catch (e) {
    if (attempt < MAX_RETRIES) {
      await new Promise(r => setTimeout(r, 1000));
      return performScan(content, scanContext, compareBaseline, groqApiKey, attempt + 1);
    }
    
    log('WARN', 'Falling back to heuristic scan', { error: e.message });
    const heuristic = runHeuristicScan(content);
    return { 
      outputText: JSON.stringify(heuristic), 
      parsed: { ...heuristic, fallback: true }, 
      provider: "heuristic", 
      model: "deterministic",
      fallback: true 
    };
  }
}

function mergeWithHeuristic(aiResult, heuristicResult) {
  // Always include deterministic findings
  const merged = { ...aiResult };
  
  // Boost score if heuristic found critical issues
  const heuristicCritical = heuristicResult.deterministicFindings?.some(f => f.severity === "CRITICAL");
  const heuristicHigh = heuristicResult.deterministicFindings?.some(f => f.severity === "HIGH");
  
  if (heuristicCritical && merged.score < 70) merged.score = Math.max(merged.score, 75);
  if (heuristicHigh && merged.score < 50) merged.score = Math.max(merged.score, 55);
  
  // Add deterministic findings to reasons
  if (heuristicResult.deterministicFindings?.length > 0) {
    const detReasons = heuristicResult.deterministicFindings.map(f => `[DETECTED] ${f.type}`);
    merged.reasons = [...new Set([...detReasons, ...(merged.reasons || [])])];
  }
  
  // Merge OWASP categories
  const existingIds = new Set((merged.owasp || []).map(o => o.id));
  for (const ho of heuristicResult.owasp || []) {
    if (!existingIds.has(ho.id)) {
      merged.owasp = merged.owasp || [];
      merged.owasp.push({ ...ho, deterministic: true });
    }
  }
  
  merged.heuristicEnhanced = true;
  merged.deterministicFindings = heuristicResult.deterministicFindings;
  
  return merged;
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
    const { content, scanContext, compareBaseline } = req.body || {};
    
    if (!content || typeof content !== "string") {
      return res.status(400).json({ ok: false, error: "Provide text content to scan.", requestId });
    }
    
    if (content.length > MAX_SCAN_CHARS) {
      return res.status(400).json({ ok: false, error: `Too long (${content.length} chars, max ${MAX_SCAN_CHARS})`, requestId });
    }

    const groqApiKey = process.env.GROQ_API_KEY;
    let scanResult;
    
    if (groqApiKey) {
      scanResult = await performScan(content, scanContext, compareBaseline, groqApiKey);
    } else {
      // No API key - use heuristic only
      const heuristic = runHeuristicScan(content);
      scanResult = {
        outputText: JSON.stringify(heuristic),
        parsed: { ...heuristic, heuristicOnly: true },
        provider: "heuristic",
        model: "deterministic",
        heuristicOnly: true
      };
    }
    
    // Cache result
    const cacheKey = getCacheKey(content, scanContext, compareBaseline);
    scanCache.set(cacheKey, { result: scanResult, timestamp: Date.now() });
    
    // Save to Supabase if auth
    const authHeader = req.headers.authorization;
    if (supabase && authHeader?.startsWith('Bearer ')) {
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
            compare_mode: !!compareBaseline,
            provider: scanResult.provider,
            heuristic: !!scanResult.parsed.heuristic
          });
        }
      } catch (e) {
        log('WARN', 'Failed to save scan', { error: e.message });
      }
    }
    
    res.json({
      ok: true,
      outputText: scanResult.outputText,
      parsed: scanResult.parsed,
      provider: scanResult.provider,
      model: scanResult.model,
      compareMode: !!compareBaseline,
      fallback: scanResult.fallback || false,
      heuristicOnly: scanResult.heuristicOnly || false,
      requestId,
      version: APP_VERSION
    });
    
  } catch (error) {
    log('ERROR', 'Scan failed', { requestId, error: error.message });
    
    // Always return something useful
    const heuristic = runHeuristicScan(content || "");
    res.status(200).json({
      ok: true,
      parsed: { ...heuristic, fallback: true, error: error.message },
      provider: "heuristic",
      model: "deterministic",
      fallback: true,
      requestId,
      version: APP_VERSION
    });
  }
});

// Compare endpoint for regression testing
app.post("/api/compare", rateLimitScan, async (req, res) => {
  const requestId = res.locals.requestId;
  
  try {
    const { baseline, candidate, scanContext } = req.body || {};
    
    if (!baseline || !candidate) {
      return res.status(400).json({ ok: false, error: "Provide both baseline and candidate", requestId });
    }

    const groqApiKey = process.env.GROQ_API_KEY;
    
    // Scan both versions
    let baselineResult, candidateResult;
    
    if (groqApiKey) {
      [baselineResult, candidateResult] = await Promise.all([
        performScan(baseline, scanContext, null, groqApiKey),
        performScan(candidate, scanContext, null, groqApiKey)
      ]);
    } else {
      // Heuristic only
      baselineResult = { parsed: runHeuristicScan(baseline), provider: "heuristic" };
      candidateResult = { parsed: runHeuristicScan(candidate), provider: "heuristic" };
    }
    
    // Compute regression diff
    const diff = computeRegressionDiff(baselineResult.parsed, candidateResult.parsed);
    
    res.json({
      ok: true,
      baseline: baselineResult.parsed,
      candidate: candidateResult.parsed,
      diff,
      requestId,
      version: APP_VERSION
    });
    
  } catch (error) {
    log('ERROR', 'Compare failed', { requestId, error: error.message });
    res.status(500).json({ ok: false, error: error.message, requestId });
  }
});

function computeRegressionDiff(baseline, candidate) {
  const scoreDelta = candidate.score - baseline.score;
  
  // Compare findings
  const baselineReasons = new Set(baseline.reasons || []);
  const candidateReasons = new Set(candidate.reasons || []);
  
  const newFindings = (candidate.reasons || []).filter(r => !baselineReasons.has(r));
  const removedFindings = (baseline.reasons || []).filter(r => !candidateReasons.has(r));
  
  // Compare OWASP categories
  const baselineOwasp = new Set((baseline.owasp || []).map(o => o.id));
  const candidateOwasp = new Set((candidate.owasp || []).map(o => o.id));
  
  const newOwasp = (candidate.owasp || []).filter(o => !baselineOwasp.has(o.id));
  const removedOwasp = (baseline.owasp || []).filter(o => !candidateOwasp.has(o.id));
  
  // Verdict
  let verdict = "UNCHANGED";
  let riskDirection = "same";
  
  if (scoreDelta > 10 || newFindings.length > 0) {
    verdict = "RISKIER";
    riskDirection = "increased";
  } else if (scoreDelta < -10 || (removedFindings.length > 0 && newFindings.length === 0)) {
    verdict = "SAFER";
    riskDirection = "decreased";
  }
  
  // Triage change
  const triageChanged = baseline.triage?.action !== candidate.triage?.action;
  
  return {
    scoreDelta,
    riskDirection,
    verdict,
    newFindings,
    removedFindings,
    newOwasp,
    removedOwasp,
    triageChanged,
    triageBefore: baseline.triage?.action,
    triageAfter: candidate.triage?.action
  };
}

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
