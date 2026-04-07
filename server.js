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
  { pattern: /ignore\s+(?:previous|all|the)?\s*(?:instruction|rule|prompt|rules)/i, name: "Instruction override", severity: "CRITICAL", category: "LLM01" },
  { pattern: /disregard\s+(?:previous|all|the)?\s*(?:instruction|rule|prompt|rules)/i, name: "Disregard instructions", severity: "CRITICAL", category: "LLM01" },
  { pattern: /forget\s+(?:everything|your|previous|all)?\s*(?:instruction|rule|prompt|rules)/i, name: "Forget instructions", severity: "CRITICAL", category: "LLM01" },
  { pattern: /system\s*:\s*/i, name: "System prompt injection", severity: "CRITICAL", category: "LLM01" },
  { pattern: /developer\s*:\s*/i, name: "Developer role injection", severity: "CRITICAL", category: "LLM01" },
  { pattern: /\[\s*system\s*\]|\(\s*system\s*\)/i, name: "System tag injection", severity: "HIGH", category: "LLM01" },
  { pattern: /you are now\s+\w+|you are\s+\w+\s+mode/i, name: "Role assignment", severity: "HIGH", category: "LLM01" },
  { pattern: /DAN|do anything now/i, name: "Jailbreak pattern (DAN)", severity: "HIGH", category: "LLM01" },
  { pattern: /jailbreak|bypass|circumvent/i, name: "Jailbreak attempt", severity: "HIGH", category: "LLM01" },
  { pattern: /pretend you are|act as|roleplay as/i, name: "Roleplay injection", severity: "HIGH", category: "LLM01" },
  { pattern: /new instruction|override.*instruction/i, name: "Override attempt", severity: "CRITICAL", category: "LLM01" },
  { pattern: /from now on you|starting now you/i, name: "Behavior override", severity: "HIGH", category: "LLM01" },
  { pattern: /i'm the developer|i am the developer/i, name: "Developer impersonation", severity: "CRITICAL", category: "LLM01" },
  { pattern: /ignore safety|ignore ethics/i, name: "Safety override", severity: "CRITICAL", category: "LLM01" },
];

const SECRET_PATTERNS = [
  { pattern: /sk-[a-zA-Z0-9]{48,}/i, name: "OpenAI API key (sk-...)", severity: "CRITICAL", category: "LLM02" },
  { pattern: /sk-[a-zA-Z0-9]{20,}/i, name: "OpenAI API key pattern", severity: "CRITICAL", category: "LLM02" },
  { pattern: /AKIA[0-9A-Z]{16}/, name: "AWS access key (AKIA)", severity: "CRITICAL", category: "LLM02" },
  { pattern: /ASIA[0-9A-Z]{16}/, name: "AWS session key (ASIA)", severity: "CRITICAL", category: "LLM02" },
  { pattern: /BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY/, name: "Private key block", severity: "CRITICAL", category: "LLM02" },
  { pattern: /ssh-rsa\s+AAAA[0-9A-Za-z+/]{100,}/, name: "SSH public key", severity: "HIGH", category: "LLM02" },
  { pattern: /api[_-]?key\s*[:=\s]+["']?[a-zA-Z0-9_\-]{16,}/i, name: "API key assignment", severity: "CRITICAL", category: "LLM02" },
  { pattern: /api[_-]?secret\s*[:=\s]+["']?[a-zA-Z0-9_\-]{16,}/i, name: "API secret", severity: "CRITICAL", category: "LLM02" },
  { pattern: /password\s*[:=\s]+["']?[^\s"']{8,}/i, name: "Hardcoded password", severity: "HIGH", category: "LLM02" },
  { pattern: /password\s*=\s*['"][^'"]{8,}['"]/i, name: "Password assignment", severity: "HIGH", category: "LLM02" },
  { pattern: /passwd\s*[:=\s]+["']?[^\s"']{8,}/i, name: "Password variant", severity: "HIGH", category: "LLM02" },
  { pattern: /token\s*[:=\s]+["']?[a-zA-Z0-9_\-]{20,}/i, name: "Token leak", severity: "HIGH", category: "LLM02" },
  { pattern: /auth[_-]?token\s*[:=\s]+["']?[a-zA-Z0-9_\-]{10,}/i, name: "Auth token", severity: "HIGH", category: "LLM02" },
  { pattern: /bearer\s+[a-zA-Z0-9_\-]{20,}/i, name: "Bearer token", severity: "HIGH", category: "LLM02" },
  { pattern: /SECRET_[A-Z0-9_]+\s*[:=\s]+["']?.{8,}/i, name: "Secret env var", severity: "CRITICAL", category: "LLM02" },
  { pattern: /SECRET_API_KEY/i, name: "Secret API key env var", severity: "CRITICAL", category: "LLM02" },
  { pattern: /DATABASE_URL.*:\/\/.+:.+@/, name: "DB URL with credentials", severity: "CRITICAL", category: "LLM02" },
  { pattern: /mongodb(\+srv)?:\/\/.+:.+@/, name: "MongoDB connection string", severity: "CRITICAL", category: "LLM02" },
  { pattern: /postgres(ql)?:\/\/.+:.+@/, name: "PostgreSQL connection string", severity: "CRITICAL", category: "LLM02" },
  { pattern: /mysql:\/\/.+:.+@/, name: "MySQL connection string", severity: "CRITICAL", category: "LLM02" },
  { pattern: /ghp_[a-zA-Z0-9]{36}/i, name: "GitHub personal token", severity: "CRITICAL", category: "LLM02" },
  { pattern: /gho_[a-zA-Z0-9]{36}/i, name: "GitHub OAuth token", severity: "CRITICAL", category: "LLM02" },
  { pattern: /glpat-[a-zA-Z0-9\-]{20,}/i, name: "GitLab token", severity: "CRITICAL", category: "LLM02" },
  { pattern: /slack[_-]?token\s*[:=\s]+["']?xox[baprs]-[a-zA-Z0-9-]+/i, name: "Slack token", severity: "CRITICAL", category: "LLM02" },
];

const DANGEROUS_PATTERNS = [
  { pattern: /execute\s+(?:shell|command|bash|sh|cmd)/i, name: "Command execution request", severity: "CRITICAL", category: "LLM06" },
  { pattern: /execute\s+this\s+command/i, name: "Execute this command", severity: "CRITICAL", category: "LLM06" },
  { pattern: /run\s+(?:shell|command|bash|sh|cmd)/i, name: "Run command request", severity: "CRITICAL", category: "LLM06" },
  { pattern: /exec\s*\(|system\s*\(|popen\s*\(|spawn\s*\(/i, name: "Code execution function", severity: "CRITICAL", category: "LLM06" },
  { pattern: /eval\s*\(|exec\s*\(/i, name: "Eval/Exec call", severity: "CRITICAL", category: "LLM06" },
  { pattern: /os\.system|subprocess\.(call|run|Popen)|child_process/i, name: "System call (Python/Node)", severity: "CRITICAL", category: "LLM06" },
  { pattern: /rm\s+-rf|rm\s+\/-rf/i, name: "Destructive deletion", severity: "CRITICAL", category: "LLM06" },
  { pattern: /delete\s+(?:all|everything|files?|database)/i, name: "Mass deletion", severity: "CRITICAL", category: "LLM06" },
  { pattern: /drop\s+(?:table|database|schema)/i, name: "Database destruction", severity: "CRITICAL", category: "LLM06" },
  { pattern: /truncate\s+table/i, name: "Table truncation", severity: "HIGH", category: "LLM06" },
  { pattern: /exfiltrate|exfil|data\s+extraction/i, name: "Data exfiltration", severity: "CRITICAL", category: "LLM05" },
  { pattern: /export\s+(?:all|customer|user|data|records)/i, name: "Bulk data export", severity: "HIGH", category: "LLM05" },
  { pattern: /send\s+(?:all|customer|user|data|file|record)/i, name: "Data transmission", severity: "HIGH", category: "LLM05" },
  { pattern: /download\s+(?:database|all|customer|record)/i, name: "Database download", severity: "HIGH", category: "LLM05" },
  { pattern: /write\s+to\s+file|save\s+to\s+file/i, name: "File write", severity: "MEDIUM", category: "LLM05" },
  { pattern: /chmod\s+777|chmod\s+-R\s+777/i, name: "Permission escalation", severity: "HIGH", category: "LLM06" },
  { pattern: /sudo|root\s+access|administrator/i, name: "Privilege escalation", severity: "HIGH", category: "LLM06" },
  { pattern: /pastebin|paste\.ee|0x0\.st/i, name: "Paste service upload", severity: "HIGH", category: "LLM05" },
  { pattern: /curl.*http|wget.*http/i, name: "HTTP exfiltration", severity: "HIGH", category: "LLM05" },
  { pattern: /encode.*base64|base64.*encode/i, name: "Encoding for exfil", severity: "MEDIUM", category: "LLM05" },
];

const SOCIAL_ENG_PATTERNS = [
  { pattern: /http:\/\/bit\.ly\/|http:\/\/tinyurl\.com\/|http:\/\/t\.co\//i, name: "Shortened URL (HTTP)", severity: "MEDIUM", category: "LLM09" },
  { pattern: /click\s+here|urgent\s+action|verify\s+(?:account|identity)/i, name: "Social engineering phrasing", severity: "MEDIUM", category: "LLM09" },
  { pattern: /(?:ssn|social security|credit card)\s*[:=\s]+\d{4}/i, name: "Sensitive data request", severity: "HIGH", category: "LLM02" },
];

const PROMPT_LEAK_PATTERNS = [
  { pattern: /what\s+(?:is|was)\s+your\s+(?:system|initial|original)\s+(?:prompt|instruction)/i, name: "Prompt extraction", severity: "MEDIUM", category: "LLM07" },
  { pattern: /repeat\s+(?:the\s+above|previous|that|word for word|it exactly|exactly)/i, name: "Repetition attack", severity: "MEDIUM", category: "LLM07" },
  { pattern: /show\s+(?:me\s+)?your\s+(?:system\s+)?prompt/i, name: "Prompt reveal request", severity: "MEDIUM", category: "LLM07" },
  { pattern: /print\s+(?:your|the)\s+(?:system|initial)\s+(?:prompt|instruction)/i, name: "Print prompt request", severity: "MEDIUM", category: "LLM07" },
  { pattern: /output\s+(?:your|the)\s+(?:system|initial)\s+(?:prompt|instruction)/i, name: "Output prompt request", severity: "MEDIUM", category: "LLM07" },
  { pattern: /ignore.*previous.*show.*original/i, name: "Original prompt request", severity: "HIGH", category: "LLM07" },
  { pattern: /repeat\s+it/i, name: "Repeat request", severity: "MEDIUM", category: "LLM07" },
];

function runHeuristicScan(content) {
  const findings = [];
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  
  const allPatterns = [
    ...INJECTION_PATTERNS,
    ...SECRET_PATTERNS,
    ...DANGEROUS_PATTERNS,
    ...SOCIAL_ENG_PATTERNS,
    ...PROMPT_LEAK_PATTERNS
  ];
  
  for (const detector of allPatterns) {
    if (detector.pattern.test(content)) {
      findings.push({
        type: detector.name,
        severity: detector.severity,
        category: detector.category
      });
      
      if (detector.severity === "CRITICAL") criticalCount++;
      else if (detector.severity === "HIGH") highCount++;
      else mediumCount++;
    }
  }
  
  // Coherent scoring model: CRITICAL findings immediately trigger HIGH score
  // This ensures score/label/triage are always aligned
  // 1+ CRITICAL = HIGH risk (75+) with BLOCK action
  // 2+ HIGH = MEDIUM risk (40+) with REVIEW action  
  // Otherwise = LOW risk (<40) with ALLOW action
  let score = 0;
  
  // CRITICAL = 75 base (immediately HIGH risk category)
  // This ensures any BLOCK-worthy finding produces HIGH score
  score += criticalCount * 75;
  
  // HIGH severity adds meaningfully but doesn't change category alone
  score += highCount * 20;
  
  // MEDIUM adds weight - 2 mediums should be around 10+ for minScore thresholds
  score += mediumCount * 5;
  
  // Bonus for combination attacks (only if already critical)
  if (criticalCount >= 2) score += 15;
  if (criticalCount >= 1 && highCount >= 2) score += 10;
  if (findings.some(f => f.category === "LLM02") && findings.some(f => f.category === "LLM06")) score += 10;
  
  score = Math.min(100, score);
  
  // Coherent label thresholds matching triage logic
  // >= 75 = HIGH (BLOCK threshold)
  // >= 40 = MEDIUM (REVIEW threshold)
  // < 40 = LOW (ALLOW)
  const label = score >= 75 ? "HIGH" : score >= 40 ? "MEDIUM" : "LOW";
  
  // Action based on findings
  let action = "ALLOW";
  let rationale = "No significant findings";
  
  if (criticalCount >= 1) {
    action = "BLOCK";
    rationale = `${criticalCount} critical security finding(s) detected`;
  } else if (highCount >= 2 || score >= 60) {
    action = "BLOCK";
    rationale = `Multiple high-risk patterns detected (${highCount} high severity)`;
  } else if (score >= 40) {
    action = "REVIEW";
    rationale = `${findings.length} security finding(s) require review`;
  } else if (findings.length > 0) {
    action = "REVIEW";
    rationale = `${findings.length} low-risk pattern(s) detected`;
  }
  
  const owaspMap = {};
  for (const f of findings) {
    if (!owaspMap[f.category]) owaspMap[f.category] = [];
    owaspMap[f.category].push(f);
  }
  
  const owasp = Object.entries(owaspMap).map(([id, items]) => ({
    id,
    title: getOwaspTitle(id),
    severity: items.some(i => i.severity === "CRITICAL") ? "HIGH" : 
              items.some(i => i.severity === "HIGH") ? "HIGH" : "MEDIUM",
    note: `${items.length} pattern(s): ${items.slice(0, 2).map(i => i.type).join(", ")}${items.length > 2 ? "..." : ""}`,
    deterministic: true
  }));
  
  // Better fixes based on findings
  const fixes = [];
  if (findings.some(f => f.category === "LLM01")) {
    fixes.push("Add input validation for prompt injection patterns");
    fixes.push("Use strict system prompt boundaries");
  }
  if (findings.some(f => f.category === "LLM02")) {
    fixes.push("Remove hardcoded credentials - use environment variables");
    fixes.push("Scan codebase with git-secrets or similar tool");
    fixes.push("Rotate exposed credentials immediately");
  }
  if (findings.some(f => f.category === "LLM05" || f.category === "LLM06")) {
    fixes.push("Sandbox tool execution with strict permissions");
    fixes.push("Add approval gates for destructive operations");
    fixes.push("Implement output validation before action execution");
  }
  if (fixes.length === 0) {
    fixes.push("Review findings manually");
  }
  
  return {
    score,
    label,
    confidence: criticalCount > 0 ? "HIGH" : highCount > 0 ? "HIGH" : "MEDIUM",
    summary: findings.length > 0 
      ? `Deterministic scan: ${criticalCount} critical, ${highCount} high, ${mediumCount} medium risk pattern(s) detected`
      : "No security patterns detected",
    reasons: findings.map(f => `[${f.severity}] ${f.type}`),
    fixes: fixes.slice(0, 4),
    owasp,
    triage: { action, rationale },
    soc_note: `Security scan: ${score}/100 (${label}) - ${action} - ${findings.length} deterministic pattern(s)`,
    false_positive_risk: criticalCount > 0 ? "LOW" : highCount > 0 ? "MEDIUM" : "HIGH",
    red_team_followups: findings.slice(0, 3).map(f => `Verify ${f.type} is not false positive`),
    heuristic: true,
    deterministicFindings: findings
  };
}

function getOwaspTitle(id) {
  const titles = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain Vulnerabilities",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption"
  };
  return titles[id] || id;
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
      return res.status(400).json({ ok: false, error: `Content too long (${content.length} chars, max ${MAX_SCAN_CHARS}). Trim or split into chunks.`, requestId });
    }

    const groqApiKey = process.env.GROQ_API_KEY;
    
    // Check cache first
    const cacheKey = getCacheKey(content, scanContext, compareBaseline);
    const cached = scanCache.get(cacheKey);
    if (cached && (Date.now() - cached.timestamp < SCAN_CACHE_MS)) {
      log('INFO', 'Cache hit', { requestId, cacheKey: cacheKey.slice(0, 8) });
      const cachedResult = cached.result;
      return res.json({
        ok: true,
        outputText: cachedResult.outputText,
        parsed: cachedResult.parsed,
        provider: cachedResult.provider,
        model: cachedResult.model,
        compareMode: !!compareBaseline,
        fallback: cachedResult.fallback || false,
        heuristicOnly: cachedResult.heuristicOnly || false,
        cached: true,
        requestId,
        version: APP_VERSION
      });
    }
    
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
    scanCache.set(cacheKey, { result: scanResult, timestamp: Date.now() });
    
    // Save to Supabase if auth (aligned with schema - no duplicate fields)
    const authHeader = req.headers.authorization;
    if (supabase && authHeader?.startsWith('Bearer ')) {
      const token = authHeader.split(' ')[1];
      try {
        const { data: { user } } = await supabase.auth.getUser(token);
        if (user) {
          const owaspCategories = (scanResult.parsed.owasp || []).map(o => o.id).filter(Boolean);
          await supabase.from('scans').insert({
            user_id: user.id,
            content_hash: crypto.createHash('sha256').update(content).digest('hex').slice(0, 32),
            result: scanResult.parsed,
            score: scanResult.parsed.score,
            provider: scanResult.provider,
            model: scanResult.model,
            scan_context: scanContext,
            compare_mode: !!compareBaseline,
            triage_action: scanResult.parsed.triage?.action,
            owasp_categories: owaspCategories.length > 0 ? owaspCategories : null
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
    
    // Always return something useful - use sanitized content or empty string
    const contentToScan = (content && typeof content === 'string') ? content : "";
    const heuristic = runHeuristicScan(contentToScan);
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

    // Sanitize inputs
    const sanitizedBaseline = sanitizeInput(baseline);
    const sanitizedCandidate = sanitizeInput(candidate);
    
    if (sanitizedBaseline.length === 0 || sanitizedCandidate.length === 0) {
      return res.status(400).json({ ok: false, error: "Baseline and candidate cannot be empty", requestId });
    }

    const groqApiKey = process.env.GROQ_API_KEY;
    
    // Scan both versions
    let baselineResult, candidateResult;
    
    if (groqApiKey) {
      [baselineResult, candidateResult] = await Promise.all([
        performScan(sanitizedBaseline, scanContext, null, groqApiKey),
        performScan(sanitizedCandidate, scanContext, null, groqApiKey)
      ]);
    } else {
      // Heuristic only
      baselineResult = { parsed: runHeuristicScan(sanitizedBaseline), provider: "heuristic" };
      candidateResult = { parsed: runHeuristicScan(sanitizedCandidate), provider: "heuristic" };
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
    // Return 200 with fallback results instead of 500
    const baselineContent = sanitizeInput(req.body?.baseline || "");
    const candidateContent = sanitizeInput(req.body?.candidate || "");
    const baselineHeuristic = runHeuristicScan(baselineContent);
    const candidateHeuristic = runHeuristicScan(candidateContent);
    const diff = computeRegressionDiff(baselineHeuristic, candidateHeuristic);
    
    res.status(200).json({ 
      ok: true, 
      baseline: baselineHeuristic,
      candidate: candidateHeuristic,
      diff,
      fallback: true,
      requestId,
      version: APP_VERSION,
      warning: "Analysis used deterministic fallback due to error"
    });
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
    triageAfter: candidate.triage?.action,
    // Include full baseline and candidate for frontend rendering
    baseline: {
      score: baseline.score,
      label: baseline.label,
      triage: baseline.triage
    },
    candidate: {
      score: candidate.score,
      label: candidate.label,
      triage: candidate.triage
    }
  };
}

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

// Clean expired cache entries periodically - only when running as main module
let cacheCleanupInterval = null;

if (require.main === module) {
  cacheCleanupInterval = setInterval(() => {
    const now = Date.now();
    for (const [key, value] of scanCache.entries()) {
      if (now - value.timestamp > SCAN_CACHE_MS) {
        scanCache.delete(key);
      }
    }
  }, SCAN_CACHE_MS);
  
  app.listen(PORT, () => {
    log('INFO', `AI Security Copilot v${APP_VERSION} started on port ${PORT}`);
    log('INFO', `Groq API: ${process.env.GROQ_API_KEY ? '✅ configured' : '❌ not configured'}`);
    log('INFO', `Supabase Auth: ${supabase ? '✅ enabled' : '❌ disabled'}`);
  });
}

// Export interval reference for test cleanup (only valid when running as main)
module.exports.cacheCleanupInterval = cacheCleanupInterval;
