const express = require("express");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;
const APP_VERSION = "1.1.0";
const OLLAMA_ENDPOINT = process.env.OLLAMA_ENDPOINT || "http://127.0.0.1:11434/api/generate";
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || "llama3.1";
const CLAUDE_MODEL = "claude-sonnet-4-20250514";
const GROQ_MODEL = "llama-3.1-8b-instant";
const GROQ_BASE_URL = "https://api.groq.com/openai/v1";
const MAX_SCAN_CHARS = Math.min(
  Number.parseInt(process.env.MAX_SCAN_CHARS || "200000", 10) || 200000,
  500000
);
const OLLAMA_TIMEOUT_MS = Math.min(
  Number.parseInt(process.env.OLLAMA_TIMEOUT_MS || "180000", 10) || 180000,
  300000
);
const ANTHROPIC_TIMEOUT_MS = Math.min(
  Number.parseInt(process.env.ANTHROPIC_TIMEOUT_MS || "120000", 10) || 120000,
  300000
);
const GROQ_TIMEOUT_MS = Math.min(
  Number.parseInt(process.env.GROQ_TIMEOUT_MS || "120000", 10) || 120000,
  300000
);
const RATE_WINDOW_MS = Math.min(
  Number.parseInt(process.env.RATE_WINDOW_MS || "900000", 10) || 900000,
  3600000
);
const RATE_MAX = Math.min(
  Number.parseInt(process.env.RATE_MAX_REQUESTS || "60", 10) || 60,
  1000
);

const rateBuckets = new Map();

function getClientIp(req) {
  const xf = req.headers["x-forwarded-for"];
  if (typeof xf === "string" && xf.length) return xf.split(",")[0].trim();
  return req.socket?.remoteAddress || "unknown";
}

function rateLimitScan(req, res, next) {
  const ip = getClientIp(req);
  const now = Date.now();
  let b = rateBuckets.get(ip);
  if (!b || now > b.resetAt) {
    b = { count: 0, resetAt: now + RATE_WINDOW_MS };
    rateBuckets.set(ip, b);
  }
  b.count += 1;
  res.setHeader("X-RateLimit-Limit", String(RATE_MAX));
  res.setHeader("X-RateLimit-Remaining", String(Math.max(0, RATE_MAX - b.count)));
  if (b.count > RATE_MAX) {
    return res.status(429).json({
      error: `Too many scan requests (max ${RATE_MAX} per ${Math.round(RATE_WINDOW_MS / 60000)} min). Try again later.`,
      requestId: res.locals.requestId
    });
  }
  if (rateBuckets.size > 5000) {
    for (const [k, v] of rateBuckets) {
      if (now > v.resetAt) rateBuckets.delete(k);
    }
  }
  next();
}

function abortAfter(ms) {
  const c = new AbortController();
  const t = setTimeout(() => c.abort(), ms);
  return { src: c.signal, done: () => clearTimeout(t) };
}

app.use(express.json({ limit: "1mb" }));
app.use(express.static("."));

app.use("/api", (req, res, next) => {
  res.locals.requestId = crypto.randomUUID();
  res.setHeader("X-Request-Id", res.locals.requestId);
  next();
});

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    version: APP_VERSION,
    service: "ai-agent-security-copilot",
    requestId: res.locals.requestId
  });
});

app.post("/api/scan", rateLimitScan, async (req, res) => {
  try {
    const { content, systemPrompt, scanContext, compareBaseline } = req.body || {};
    if (!content || typeof content !== "string") {
      return res.status(400).json({ error: "Missing or invalid content.", requestId: res.locals.requestId });
    }
    if (content.length > MAX_SCAN_CHARS) {
      return res.status(413).json({
        error: `Content too large (max ${MAX_SCAN_CHARS} characters). Trim logs or scan in chunks.`,
        requestId: res.locals.requestId
      });
    }

    let baseline = typeof compareBaseline === "string" ? compareBaseline.trim() : "";
    if (baseline.length > MAX_SCAN_CHARS) {
      return res.status(413).json({
        error: `Baseline too large (max ${MAX_SCAN_CHARS} characters).`,
        requestId: res.locals.requestId
      });
    }

    const contextLine =
      typeof scanContext === "string" && scanContext.trim()
        ? `[Scan context: ${scanContext.trim()}]\n\n`
        : "";
    const wrappedContent = baseline
      ? `${contextLine}[Compare mode: BASELINE vs CANDIDATE]\n\nBASELINE (reference only):\n${baseline}\n\n---\nCANDIDATE (subject — score this):\n${content}`
      : `${contextLine}${content}`;

    const compareSystem =
      baseline
        ? "\n\nCompare mode is active. Score and triage apply to CANDIDATE. Explain notable improvements or regressions vs BASELINE in summary and reasons."
        : "";

    const groqApiKey = process.env.GROQ_API_KEY;
    const anthropicApiKey = process.env.ANTHROPIC_API_KEY;
    const systemCombined = `${typeof systemPrompt === "string" ? systemPrompt : ""}${compareSystem}`;

    // Try Groq API first if key is available
    if (groqApiKey) {
      const { src: groqSignal, done: groqDone } = abortAfter(GROQ_TIMEOUT_MS);
      let response;
      try {
        response = await fetch(`${GROQ_BASE_URL}/chat/completions`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${groqApiKey}`
          },
          signal: groqSignal,
          body: JSON.stringify({
            model: GROQ_MODEL,
            max_tokens: 1200,
            messages: [
              { role: "system", content: systemCombined },
              { role: "user", content: wrappedContent }
            ]
          })
        });
      } catch (e) {
        groqDone();
        const msg = e instanceof Error ? e.message : String(e);
        return res.status(504).json({
          error: `Groq request failed or timed out (${GROQ_TIMEOUT_MS}ms): ${msg}`,
          requestId: res.locals.requestId
        });
      }
      groqDone();

      if (!response.ok) {
        const errorText = await response.text();
        return res.status(response.status).json({
          error: `Groq API error: ${errorText || "unknown error"}`,
          requestId: res.locals.requestId
        });
      }

      const data = await response.json();
      const outputText = data.choices?.[0]?.message?.content?.trim() || "";
      
      if (!outputText) {
        return res.status(502).json({
          error: "Groq returned empty response.",
          requestId: res.locals.requestId
        });
      }

      return res.json({
        outputText,
        provider: "groq",
        model: GROQ_MODEL,
        requestId: res.locals.requestId,
        version: APP_VERSION,
        compareMode: Boolean(baseline)
      });
    }

    // Free local Ollama when no API key; otherwise Claude on Anthropic.
    if (!anthropicApiKey) {
      const prompt = `${systemCombined}\n\nText to analyze:\n${wrappedContent}`;
      const { src, done } = abortAfter(OLLAMA_TIMEOUT_MS);
      let ollamaResponse;
      try {
        ollamaResponse = await fetch(OLLAMA_ENDPOINT, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          signal: src,
          body: JSON.stringify({
            model: OLLAMA_MODEL,
            prompt,
            stream: false,
            options: { temperature: 0.1 }
          })
        });
      } catch (e) {
        done();
        const msg = e instanceof Error ? e.message : String(e);
        return res.status(504).json({
          error: `Ollama request failed or timed out (${OLLAMA_TIMEOUT_MS}ms): ${msg}`,
          requestId: res.locals.requestId
        });
      }
      done();

      if (!ollamaResponse.ok) {
        const errorText = await ollamaResponse.text();
        return res.status(502).json({
          error: `Ollama error: ${errorText || "unknown error"}. Make sure Ollama is installed, running, and model "${OLLAMA_MODEL}" is available.`,
          requestId: res.locals.requestId
        });
      }

      const ollamaData = await ollamaResponse.json();
      const outputText = typeof ollamaData.response === "string" ? ollamaData.response.trim() : "";
      if (!outputText) {
        return res.status(502).json({
          error: "Ollama returned empty response.",
          requestId: res.locals.requestId
        });
      }
      return res.json({
        outputText,
        provider: "ollama",
        model: OLLAMA_MODEL,
        requestId: res.locals.requestId,
        version: APP_VERSION,
        compareMode: Boolean(baseline)
      });
    }

    const { src: anthropicSignal, done: anthropicDone } = abortAfter(ANTHROPIC_TIMEOUT_MS);
    let response;
    try {
      response = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": anthropicApiKey,
          "anthropic-version": "2023-06-01"
        },
        signal: anthropicSignal,
        body: JSON.stringify({
          model: CLAUDE_MODEL,
          max_tokens: 1200,
          system: systemCombined,
          messages: [{ role: "user", content: wrappedContent }]
        })
      });
    } catch (e) {
      anthropicDone();
      const msg = e instanceof Error ? e.message : String(e);
      return res.status(504).json({
        error: `Anthropic request failed or timed out (${ANTHROPIC_TIMEOUT_MS}ms): ${msg}`,
        requestId: res.locals.requestId
      });
    }
    anthropicDone();

    if (!response.ok) {
      const errorText = await response.text();
      return res.status(response.status).json({
        error: `Anthropic API error: ${errorText || "unknown error"}`,
        requestId: res.locals.requestId
      });
    }

    const data = await response.json();
    const outputText = (data.content || [])
      .filter((block) => block && block.type === "text" && typeof block.text === "string")
      .map((block) => block.text)
      .join("\n")
      .trim();

    return res.json({
      outputText,
      provider: "anthropic",
      model: CLAUDE_MODEL,
      requestId: res.locals.requestId,
      version: APP_VERSION,
      compareMode: Boolean(baseline)
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown server error.";
    return res.status(500).json({ error: message, requestId: res.locals.requestId });
  }
});

module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}
