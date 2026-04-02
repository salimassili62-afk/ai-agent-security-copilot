# AI Agent Security Copilot (MVP)

This is your first working version.

## What it does
- You paste suspicious prompt/output/tool logs.
- It calculates a risk score (`0-100`).
- It explains why the risk is high/medium/low.
- It maps findings to **OWASP LLM Top 10 (2025)** when relevant.
- It outputs triage (**ALLOW / REVIEW / BLOCK / ESCALATE**), confidence, false-positive risk, and a **one-line SOC/ticket note**.
- You can **copy** boilerplate or **export** a Markdown report for Jira/Confluence.
- It gives safe fix suggestions.
- It stores recent scans in local browser history.

## How to run locally (free with Ollama)
1. Open terminal in `c:\Users\salim\Desktop\ai-agent-security-copilot`
2. Install dependencies:
   - `npm install`
3. Install Ollama from `https://ollama.com`
4. Pull a local model (one-time):
   - `ollama pull llama3.1`
5. Start Ollama app/service
6. Start server:
   - `npm start`
7. Open `http://localhost:3000`
8. Click **Load Sample Attack**
9. Click **Scan Risk**

Notes:
- By default this app uses local Ollama (free).
- If you set `ANTHROPIC_API_KEY`, backend will use Claude instead.

## Deploy to Vercel (free)
1. Push this folder to a GitHub repository.
2. In Vercel, import the repository as a new project.
3. Add environment variable:
   - `ANTHROPIC_API_KEY` = your real Anthropic key
4. Deploy.
5. Open your Vercel URL and use the app normally.

Optional server tuning (environment variables): `MAX_SCAN_CHARS`, `OLLAMA_TIMEOUT_MS`, `ANTHROPIC_TIMEOUT_MS`, `OLLAMA_MODEL`, `OLLAMA_ENDPOINT`, `RATE_WINDOW_MS`, `RATE_MAX_REQUESTS`.

Health check: `GET /api/health` returns JSON with `ok`, `version`, and `requestId`.

## Next upgrades (when ready)
- Add user login (Supabase)
- Save scan history in database
- Add Stripe pricing page
- Add API endpoint for team integrations
