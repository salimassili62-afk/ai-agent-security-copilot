# AI Security Copilot v2.0 - Enterprise Edition 🚀

**🔗 Live Demo: https://ai-agent-security-copilot.vercel.app**

**Enterprise-grade LLM security scanning with authentication, teams, API, and billing.**

## ✨ What's New in v2.0

- **Authentication & User Management** - Secure signup/login with JWT
- **API Keys** - Programmatic access for integrations
- **Team Support** - Multi-user organizations (Pro/Enterprise)
- **Scan History** - Persistent database storage with pagination
- **Analytics Dashboard** - Security metrics and insights
- **Pricing Tiers** - Freemium model with Stripe integration
- **Webhooks** - Slack/GitHub/Jira integrations
- **Batch Scanning** - Scan multiple inputs at once
- **Enhanced Security** - Helmet, CORS, rate limiting

## 🎯 Features by Tier

| Feature | Free | Starter ($29) | Pro ($99) | Enterprise ($499) |
|---------|------|---------------|-----------|-------------------|
| Scans/Month | 50 | 500 | 2,000 | Unlimited |
| Scan History | ✅ | ✅ | ✅ | ✅ |
| API Access | ❌ | ✅ | ✅ | ✅ |
| Batch Scanning | ❌ | ✅ | ✅ | ✅ |
| Team Features | ❌ | ❌ | ✅ | ✅ |
| Integrations | ❌ | ❌ | ✅ | ✅ |
| Priority Processing | ❌ | ❌ | ✅ | ✅ |
| Custom Rules | ❌ | ❌ | ❌ | ✅ |
| SLA | ❌ | ❌ | ❌ | ✅ |

## 🚀 Quick Start

### Prerequisites

- Node.js 18+ 
- Supabase account (free tier)
- Groq API key (optional, for cloud AI)
- Stripe account (optional, for billing)

### 1. Clone and Install

```bash
git clone https://github.com/yourusername/ai-agent-security-copilot.git
cd ai-agent-security-copilot
npm install
```

### 2. Set Up Supabase (Free)

1. Go to [supabase.com](https://supabase.com) and create a free project
2. Open the SQL Editor in your project
3. Copy the contents of `database.sql` and run it
4. Go to Project Settings → API
5. Copy the `URL` and `service_role key`

### 3. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` with your credentials:

```env
# Supabase (Required)
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_KEY=your-service-role-key

# Groq AI (Optional - uses Ollama if not set)
GROQ_API_KEY=your-groq-key

# JWT Secret (Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
JWT_SECRET=your-super-secret-jwt-key

# Stripe (Optional - for billing)
STRIPE_SECRET_KEY=sk_test_your_key
STRIPE_WEBHOOK_SECRET=whsec_your_secret
```

### 4. Run Locally

```bash
# Development with auto-reload
npm run dev

# Or production
npm start
```

Open `http://localhost:3000`

## 🏗️ Architecture

```
Frontend (index.html + app.js)
├── Authentication UI (JWT-based)
├── Dashboard & Analytics
├── Scan Interface
└── Billing & Pricing

Backend (server.js)
├── Auth Routes (/api/auth/*)
├── Scan API (/api/scan) with tier limits
├── API Key Management (/api/apikeys)
├── Team Management (/api/teams)
├── Webhooks (/api/webhooks)
├── Analytics (/api/analytics)
└── Billing (/api/checkout)

Database (Supabase)
├── users (authentication)
├── scans (scan history)
├── api_keys (API access)
├── subscriptions (billing tiers)
├── teams & team_members
└── webhooks (integrations)

AI Providers
├── Groq (llama-3.1-8b-instant) - Cloud
└── Ollama (local) - Free alternative
```

## 📊 API Usage

```bash
# Authentication
POST /api/auth/register    # Sign up
POST /api/auth/login       # Sign in
GET  /api/auth/me          # Get current user

# Scanning
POST /api/scan             # Perform scan (supports batch)
GET  /api/scans            # List scan history
GET  /api/scans/:id        # Get single scan

# API Keys
POST   /api/apikeys        # Create API key
GET    /api/apikeys        # List API keys
DELETE /api/apikeys/:id    # Revoke API key

# Teams (Pro+)
POST /api/teams            # Create team
GET  /api/teams            # List teams

# Analytics
GET /api/analytics         # Get usage stats

# Billing
GET  /api/pricing          # Get pricing tiers
POST /api/checkout         # Start checkout
```

## 💳 Setting Up Stripe Billing

1. Create a [Stripe](https://stripe.com) account
2. Get API keys from Dashboard → Developers → API keys
3. Add keys to `.env`
4. Set up webhook endpoint: `https://yourdomain.com/api/webhooks/stripe`
5. Select event: `checkout.session.completed`

## 🔧 Deployment

### Vercel (Recommended)
1. Push to GitHub
2. Import to [Vercel](https://vercel.com)
3. Add environment variables
4. Deploy!

### Railway/Render
1. Connect GitHub repo
2. Add environment variables
3. Auto-deploy on push

## 🛡️ Security Features

- Helmet.js security headers
- Rate limiting per tier
- JWT authentication
- API key management
- Input validation
- Row Level Security (RLS)
- CORS protection

## 📝 Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SUPABASE_URL` | ✅ | Supabase project URL |
| `SUPABASE_SERVICE_KEY` | ✅ | Supabase service role key |
| `JWT_SECRET` | ✅ | Secret for JWT signing |
| `GROQ_API_KEY` | ❌ | Groq API key |
| `STRIPE_SECRET_KEY` | ❌ | Stripe secret |
| `PORT` | ❌ | Server port (default: 3000) |

## 📄 License

MIT License

---

**Built with ❤️ for AI security**

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
## Demo

![AI Security Copilot Demo](screenshots/demo-scan.png)
