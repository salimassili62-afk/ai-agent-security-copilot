# AI Security Copilot - Deployment Guide

## Critical Issues Fix (One-Time Setup)

### 1. Fix "Invalid Redirect URI" Error (Supabase Auth)

**Problem**: Supabase Auth returns "Invalid Redirect URI" when users try to sign in with GitHub.

**Root Cause**: Your production domain is not whitelisted in Supabase's redirect URLs.

**Solution**:
1. Go to [Supabase Dashboard](https://app.supabase.com)
2. Select your project
3. Go to **Authentication → URL Configuration**
4. Add these URLs to **Redirect URLs**:
   ```
   https://ai-agent-security-copilot.vercel.app
   https://ai-agent-security-copilot.vercel.app/dashboard
   https://ai-agent-security-copilot.vercel.app/api/auth/callback
   http://localhost:3000  (for local dev)
   ```
5. Set **Site URL** to: `https://ai-agent-security-copilot.vercel.app`
6. Save changes

### 2. Fix "Rules-only Mode" (Enable AI Enhancement)

**Problem**: App shows "Running in deterministic mode" instead of using Groq AI.

**Root Cause**: `GROQ_API_KEY` environment variable is not set in Vercel.

**Solution**:
1. Get your Groq API key from [console.groq.com](https://console.groq.com)
2. Go to [Vercel Dashboard](https://vercel.com)
3. Select your project
4. Go to **Settings → Environment Variables**
5. Add:
   - Name: `GROQ_API_KEY`
   - Value: `gsk_your_groq_key_here`
   - Environment: Production (and Preview/Development if needed)
6. Click **Save**
7. Redeploy your app (Vercel → Deployments → Redeploy)

### 3. Enable Payments (Stripe)

**Problem**: No pricing page, checkout doesn't work, no Pro tier.

**Root Cause**: Stripe environment variables not configured.

**Solution**:

#### Step 1: Create Stripe Account & Products
1. Sign up at [stripe.com](https://stripe.com)
2. Go to **Products → Add Product**
3. Create two products:
   - **Professional Plan** - $19/month recurring
   - **Enterprise Plan** - $99/month recurring
4. Copy the **Price IDs** (they look like `price_1ABC...`)

#### Step 2: Get API Keys
1. In Stripe Dashboard, go to **Developers → API Keys**
2. Copy **Secret Key** (starts with `sk_live_` or `sk_test_`)
3. Go to **Developers → Webhooks**
4. Click **Add Endpoint**
   - URL: `https://ai-agent-security-copilot.vercel.app/api/stripe-webhook`
   - Events: `checkout.session.completed`, `customer.subscription.deleted`
5. Copy the **Signing Secret** (starts with `whsec_`)

#### Step 3: Add to Vercel
Add these environment variables:
```
STRIPE_SECRET_KEY=sk_live_... (or sk_test_... for testing)
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PUBLISHABLE_KEY=pk_live_... (or pk_test_...)
STRIPE_PRICE_PRO=price_... (your Pro plan price ID)
STRIPE_PRICE_TEAM=price_... (your Enterprise plan price ID)
```

#### Step 4: Configure Supabase Schema
Run this SQL in Supabase SQL Editor to create user profiles table:
```sql
-- User profiles table (extends Supabase auth.users)
CREATE TABLE IF NOT EXISTS user_profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  plan TEXT DEFAULT 'free' CHECK (plan IN ('free', 'pro', 'enterprise')),
  stripe_customer_id TEXT,
  stripe_subscription_id TEXT,
  scans_used INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- API keys table
CREATE TABLE IF NOT EXISTS api_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
  key_hash TEXT NOT NULL,
  name TEXT,
  created_at TIMESTAMP DEFAULT NOW(),
  last_used_at TIMESTAMP,
  revoked_at TIMESTAMP
);

-- Scans table (already exists, but ensure user_id column)
ALTER TABLE scans ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES auth.users(id);
```

### 4. GitHub OAuth Setup

**Problem**: GitHub login doesn't work.

**Solution**:
1. Go to [GitHub Developer Settings](https://github.com/settings/developers)
2. Click **OAuth Apps → New OAuth App**
3. Fill in:
   - **Application Name**: AI Security Copilot
   - **Homepage URL**: `https://ai-agent-security-copilot.vercel.app`
   - **Authorization Callback URL**: `https://your-project.supabase.co/auth/v1/callback`
     (Replace with your actual Supabase project URL)
4. Click **Register Application**
5. Copy **Client ID** and **Client Secret**
6. Go to Supabase Dashboard → Authentication → Providers → GitHub
7. Enable GitHub and paste the Client ID and Secret
8. Save

### 5. Verify Deployment

After completing all steps above:

1. Visit your app: `https://ai-agent-security-copilot.vercel.app`
2. Click "Sign in with GitHub" - should work without "Invalid Redirect URI" error
3. Run a scan - should show "AI + Security Rules" instead of "Security Rules"
4. Visit `/pricing` - should show pricing cards
5. Click "Get Pro" - should redirect to Stripe checkout

## Quick Environment Variable Checklist

Copy this into Vercel (all required for full functionality):

```
# Required for Auth
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_KEY=eyJ... (service role key)
SUPABASE_JWT_SECRET=your-jwt-secret

# Required for AI
GROQ_API_KEY=gsk_...

# Required for Payments
STRIPE_SECRET_KEY=sk_live_... (or sk_test_...)
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PUBLISHABLE_KEY=pk_live_... (or pk_test_...)
STRIPE_PRICE_PRO=price_...
STRIPE_PRICE_TEAM=price_...

# Optional (for error tracking)
SENTRY_DSN=...
```

## Testing Locally

Create `.env.local` file (never commit this):

```bash
# Copy from .env.example and fill in your values
cp .env.example .env.local
# Edit .env.local with your actual keys
```

Run:
```bash
npm install
npm run dev
```

Test:
- `http://localhost:3000` - Main app
- `http://localhost:3000/dashboard` - Dashboard (requires auth)
- `http://localhost:3000/pricing` - Pricing page
- `http://localhost:3000/api/health` - Health check

## Troubleshooting

### "Invalid Redirect URI" still happening?
- Double-check the redirect URL in Supabase matches exactly (including https://)
- Check browser console for exact error message
- Ensure you're using the correct Supabase project

### Groq API still not working?
- Check Vercel logs: `vercel logs --all`
- Verify key is set: `vercel env ls`
- Test key locally first

### Stripe checkout fails?
- Use test mode keys (`sk_test_`, `pk_test_`) for development
- Check Stripe Dashboard → Logs for webhook errors
- Verify webhook endpoint URL is correct

### Database errors?
- Run the SQL in Supabase SQL Editor
- Check RLS policies are not blocking access
- Verify service key has correct permissions

## Support

If issues persist after following this guide:
1. Check Vercel deployment logs
2. Check Supabase Auth logs
3. Verify all environment variables are set correctly
4. Test locally with `.env.local` first
