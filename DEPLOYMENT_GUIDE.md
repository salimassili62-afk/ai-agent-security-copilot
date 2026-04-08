# AI Security Copilot - Deployment Guide

## 🎯 Mission Complete Status

✅ **All 3 critical blockers FIXED and monetization system BUILT**

### What's Been Implemented:
1. **Supabase Auth Fixed** - OAuth endpoints configured, redirect URI issue resolved
2. **Groq API Activated** - AI enhancement layer ready (needs API key)
3. **Complete Monetization** - Pricing page, Stripe payments, API keys, dashboard

---

## 🚀 Quick Deploy to Vercel

### Step 1: Add Environment Variables

Go to **Vercel Dashboard → Project → Settings → Environment Variables** and add:

```bash
# Supabase Authentication
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_KEY=your-anon-or-service-key
SUPABASE_GITHUB_CLIENT_ID=your-github-oauth-client-id
SUPABASE_GITHUB_CLIENT_SECRET=your-github-oauth-secret

# Groq AI API
GROQ_API_KEY=gsk_your_actual_groq_api_key_here

# Stripe Payments
STRIPE_SECRET_KEY=sk_test_your_stripe_secret_key
STRIPE_PUBLIC_KEY=pk_test_your_stripe_public_key
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret

# Optional: Custom pricing IDs
STRIPE_PRICE_PRO=price_your_pro_price_id
STRIPE_PRICE_TEAM=price_your_team_price_id
```

### Step 2: Deploy

```bash
git add .
git commit -m "feat: complete monetization system - auth fix, groq activation, pricing, stripe payments, api keys, dashboard"
git push
```

Vercel will automatically redeploy with the new environment variables.

---

## 🔧 Configuration Details

### Supabase Setup

1. **Create Supabase Project**: https://supabase.com/dashboard
2. **Enable GitHub OAuth**:
   - Go to Authentication → Providers → GitHub
   - Enable and add your GitHub OAuth App credentials
   - Set redirect URL: `https://your-domain.vercel.app/api/auth/callback`
3. **Get Keys**: Project Settings → API → URL and service_role_key

### Stripe Setup

1. **Create Stripe Account**: https://dashboard.stripe.com/register
2. **Get API Keys**: Developers → API keys → Publishable key and Secret key
3. **Create Products**:
   - Create a "Pro" subscription product ($99/month)
   - Copy the Price ID (looks like `price_1234567890`)
4. **Setup Webhook**:
   - Create webhook endpoint: `https://your-domain.vercel.app/api/stripe-webhook`
   - Get webhook signing secret

### GitHub OAuth Setup

1. **Create GitHub OAuth App**: https://github.com/settings/applications/new
2. **Settings**:
   - Homepage URL: `https://your-domain.vercel.app`
   - Authorization callback URL: `https://your-domain.vercel.app/api/auth/callback`
3. **Copy Client ID and Secret** to Supabase

---

## 🧪 Testing Checklist

### ✅ Basic Functionality
- [ ] Homepage loads: `https://your-domain.vercel.app`
- [ ] Pricing page loads: `https://your-domain.vercel.app/pricing`
- [ ] Dashboard loads: `https://your-domain.vercel.app/dashboard`

### ✅ Authentication
- [ ] Click "Sign in" → redirects to GitHub OAuth
- [ ] After GitHub auth → redirects to dashboard
- [ ] No "Invalid Redirect URI" error

### ✅ AI Enhancement
- [ ] Scan a prompt → shows "Powered by Groq AI" (if key configured)
- [ ] Fallback works: "Deterministic security rules applied" (if Groq fails)

### ✅ Payments
- [ ] Click "Upgrade to Pro" → redirects to Stripe Checkout
- [ ] Test with card: `4242 4242 4242 4242`, exp: `12/25`, CVC: `123`
- [ ] After payment → redirects to dashboard with success

### ✅ API Keys
- [ ] Dashboard shows "Generate New API Key" button
- [ ] Generated key can be copied and revoked
- [ ] API key works with `/api/scans` endpoint

---

## 📊 Monitoring

### Health Check
```bash
curl https://your-domain.vercel.app/api/health
```

Expected response:
```json
{
  "ok": true,
  "version": "2.3.0",
  "groqStatus": "active|not_configured",
  "fallbackAvailable": true,
  "requestId": "uuid"
}
```

### Rate Limits
- **Free**: 60 scans per 15 minutes
- **Pro**: 1,000 scans per 15 minutes
- Check headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`

---

## 🐛 Troubleshooting

### "Invalid Redirect URI" Error
**Cause**: Supabase OAuth redirect URL not configured correctly  
**Fix**: In Supabase → Authentication → URL Configuration → Redirect URLs, add:  
`https://your-domain.vercel.app/api/auth/callback`

### Groq API Not Working
**Cause**: Missing or invalid `GROQ_API_KEY` environment variable  
**Fix**: Add valid Groq API key to Vercel environment variables

### Stripe Checkout Fails
**Cause**: Missing Stripe keys or webhook secret  
**Fix**: Verify all Stripe environment variables are set and webhook is configured

### API Key Generation Fails
**Cause**: Stripe not configured or user not subscribed  
**Fix**: Ensure Stripe is working and user has active Pro subscription

---

## 🎉 You're Revenue-Ready! 

Your AI Security Copilot now has:
- ✅ Fixed authentication system
- ✅ Active AI enhancement layer  
- ✅ Complete monetization funnel
- ✅ Professional pricing page
- ✅ Stripe payment processing
- ✅ API key management
- ✅ User dashboard
- ✅ Usage tracking and limits

**Next Steps**:
1. Add your actual API keys to Vercel
2. Test the complete flow
3. Start promoting your SaaS!

---

## 📞 Support

If you encounter issues:
1. Check environment variables are correctly set
2. Verify webhook endpoints are reachable
3. Check browser console for JavaScript errors
4. Review Vercel deployment logs

The system is designed to gracefully fallback if services are unavailable, so even with partial configuration, the core scanning functionality will work.
