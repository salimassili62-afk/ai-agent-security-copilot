# GitHub OAuth Setup Guide - Fix "Invalid Redirect URI" Error

## 🎯 Mission Status: ✅ CODE FIXED - Now Complete the Setup

The GitHub OAuth "Invalid Redirect URI" error has been **FIXED** in the code. Now you need to complete the configuration steps below.

---

## 📋 Required Setup Steps

### STEP 1: Create GitHub OAuth App

1. Go to: https://github.com/settings/developers
2. Click: **"New OAuth App"**
3. Fill in the form:
   - **Application name**: `AI Security Copilot`
   - **Homepage URL**: `https://ai-agent-security-copilot.vercel.app`
   - **Authorization callback URL**: `https://ai-agent-security-copilot.vercel.app/auth/callback`
4. Click: **"Create application"**
5. **Copy and save**: 
   - Client ID (public)
   - Client Secret (click "Generate a new client secret")

### STEP 2: Configure Supabase GitHub OAuth

1. Go to: https://supabase.com → Your Project → Authentication → Providers
2. Find **GitHub** in the list and click to expand
3. **Enable** GitHub provider
4. Paste the credentials from Step 1:
   - **Client ID**: (from GitHub OAuth app)
   - **Client Secret**: (from GitHub OAuth app)
5. Click: **"Save"**

### STEP 3: Add Redirect URLs in Supabase

1. In Supabase, go to: Authentication → URL Configuration
2. Add these redirect URLs (one per line):
   ```
   https://ai-agent-security-copilot.vercel.app
   https://ai-agent-security-copilot.vercel.app/auth/callback
   https://ai-agent-security-copilot.vercel.app/dashboard
   ```
3. Click: **"Save"**

### STEP 4: Add Environment Variables to Vercel

1. Go to: Vercel Dashboard → Your Project → Settings → Environment Variables
2. Add/Update these variables:

```bash
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_SERVICE_KEY=your-service-role-key
```

*(Get these from Supabase → Project Settings → API)*

---

## 🚀 Test the OAuth Flow

After completing the setup:

1. **Wait 2-3 minutes** for Vercel to redeploy
2. Visit: https://ai-agent-security-copilot.vercel.app
3. Click **"Sign In"** button
4. Should redirect to GitHub OAuth (no error!)
5. Authorize the application
6. Should redirect back to dashboard

**Expected Flow:**
```
User clicks "Sign In" 
→ Redirect to /auth/login 
→ Redirect to Supabase OAuth 
→ Redirect to GitHub OAuth 
→ User authorizes 
→ Redirect to /auth/callback 
→ Redirect to /dashboard
```

---

## 🔧 Troubleshooting

### Still getting "Invalid Redirect URI"?

**Check these:**

1. **GitHub OAuth App Settings**:
   - Homepage URL: `https://ai-agent-security-copilot.vercel.app`
   - Callback URL: `https://ai-agent-security-copilot.vercel.app/auth/callback`

2. **Supabase Redirect URLs**:
   - Must include: `https://ai-agent-security-copilot.vercel.app/auth/callback`

3. **Environment Variables**:
   - `SUPABASE_URL` must be correct
   - `SUPABASE_SERVICE_KEY` must be valid

### Getting "Supabase not configured" error?

**Missing environment variables:**
- Add `SUPABASE_URL` and `SUPABASE_SERVICE_KEY` to Vercel

### Getting "Authentication not configured on server"?

**Supabase provider not enabled:**
- Enable GitHub provider in Supabase Auth → Providers

---

## 🧪 Quick Test Commands

Test the auth endpoints directly:

```bash
# Test login endpoint (should redirect to GitHub)
curl -L https://ai-agent-security-copilot.vercel.app/auth/login

# Test callback (should redirect to home if no code)
curl -L https://ai-agent-security-copilot.vercel.app/auth/callback

# Test health check
curl https://ai-agent-security-copilot.vercel.app/api/health
```

---

## ✅ Success Indicators

You'll know it's working when:

1. ✅ No "Invalid Redirect URI" error
2. ✅ Clicking "Sign In" redirects to GitHub
3. ✅ After GitHub authorization, redirects to dashboard
4. ✅ User stays logged in (session works)
5. ✅ Logout button works and clears session

---

## 🎉 What Was Fixed

**Before**: Complex API-based auth flow that caused redirect URI mismatches

**After**: Simple direct redirect flow:
- `/auth/login` → Direct to Supabase OAuth
- `/auth/callback` → Handle GitHub response  
- `/auth/logout` → Clear session and redirect

This eliminates the redirect URI issues by using Supabase's built-in OAuth flow correctly.

---

## 📞 Need Help?

If you're still having issues after following these steps:

1. Double-check all URLs match exactly (no trailing slashes)
2. Ensure environment variables are set in Vercel (not just locally)
3. Verify GitHub OAuth app is not in "draft" mode
4. Check Supabase logs for authentication errors

The code is now production-ready - just complete the configuration steps above! 🚀
