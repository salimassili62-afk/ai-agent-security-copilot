#!/usr/bin/env node
/**
 * Environment Variable Validation Script
 * Run this to check if all required environment variables are set
 */

const required = {
  // Auth (Required)
  SUPABASE_URL: { required: true, hint: 'Get from Supabase Project Settings > API' },
  SUPABASE_SERVICE_KEY: { required: true, hint: 'Get from Supabase Project Settings > API (service_role key)' },
  
  // AI (Required for full functionality, optional for basic)
  GROQ_API_KEY: { required: false, hint: 'Get from console.groq.com' },
  
  // Payments (Required for monetization)
  STRIPE_SECRET_KEY: { required: false, hint: 'Get from Stripe Dashboard > Developers > API Keys' },
  STRIPE_WEBHOOK_SECRET: { required: false, hint: 'Get from Stripe Dashboard > Developers > Webhooks' },
  STRIPE_PUBLISHABLE_KEY: { required: false, hint: 'Get from Stripe Dashboard > Developers > API Keys (publishable)' },
  STRIPE_PRICE_PRO: { required: false, hint: 'Create in Stripe Dashboard > Products, copy Price ID' },
  STRIPE_PRICE_TEAM: { required: false, hint: 'Create in Stripe Dashboard > Products, copy Price ID' },
};

const optional = {
  SUPABASE_JWT_SECRET: 'For JWT verification (optional)',
  SENTRY_DSN: 'For error tracking (optional)',
};

console.log('🔍 AI Security Copilot - Environment Check\n');

let missing = [];
let present = [];

// Check required vars
console.log('📋 Required Variables:');
for (const [key, config] of Object.entries(required)) {
  const value = process.env[key];
  if (!value) {
    console.log(`  ❌ ${key}: NOT SET`);
    if (config.hint) console.log(`     💡 ${config.hint}`);
    if (config.required) missing.push(key);
  } else {
    const masked = value.length > 10 
      ? `${value.slice(0, 4)}...${value.slice(-4)}` 
      : '****';
    console.log(`  ✅ ${key}: ${masked}`);
    present.push(key);
  }
}

// Check optional vars
console.log('\n📋 Optional Variables:');
for (const [key, hint] of Object.entries(optional)) {
  const value = process.env[key];
  if (!value) {
    console.log(`  ⚠️  ${key}: NOT SET (${hint})`);
  } else {
    const masked = value.length > 10 
      ? `${value.slice(0, 4)}...${value.slice(-4)}` 
      : '****';
    console.log(`  ✅ ${key}: ${masked}`);
    present.push(key);
  }
}

// Summary
console.log('\n📊 Summary:');
console.log(`  Total Required: ${Object.keys(required).length}`);
console.log(`  Present: ${present.length}`);
console.log(`  Missing Required: ${missing.length}`);

if (missing.length > 0) {
  console.log('\n❌ Validation FAILED');
  console.log('Missing required variables:', missing.join(', '));
  console.log('\n📝 Next steps:');
  console.log('1. Add missing variables to Vercel:');
  console.log('   vercel env add <VARIABLE_NAME>');
  console.log('2. Or use Vercel Dashboard: Settings → Environment Variables');
  console.log('3. Redeploy after adding variables');
  process.exit(1);
} else {
  console.log('\n✅ All required variables present!');
  
  // Check if AI is configured
  if (!process.env.GROQ_API_KEY) {
    console.log('\n⚠️  Note: GROQ_API_KEY not set - app will run in deterministic-only mode');
  }
  
  // Check if payments are configured
  if (!process.env.STRIPE_SECRET_KEY) {
    console.log('\n⚠️  Note: Stripe not configured - payments will not work');
  }
  
  console.log('\n🚀 Ready for deployment!');
  process.exit(0);
}
