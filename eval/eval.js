#!/usr/bin/env node

/**
 * Evaluation script for AI Security Copilot
 * Runs the test corpus and reports metrics
 * 
 * Usage: node eval/eval.js
 * Environment: AI_SECURITY_API=http://localhost:3000
 */

const http = require('http');
const corpus = require('./corpus');
const { spawn } = require('child_process');
const path = require('path');

const API_URL = process.env.AI_SECURITY_API || 'http://localhost:3000';
const TEST_TIMEOUT = 30000;
const MAX_STARTUP_TIME = 10000;

const metrics = {
  total: corpus.length,
  passed: 0,
  failed: 0,
  byCategory: {},
  avgLatency: 0,
  fallbackRate: 0,
  heuristicOnlyRate: 0
};

let serverProcess = null;

function startServer() {
  return new Promise((resolve, reject) => {
    const serverPath = path.join(__dirname, '..', 'server.js');
    serverProcess = spawn('node', [serverPath], {
      stdio: 'pipe',
      env: { ...process.env, PORT: '3000' }
    });
    
    serverProcess.stdout.on('data', (data) => {
      const line = data.toString();
      if (line.includes('started on port')) {
        console.log('🚀 Test server started');
        resolve();
      }
    });
    
    serverProcess.stderr.on('data', (data) => {
      // Ignore stderr during startup
    });
    
    serverProcess.on('error', reject);
    
    setTimeout(() => {
      if (serverProcess) resolve(); // Assume started after timeout
    }, MAX_STARTUP_TIME);
  });
}

function stopServer() {
  if (serverProcess) {
    serverProcess.kill();
    serverProcess = null;
    console.log('🛑 Stopped test server');
  }
  // Clear any dangling intervals
  try {
    const app = require('../server.js');
    if (app.cacheCleanupInterval) {
      clearInterval(app.cacheCleanupInterval);
      console.log('🧹 Cleared cache cleanup interval');
    }
  } catch (e) {
    // Ignore errors during cleanup
  }
}

function request(path, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, API_URL);
    const req = http.request(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve({ latency: Date.now(), body: json });
        } catch {
          reject(new Error('Invalid JSON'));
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(TEST_TIMEOUT);
    req.write(JSON.stringify(body));
    req.end();
  });
}

function evaluateResult(testCase, result, startTime) {
  const latency = Date.now() - startTime;
  const score = result.parsed?.score || 0;
  const reasons = (result.parsed?.reasons || []).join(' ').toLowerCase();
  const label = result.parsed?.label || 'UNKNOWN';
  
  let passed = true;
  const failures = [];
  
  // Check minimum score for malicious content
  if (testCase.minScore !== undefined && score < testCase.minScore) {
    passed = false;
    failures.push(`Score ${score} < minimum ${testCase.minScore}`);
  }
  
  // Check maximum score for benign content
  if (testCase.maxScore !== undefined && score > testCase.maxScore) {
    passed = false;
    failures.push(`Score ${score} > maximum ${testCase.maxScore}`);
  }
  
  // Check expected detections
  if (testCase.shouldDetect.length > 0) {
    const detectedAny = testCase.shouldDetect.some(pattern => 
      reasons.includes(pattern.toLowerCase())
    );
    if (!detectedAny) {
      passed = false;
      failures.push(`None of [${testCase.shouldDetect.join(', ')}] detected in: ${reasons.slice(0, 100)}...`);
    }
  }
  
  // Check no false positives for benign
  if (testCase.category === 'NONE' && label !== 'LOW') {
    // Allow some wiggle room - not a strict failure
    if (score > 40) {
      passed = false;
      failures.push(`Benign content scored ${score} (expected < 40)`);
    }
  }
  
  return {
    passed,
    failures,
    score,
    label,
    latency,
    fallback: result.fallback || false,
    heuristicOnly: result.heuristicOnly || false
  };
}

async function runEval() {
  console.log('\n🔬 AI Security Copilot - Evaluation\n');
  console.log(`API: ${API_URL}`);
  console.log(`Cases: ${corpus.length}\n`);
  
  // Start test server if using default URL
  const shouldManageServer = !process.env.AI_SECURITY_API;
  if (shouldManageServer) {
    await startServer();
    // Give server a moment to fully initialize
    await new Promise(r => setTimeout(r, 500));
  }
  
  const results = [];
  let totalLatency = 0;
  let fallbackCount = 0;
  let heuristicCount = 0;
  
  try {
    for (const testCase of corpus) {
      const startTime = Date.now();
      
      try {
        const res = await request('/api/scans', { content: testCase.content });
        const evaluation = evaluateResult(testCase, res.body, startTime);
        
        totalLatency += evaluation.latency;
        if (evaluation.fallback) fallbackCount++;
        if (evaluation.heuristicOnly) heuristicCount++;
        
        // Track by category
        if (!metrics.byCategory[testCase.category]) {
          metrics.byCategory[testCase.category] = { total: 0, passed: 0 };
        }
        metrics.byCategory[testCase.category].total++;
        if (evaluation.passed) {
          metrics.byCategory[testCase.category].passed++;
          metrics.passed++;
        } else {
          metrics.failed++;
        }
        
        const icon = evaluation.passed ? '✅' : '❌';
        console.log(`${icon} ${testCase.id} (${testCase.category}): ${evaluation.score}/100 ${evaluation.label} - ${evaluation.latency}ms`);
        
        if (!evaluation.passed) {
          evaluation.failures.forEach(f => console.log(`   → ${f}`));
          console.log(`   Score: ${evaluation.score}, Expected: ${testCase.minScore || 0}-${testCase.maxScore || 100}`);
        }
        
        results.push({ id: testCase.id, ...evaluation });
        
      } catch (error) {
        console.log(`❌ ${testCase.id}: ERROR - ${error.message}`);
        metrics.failed++;
        results.push({ id: testCase.id, passed: false, error: error.message });
      }
    }
  } finally {
    if (shouldManageServer) {
      stopServer();
    }
  }
  
  // Calculate metrics
  metrics.avgLatency = Math.round(totalLatency / corpus.length);
  metrics.fallbackRate = Math.round((fallbackCount / corpus.length) * 100);
  metrics.heuristicOnlyRate = Math.round((heuristicCount / corpus.length) * 100);
  
  // Print summary
  console.log('\n' + '='.repeat(50));
  console.log('📊 SUMMARY');
  console.log('='.repeat(50));
  console.log(`Total Cases:    ${metrics.total}`);
  console.log(`Passed:         ${metrics.passed} (${Math.round(metrics.passed/metrics.total*100)}%)`);
  console.log(`Failed:         ${metrics.failed} (${Math.round(metrics.failed/metrics.total*100)}%)`);
  console.log(`Avg Latency:    ${metrics.avgLatency}ms`);
  console.log(`Fallback Rate:  ${metrics.fallbackRate}%`);
  console.log(`Heuristic Only: ${metrics.heuristicOnlyRate}%`);
  
  console.log('\n📋 By Category:');
  for (const [cat, data] of Object.entries(metrics.byCategory)) {
    const pct = Math.round((data.passed / data.total) * 100);
    console.log(`  ${cat}: ${data.passed}/${data.total} (${pct}%)`);
  }
  
  console.log('\n' + '='.repeat(50));
  
  // Exit code
  const passRate = metrics.passed / metrics.total;
  if (passRate >= 0.8) {
    console.log('✅ Evaluation PASSED (>= 80%)');
    process.exit(0);
  } else if (passRate >= 0.6) {
    console.log('⚠️ Evaluation MARGINAL (60-80%)');
    process.exit(1);
  } else {
    console.log('❌ Evaluation FAILED (< 60%)');
    process.exit(2);
  }
}

runEval().catch(e => {
  console.error('Eval failed:', e);
  process.exit(1);
});
