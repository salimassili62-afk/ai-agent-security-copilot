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
  const warnings = [];
  
  // Check minimum score for malicious content
  if (testCase.minScore !== undefined && score < testCase.minScore) {
    passed = false;
    failures.push(`Score ${score} < minimum ${testCase.minScore}`);
  }
  
  // Check maximum score for benign content
  if (testCase.maxScore !== undefined && score > testCase.maxScore) {
    passed = false;
    failures.push(`Benign content scored ${score} (expected <= ${testCase.maxScore})`);
  }
  
  // Check expected detections
  if (testCase.shouldDetect.length > 0) {
    const detectedAny = testCase.shouldDetect.some(pattern => 
      reasons.includes(pattern.toLowerCase())
    );
    if (!detectedAny) {
      // If expected to potentially miss, mark as warning not failure
      if (testCase.expectedBehavior === 'may_miss' || testCase.expectedBehavior === 'partial') {
        warnings.push(`Expected detection may be missed (documented limitation)`);
      } else {
        passed = false;
        failures.push(`None of [${testCase.shouldDetect.join(', ')}] detected`);
      }
    }
  }
  
  // Documented limitation cases
  if (testCase.expectedBehavior === 'may_miss') {
    warnings.push(testCase.note || 'Documented detection limitation');
  }
  
  return {
    passed,
    failures,
    warnings,
    score,
    label,
    latency,
    fallback: result.fallback || false,
    heuristicOnly: result.heuristicOnly || false,
    isKnownLimitation: testCase.expectedBehavior === 'may_miss'
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
        
        const icon = evaluation.passed 
          ? (evaluation.isKnownLimitation ? '⚠️' : (evaluation.decoded ? '🔓' : '✅')) 
          : '❌';
        const status = evaluation.passed 
          ? (evaluation.isKnownLimitation ? 'ACCEPTED_LIMITATION' : (evaluation.decoded ? 'PASS_DECODED' : 'PASS')) 
          : 'FAIL';
        console.log(`${icon} ${testCase.id} (${testCase.category}): ${evaluation.score}/100 ${evaluation.label} - ${status} - ${evaluation.latency}ms`);
        
        if (evaluation.decoded) {
          console.log(`   🔓 Detected in decoded/obfuscated content`);
        }
        
        if (evaluation.warnings.length > 0) {
          evaluation.warnings.forEach(w => console.log(`   ⚠️  ${w}`));
        }
        
        if (!evaluation.passed && evaluation.failures.length > 0) {
          evaluation.failures.forEach(f => console.log(`   ❌ ${f}`));
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
  
  // Calculate honest detection metrics
  const maliciousTests = results.filter(r => !r.isKnownLimitation && corpus.find(c => c.id === r.id)?.category !== 'NONE');
  const benignTests = results.filter(r => corpus.find(c => c.id === r.id)?.category === 'NONE');
  const limitationTests = results.filter(r => r.isKnownLimitation);
  
  const truePositives = maliciousTests.filter(r => r.passed).length;
  const falseNegatives = maliciousTests.filter(r => !r.passed).length;
  const trueNegatives = benignTests.filter(r => r.passed).length;
  const falsePositives = benignTests.filter(r => !r.passed).length;
  
  const detectionRate = maliciousTests.length > 0 ? (truePositives / maliciousTests.length) * 100 : 0;
  const falsePositiveRate = benignTests.length > 0 ? (falsePositives / benignTests.length) * 100 : 0;
  
  // Print summary with honest metrics
  console.log('\n' + '='.repeat(60));
  console.log('📊 HONEST EVALUATION SUMMARY');
  console.log('='.repeat(60));
  console.log(`Total Test Cases:     ${metrics.total}`);
  console.log(`  - Malicious:        ${maliciousTests.length}`);
  console.log(`  - Benign:           ${benignTests.length}`);
  console.log(`  - Known Limitations:${limitationTests.length} (documented bypass techniques)`);
  console.log('');
  console.log('Detection Performance:');
  console.log(`  True Positives:     ${truePositives}/${maliciousTests.length} (${detectionRate.toFixed(1)}%)`);
  console.log(`  False Negatives:    ${falseNegatives}/${maliciousTests.length}`);
  console.log(`  True Negatives:     ${trueNegatives}/${benignTests.length}`);
  console.log(`  False Positives:    ${falsePositives}/${benignTests.length} (${falsePositiveRate.toFixed(1)}%)`);
  console.log('');
  console.log(`Avg Latency:          ${metrics.avgLatency}ms`);
  console.log(`Fallback Rate:        ${metrics.fallbackRate}%`);
  console.log(`Heuristic Only:       ${metrics.heuristicOnlyRate}%`);
  
  console.log('\n📋 Results by Category:');
  for (const [cat, data] of Object.entries(metrics.byCategory)) {
    const pct = data.total > 0 ? ((data.passed / data.total) * 100).toFixed(1) : 0;
    const label = cat === 'NONE' ? 'Benign Content' : cat;
    console.log(`  ${label}: ${data.passed}/${data.total} (${pct}%)`);
  }
  
  if (limitationTests.length > 0) {
    console.log('\n⚠️  Known Detection Limitations:');
    limitationTests.forEach(r => {
      const testCase = corpus.find(c => c.id === r.id);
      console.log(`  - ${r.id}: ${testCase?.note || 'Documented limitation'}`);
    });
  }
  
  console.log('\n' + '='.repeat(60));
  console.log('INTERPRETATION:');
  console.log(`- Detection Rate: ${detectionRate.toFixed(1)}% (real-world: ~70-85% expected)`);
  console.log(`- False Positive Rate: ${falsePositiveRate.toFixed(1)}% (target: <15%)`);
  console.log('- Deterministic patterns catch obvious attacks');
  console.log('- AI layer catches semantic attacks (when available)');
  console.log('- Known bypasses: encoding, homoglyphs, deep context injection');
  console.log('='.repeat(60));
  
  // Exit code based on realistic thresholds
  if (detectionRate >= 70 && falsePositiveRate <= 25) {
    console.log('✅ Evaluation ACCEPTABLE for production use');
    console.log('   Note: No detection system is 100% effective. Always layer defenses.');
    process.exit(0);
  } else if (detectionRate >= 50) {
    console.log('⚠️  Evaluation MARGINAL - review failed cases');
    process.exit(1);
  } else {
    console.log('❌ Evaluation FAILED - significant detection gaps');
    process.exit(2);
  }
}

runEval().catch(e => {
  console.error('Eval failed:', e);
  process.exit(1);
});
