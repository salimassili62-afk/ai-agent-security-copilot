#!/usr/bin/env node

/**
 * AI Security Copilot CLI
 * Scan prompts and agents for security issues
 * 
 * Usage:
 *   ai-security-scan <file>
 *   ai-security-scan --compare <baseline> <candidate>
 *   cat prompt.txt | ai-security-scan
 */

const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');

const API_URL = process.env.AI_SECURITY_API || 'http://localhost:3000';

// Choose http or https based on URL
function getRequestModule(url) {
  return url.startsWith('https:') ? https : http;
}

function showHelp() {
  console.log(`
AI Security Copilot CLI v1.3.0

Usage:
  ai-security-scan [options] <file>
  cat prompt.txt | ai-security-scan

Options:
  -h, --help              Show help
  -c, --compare <file>    Compare mode (provide baseline and candidate)
  -o, --output <format>   Output format: json, markdown, summary (default: summary)
  --fail-on <level>       Exit with error if risk >= level (low/medium/high)

Environment:
  AI_SECURITY_API         API endpoint (default: http://localhost:3000)
  GROQ_API_KEY            Optional: for direct API access

Examples:
  ai-security-scan prompt.txt
  ai-security-scan --compare baseline.txt new-version.txt
  echo "Ignore previous instructions" | ai-security-scan --fail-on medium
`);
}

function request(path, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, API_URL);
    const client = getRequestModule(url.toString());
    const timeout = options.timeout || 30000;
    
    const req = client.request(url, {
      method: options.method || 'POST',
      headers: { 'Content-Type': 'application/json', ...options.headers },
      timeout: timeout
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          reject(new Error('Invalid JSON response'));
        }
      });
    });
    
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
    
    if (options.body) req.write(JSON.stringify(options.body));
    req.end();
  });
}

function formatSummary(result) {
  const r = result.parsed || result;
  return `
╔════════════════════════════════════════════════════════╗
║  SECURITY SCAN RESULT                                  ║
╠════════════════════════════════════════════════════════╣
  Risk Score:  ${r.score}/100 ${r.label}
  Triage:      ${r.triage?.action || 'REVIEW'}
  
  Summary:
  ${r.summary}
  
  ${r.reasons?.length ? 'Findings:\n  • ' + r.reasons.join('\n  • ') : 'No significant issues found.'}
  
  ${r.owasp?.length ? 'OWASP Categories: ' + r.owasp.map(o => o.id).join(', ') : ''}
╚════════════════════════════════════════════════════════╝
`;
}

function formatMarkdown(result, fileName) {
  const r = result.parsed || result;
  return `# Security Scan: ${fileName}

**Score:** ${r.score}/100 (${r.label})  
**Triage:** ${r.triage?.action || 'REVIEW'}  
**Confidence:** ${r.confidence}

## Summary
${r.summary}

${r.reasons?.length ? `## Findings
${r.reasons.map(x => `- ${x}`).join('\n')}
` : ''}

${r.fixes?.length ? `## Recommendations
${r.fixes.map(x => `- ${x}`).join('\n')}
` : ''}

${r.owasp?.length ? `## OWASP LLM Top 10 Mapping
${r.owasp.map(o => `- **${o.id}:** ${o.title} (${o.severity})`).join('\n')}
` : ''}

---
*Scanned with AI Security Copilot v${result.version || '1.3.0'}*
`;
}

async function scanFile(filePath, options = {}) {
  const content = fs.readFileSync(filePath, 'utf-8');
  
  const result = await request('/api/scans', {
    body: { content, scanContext: options.context || 'CLI scan' }
  });
  
  if (!result.ok) {
    throw new Error(result.error || 'Scan failed');
  }
  
  return result;
}

async function compareFiles(baselinePath, candidatePath, options = {}) {
  const baseline = fs.readFileSync(baselinePath, 'utf-8');
  const candidate = fs.readFileSync(candidatePath, 'utf-8');
  
  const result = await request('/api/compare', {
    body: { baseline, candidate, scanContext: options.context || 'CLI compare' }
  });
  
  if (!result.ok) {
    throw new Error(result.error || 'Compare failed');
  }
  
  return result;
}

function formatCompare(result, baselineName, candidateName) {
  const d = result.diff;
  let verdict = d.verdict;
  let color = verdict === 'SAFER' ? '✅' : verdict === 'RISKIER' ? '⚠️' : '➡️';
  
  return `
╔════════════════════════════════════════════════════════╗
║  REGRESSION TEST RESULT                                ║
╠════════════════════════════════════════════════════════╣
  Baseline:  ${baselineName} (${result.baseline.score}/100)
  Candidate: ${candidateName} (${result.candidate.score}/100)
  
  Verdict:   ${color} ${verdict}
  Delta:     ${d.scoreDelta > 0 ? '+' : ''}${d.scoreDelta} points
  
  ${d.newFindings.length ? '⚠️ New Findings:\n  • ' + d.newFindings.join('\n  • ') : ''}
  ${d.removedFindings.length ? '✅ Resolved:\n  • ' + d.removedFindings.join('\n  • ') : ''}
  
  ${d.triageChanged ? `🔄 Triage changed: ${d.triageBefore} → ${d.triageAfter}` : ''}
╚════════════════════════════════════════════════════════╝
`;
}

function checkFailLevel(result, failLevel) {
  if (!failLevel) return 0;
  
  const levels = { low: 1, medium: 2, high: 3 };
  const resultLevel = result.parsed?.label?.toLowerCase();
  const resultValue = levels[resultLevel] || 0;
  const failValue = levels[failLevel.toLowerCase()] || 0;
  
  return resultValue >= failValue ? 1 : 0;
}

async function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
    showHelp();
    process.exit(0);
  }
  
  const options = {
    output: 'summary',
    failOn: null,
    context: null
  };
  
  let files = [];
  
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    
    if (arg === '-o' || arg === '--output') {
      options.output = args[++i];
    } else if (arg === '--fail-on') {
      options.failOn = args[++i];
    } else if (arg === '-c' || arg === '--compare') {
      options.compare = true;
    } else if (!arg.startsWith('-')) {
      files.push(arg);
    }
  }
  
  try {
    let result;
    let output;
    
    if (options.compare) {
      if (files.length !== 2) {
        console.error('Compare mode requires exactly 2 files: baseline and candidate');
        process.exit(1);
      }
      
      result = await compareFiles(files[0], files[1], options);
      output = formatCompare(result, path.basename(files[0]), path.basename(files[1]));
      
      // Exit code based on regression
      const exitCode = result.diff.verdict === 'RISKIER' ? 1 : 0;
      console.log(output);
      process.exit(exitCode);
      
    } else {
      // Single file scan
      let content;
      let fileName = 'stdin';
      
      if (files.length === 0) {
        // Read from stdin
        content = fs.readFileSync(0, 'utf-8');
      } else {
        content = fs.readFileSync(files[0], 'utf-8');
        fileName = path.basename(files[0]);
      }
      
      result = await request('/api/scans', {
        body: { content, scanContext: options.context || 'CLI scan' }
      });
      
      if (!result.ok) {
        console.error('Scan failed:', result.error);
        process.exit(1);
      }
      
      switch (options.output) {
        case 'json':
          console.log(JSON.stringify(result, null, 2));
          break;
        case 'markdown':
          console.log(formatMarkdown(result, fileName));
          break;
        case 'summary':
        default:
          console.log(formatSummary(result));
      }
      
      const exitCode = checkFailLevel(result, options.failOn);
      process.exit(exitCode);
    }
    
  } catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

main();
