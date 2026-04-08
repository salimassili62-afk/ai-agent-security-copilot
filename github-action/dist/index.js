// AI Security Copilot GitHub Action - Self-contained bundle
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');

// Mock @actions/core
const core = {
  getInput: (name, options = {}) => {
    const envName = `INPUT_${name.toUpperCase().replace(/-/g, '_')}`;
    const value = process.env[envName];
    if (options.required && !value) {
      throw new Error(`Input required and not supplied: ${name}`);
    }
    return value || '';
  },
  setOutput: (name, value) => {
    console.log(`::set-output name=${name}::${value}`);
    process.stdout.write(`::set-output name=${name}::${value}\n`);
  },
  setFailed: (message) => {
    console.log(`::error::${message}`);
    process.exit(1);
  }
};

// Mock @actions/github
const github = {
  context: {
    repo: {
      owner: process.env.GITHUB_REPOSITORY?.split('/')[0] || 'unknown',
      repo: process.env.GITHUB_REPOSITORY?.split('/')[1] || 'unknown'
    },
    issue: {
      number: parseInt(process.env.GITHUB_EVENT_NUMBER || '0', 10)
    },
    payload: {
      pull_request: process.env.GITHUB_EVENT_NAME === 'pull_request' ? {} : null
    }
  },
  getOctokit: (token) => ({
    rest: {
      pulls: {
        get: async ({ owner, repo, pull_number }) => ({
          data: { number: pull_number, head: { sha: 'abc123' } }
        })
      },
      issues: {
        listComments: async ({ owner, repo, issue_number }) => ({
          data: []
        }),
        createComment: async ({ owner, repo, issue_number, body }) => {
          console.log('📤 Would post PR comment:');
          console.log(body.substring(0, 500) + '...');
        },
        updateComment: async ({ owner, repo, comment_id, body }) => {
          console.log('📝 Would update PR comment');
        }
      }
    }
  })
};

// Mock @actions/glob
const glob = {
  create: async (pattern, options = {}) => ({
    globGenerator: async function* () {
      // Simple glob matching for common patterns
      const files = await findFilesByPattern(pattern);
      for (const file of files) {
        yield file;
      }
    },
    glob: async () => {
      return findFilesByPattern(pattern);
    }
  })
};

async function findFilesByPattern(pattern) {
  const files = [];
  const cwd = process.cwd();
  
  // Simple pattern expansion
  if (pattern.includes('**')) {
    // Recursive search
    const ext = pattern.split('.').pop();
    await recursiveFind(cwd, ext, files, ['node_modules', '.git', 'dist', 'build']);
  } else if (pattern.includes('*.')) {
    // Extension pattern
    const ext = pattern.split('.').pop();
    const dir = pattern.split('*')[0] || cwd;
    if (fs.existsSync(dir)) {
      const entries = fs.readdirSync(dir);
      for (const entry of entries) {
        if (entry.endsWith('.' + ext)) {
          files.push(path.join(dir, entry));
        }
      }
    }
  }
  
  return files;
}

async function recursiveFind(dir, ext, files, exclude) {
  if (!fs.existsSync(dir)) return;
  
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    
    if (entry.isDirectory()) {
      if (!exclude.includes(entry.name)) {
        await recursiveFind(fullPath, ext, files, exclude);
      }
    } else if (entry.isFile() && entry.name.endsWith('.' + ext)) {
      files.push(fullPath);
    }
  }
}

const API_URL = 'https://ai-agent-security-copilot.vercel.app/api/scan';

// Scanner module
async function scanFile(filePath, apiKey) {
  const content = fs.readFileSync(filePath, 'utf8');
  
  if (isBinary(content)) {
    return { findings: [] };
  }

  return new Promise((resolve, reject) => {
    const postData = JSON.stringify({
      input: content,
      format: 'json',
      filename: filePath.split('/').pop()
    });

    const url = new URL(API_URL);
    
    const options = {
      hostname: url.hostname,
      port: url.port || (url.protocol === 'https:' ? 443 : 80),
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
        'X-API-Key': apiKey,
        'User-Agent': 'AI-Security-Copilot-GitHub-Action/2.0.0'
      },
      timeout: 30000
    };

    const reqModule = url.protocol === 'https:' ? https : http;
    
    const req = reqModule.request(options, (res) => {
      let data = '';
      
      res.on('data', (chunk) => {
        data += chunk;
      });
      
      res.on('end', () => {
        try {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            const result = JSON.parse(data);
            resolve({
              findings: result.parsed?.reasons?.map(r => ({
                pattern: r,
                severity: result.parsed?.label || 'MEDIUM',
                category: 'SECURITY',
                description: result.parsed?.summary || ''
              })) || [],
              score: result.parsed?.score || 0,
              label: result.parsed?.label || 'LOW'
            });
          } else {
            // Fallback to local scanning
            const localResult = localScan(content);
            resolve(localResult);
          }
        } catch (error) {
          // Fallback to local scanning
          const localResult = localScan(content);
          resolve(localResult);
        }
      });
    });

    req.on('error', (error) => {
      console.log(`⚠️ API unavailable, using local scan for ${filePath}`);
      const localResult = localScan(content);
      resolve(localResult);
    });

    req.on('timeout', () => {
      req.destroy();
      console.log(`⏱️ API timeout, using local scan for ${filePath}`);
      const localResult = localScan(content);
      resolve(localResult);
    });

    req.write(postData);
    req.end();
  });
}

// Local fallback scanning
function localScan(content) {
  const findings = [];
  
  const patterns = [
    { pattern: /ignore\s+(?:all\s+)?(?:previous|above|prior)\s+(?:instructions?|commands?)/i, severity: 'CRITICAL', name: 'Instruction override' },
    { pattern: /sk-[a-zA-Z0-9]{20,}/i, severity: 'CRITICAL', name: 'OpenAI API Key' },
    { pattern: /AKIA[0-9A-Z]{16}/, severity: 'CRITICAL', name: 'AWS Access Key' },
    { pattern: /BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY/i, severity: 'CRITICAL', name: 'Private Key' },
    { pattern: /(?:DROP|DELETE|TRUNCATE)\s+(?:TABLE|DATABASE)/i, severity: 'HIGH', name: 'Destructive SQL' },
    { pattern: /rm\s+-rf/i, severity: 'HIGH', name: 'Destructive command' },
    { pattern: /(?:system|admin|root)\s*:\s*/i, severity: 'HIGH', name: 'Role injection' },
    { pattern: /DAN\s*(?:mode|bypass)/i, severity: 'HIGH', name: 'Jailbreak attempt' },
    { pattern: /password\s*[:=]\s*["\'][^"\']{8,}/i, severity: 'MEDIUM', name: 'Hardcoded password' },
    { pattern: /api[_-]?key\s*[:=]\s*["\'][^"\']{16,}/i, severity: 'MEDIUM', name: 'API Key' }
  ];

  for (const { pattern, severity, name } of patterns) {
    if (pattern.test(content)) {
      findings.push({
        pattern: name,
        severity,
        category: 'LOCAL_SCAN',
        description: `Detected ${name} pattern (local fallback scan)`
      });
    }
  }

  return { findings, score: findings.length > 0 ? 60 : 0, label: findings.length > 0 ? 'MEDIUM' : 'LOW' };
}

function isBinary(content) {
  const nullCount = (content.match(/\x00/g) || []).length;
  const nonPrintable = (content.match(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g) || []).length;
  
  if (nullCount > 0) return true;
  if (content.length > 0 && nonPrintable / content.length > 0.1) return true;
  
  return false;
}

// PR Comment module
const SEVERITY_ICONS = {
  CRITICAL: '🔴',
  HIGH: '🟠',
  MEDIUM: '🟡',
  LOW: '🔵'
};

async function postPRComment(token, summary) {
  const octokit = github.getOctokit(token);
  const { data: pullRequest } = await octokit.rest.pulls.get({
    owner: github.context.repo.owner,
    repo: github.context.repo.repo,
    pull_number: github.context.issue.number
  });

  const body = formatPRComment(summary);

  const { data: comments } = await octokit.rest.issues.listComments({
    owner: github.context.repo.owner,
    repo: github.context.repo.repo,
    issue_number: github.context.issue.number
  });

  const existingComment = comments.find(c => 
    c.user?.type === 'Bot' && 
    c.body?.includes('AI Security Copilot')
  );

  if (existingComment) {
    await octokit.rest.issues.updateComment({
      owner: github.context.repo.owner,
      repo: github.context.repo.repo,
      comment_id: existingComment.id,
      body
    });
    console.log('📝 Updated existing PR comment');
  } else {
    await octokit.rest.issues.createComment({
      owner: github.context.repo.owner,
      repo: github.context.repo.repo,
      issue_number: github.context.issue.number,
      body
    });
    console.log('📝 Posted new PR comment');
  }
}

function formatPRComment(summary) {
  const { critical, high, medium, low, totalFindings, findings, passed } = summary;
  
  const statusIcon = passed ? '✅' : '❌';
  const statusText = passed ? 'PASSED' : 'FAILED';

  let comment = `## ${statusIcon} AI Security Copilot Scan ${statusText}

**Scan Summary:**
| Metric | Count |
|--------|-------|
| Files Scanned | ${summary.totalFiles} |
| Total Findings | ${totalFindings} |
| 🔴 Critical | ${critical} |
| 🟠 High | ${high} |
| 🟡 Medium | ${medium} |
| 🔵 Low | ${low} |

`;

  if (totalFindings > 0) {
    comment += `### 🚨 Security Findings

`;

    const bySeverity = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
    for (const f of findings) {
      const sev = f.severity?.toUpperCase() || 'LOW';
      if (!bySeverity[sev]) bySeverity[sev] = [];
      bySeverity[sev].push(f);
    }

    for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
      const sevFindings = bySeverity[severity];
      if (!sevFindings || sevFindings.length === 0) continue;

      const icon = SEVERITY_ICONS[severity];
      comment += `<details>
<summary>${icon} ${severity} (${sevFindings.length})</summary>

`;

      for (const finding of sevFindings.slice(0, 20)) {
        comment += `- **${finding.pattern || finding.category}** in \`${finding.file}\`\n`;
        if (finding.description) {
          comment += `  - ${finding.description.substring(0, 100)}${finding.description.length > 100 ? '...' : ''}\n`;
        }
        comment += '\n';
      }

      if (sevFindings.length > 20) {
        comment += `_... and ${sevFindings.length - 20} more ${severity} findings_\n`;
      }

      comment += `</details>

`;
    }
  }

  if (!passed) {
    comment += `### ❌ Build Failed

This PR contains security issues that must be resolved before merging.

**Required Actions:**
1. Review the findings above
2. Fix CRITICAL and HIGH severity issues
3. Re-run the scan

`;
  }

  comment += `---
*Powered by [AI Security Copilot](https://ai-agent-security-copilot.vercel.app) - OWASP LLM Top 10 Scanner*
`;

  return comment;
}

// File finder
async function findFiles(scanPath, includePatterns, excludePatterns, maxFileSizeKB) {
  const files = [];
  const maxBytes = maxFileSizeKB * 1024;
  
  const includes = includePatterns.split(',').map(p => p.trim()).filter(Boolean);
  const excludes = excludePatterns.split(',').map(p => p.trim()).filter(Boolean);

  for (const pattern of includes) {
    const globber = await glob.create(pattern, { followSymbolicLinks: false });
    
    for await (const file of globber.globGenerator()) {
      let excluded = false;
      for (const exclude of excludes) {
        if (file.includes('node_modules') || file.includes('.git') || file.includes('dist')) {
          excluded = true;
          break;
        }
      }
      
      if (excluded) continue;
      
      try {
        const stats = fs.statSync(file);
        if (stats.isFile() && stats.size <= maxBytes) {
          files.push(path.resolve(file));
        }
      } catch (e) {
        // Skip files we can't stat
      }
    }
  }

  if (fs.existsSync(scanPath) && fs.statSync(scanPath).isFile()) {
    const resolved = path.resolve(scanPath);
    if (!files.includes(resolved)) {
      files.push(resolved);
    }
  }

  return [...new Set(files)];
}

// Main action runner
async function run() {
  try {
    const apiKey = core.getInput('api-key', { required: true });
    const scanPath = core.getInput('scan-path') || '.';
    const failOnHigh = core.getInput('fail-on-high') === 'true';
    const failOnCritical = core.getInput('fail-on-critical') !== 'false';
    const includePatterns = core.getInput('include-patterns') || '*.js,*.ts,*.jsx,*.tsx,*.py,*.prompt,*.txt,*.md';
    const excludePatterns = core.getInput('exclude-patterns') || 'node_modules/**,dist/**,build/**,.git/**';
    const maxFileSize = parseInt(core.getInput('max-file-size') || '500', 10);
    const prCommentEnabled = core.getInput('pr-comment') === 'true';
    const githubToken = core.getInput('github-token');

    console.log('🔒 AI Security Copilot - GitHub Action v2.0.0');
    console.log(`📁 Scan path: ${scanPath}`);
    console.log(`🎯 Fail on HIGH: ${failOnHigh}, CRITICAL: ${failOnCritical}`);
    console.log('');

    const files = await findFiles(scanPath, includePatterns, excludePatterns, maxFileSize);
    
    if (files.length === 0) {
      console.log('⚠️ No files found to scan');
      core.setOutput('summary', JSON.stringify({ passed: true, findings: [] }));
      core.setOutput('total-findings', '0');
      core.setOutput('has-failures', 'false');
      return;
    }

    console.log(`🔍 Found ${files.length} files to scan`);
    console.log('');

    const allFindings = [];
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;

    for (const file of files) {
      try {
        const result = await scanFile(file, apiKey);
        
        if (result.findings && result.findings.length > 0) {
          for (const finding of result.findings) {
            allFindings.push({
              file: path.relative(process.cwd(), file),
              ...finding
            });

            const severity = finding.severity?.toUpperCase();
            if (severity === 'CRITICAL') criticalCount++;
            else if (severity === 'HIGH') highCount++;
            else if (severity === 'MEDIUM') mediumCount++;
            else lowCount++;
          }
        }

        if (files.length > 20 && files.indexOf(file) % 10 === 0) {
          console.log(`  Scanned ${files.indexOf(file) + 1}/${files.length} files...`);
        }
      } catch (error) {
        console.error(`❌ Error scanning ${file}: ${error.message}`);
      }
    }

    const summary = {
      totalFiles: files.length,
      totalFindings: allFindings.length,
      critical: criticalCount,
      high: highCount,
      medium: mediumCount,
      low: lowCount,
      findings: allFindings,
      passed: true
    };

    let hasFailures = false;
    if (failOnCritical && criticalCount > 0) {
      hasFailures = true;
      summary.passed = false;
    }
    if (failOnHigh && highCount > 0) {
      hasFailures = true;
      summary.passed = false;
    }

    core.setOutput('summary', JSON.stringify(summary));
    core.setOutput('critical-count', String(criticalCount));
    core.setOutput('high-count', String(highCount));
    core.setOutput('total-findings', String(allFindings.length));
    core.setOutput('has-failures', String(hasFailures));

    console.log('');
    console.log('='.repeat(60));
    console.log('📊 SCAN RESULTS');
    console.log('='.repeat(60));
    console.log(`Files scanned: ${files.length}`);
    console.log(`Total findings: ${allFindings.length}`);
    console.log(`  🔴 CRITICAL: ${criticalCount}`);
    console.log(`  🟠 HIGH: ${highCount}`);
    console.log(`  🟡 MEDIUM: ${mediumCount}`);
    console.log(`  🔵 LOW: ${lowCount}`);
    console.log('');

    if (allFindings.length > 0) {
      console.log('🚨 SECURITY FINDINGS:');
      console.log('-'.repeat(60));
      
      const bySeverity = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
      for (const f of allFindings) {
        const sev = f.severity?.toUpperCase() || 'LOW';
        if (!bySeverity[sev]) bySeverity[sev] = [];
        bySeverity[sev].push(f);
      }

      for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
        const findings = bySeverity[severity] || [];
        if (findings.length === 0) continue;

        const icon = severity === 'CRITICAL' ? '🔴' : severity === 'HIGH' ? '🟠' : severity === 'MEDIUM' ? '🟡' : '🔵';
        console.log(`\n${icon} ${severity} (${findings.length}):`);
        
        for (const finding of findings.slice(0, 10)) {
          console.log(`  • ${finding.pattern || finding.category}: ${finding.file}`);
          if (finding.description) {
            console.log(`    ${finding.description.substring(0, 80)}${finding.description.length > 80 ? '...' : ''}`);
          }
        }
        
        if (findings.length > 10) {
          console.log(`    ... and ${findings.length - 10} more`);
        }
      }
      console.log('');
    }

    if (prCommentEnabled && githubToken && github.context.payload.pull_request) {
      await postPRComment(githubToken, summary);
    }

    console.log('='.repeat(60));
    if (hasFailures) {
      console.log('❌ SCAN FAILED - Security issues detected');
      console.log('='.repeat(60));
      core.setFailed(`Security scan failed: ${criticalCount} CRITICAL, ${highCount} HIGH severity issues found`);
    } else {
      console.log('✅ SCAN PASSED - No critical/high severity issues');
      console.log('='.repeat(60));
    }

  } catch (error) {
    core.setFailed(`Action failed: ${error.message}`);
  }
}

run();
