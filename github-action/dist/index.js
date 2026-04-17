/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ 500:
/***/ ((module) => {

// PR Blocking Engine
// Compares baseline vs candidate and blocks PRs if security degrades

class PRBlockerEngine {
  constructor() {
    this.defaultConfig = {
      fail_on_increase: true,
      max_risk_score: 70,
      min_score_delta: -10, // Block if score drops by 10+ points
      block_new_critical: true,
      block_new_high: false
    };
  }

  async evaluatePR(baselineScan, candidateScan, config = {}) {
    const finalConfig = { ...this.defaultConfig, ...config };
    
    const baseline = baselineScan.parsed || {};
    const candidate = candidateScan.parsed || {};
    
    const baselineScore = baseline.score || 0;
    const candidateScore = candidate.score || 0;
    const scoreDelta = candidateScore - baselineScore;
    
    // Analyze new issues
    const baselineIssues = this.extractIssues(baseline);
    const candidateIssues = this.extractIssues(candidate);
    const newIssues = this.findNewIssues(baselineIssues, candidateIssues);
    
    // Evaluate blocking conditions
    const shouldBlock = this.shouldBlockPR({
      scoreDelta,
      baselineScore,
      candidateScore,
      newIssues,
      config: finalConfig
    });
    
    // Generate PR comment
    const comment = this.generatePRComment({
      baselineScore,
      candidateScore,
      scoreDelta,
      newIssues,
      shouldBlock,
      config: finalConfig,
      scanDetails: {
        baseline: baselineScan,
        candidate: candidateScan
      }
    });
    
    return {
      should_block: shouldBlock,
      score_delta: scoreDelta,
      baseline_score: baselineScore,
      candidate_score: candidateScore,
      new_issues: newIssues,
      comment: comment,
      evaluation: {
        risk_level: this.getRiskLevel(candidateScore),
        trend: scoreDelta < -5 ? 'DEGRADING' : scoreDelta > 5 ? 'IMPROVING' : 'STABLE',
        blocking_reasons: this.getBlockingReasons(shouldBlock, {
          scoreDelta,
          newIssues,
          config: finalConfig
        })
      }
    };
  }

  extractIssues(scanResult) {
    const issues = [];
    
    // Extract from deterministic findings
    if (scanResult.deterministicFindings) {
      scanResult.deterministicFindings.forEach(finding => {
        issues.push({
          category: finding.category || 'UNKNOWN',
          severity: finding.severity,
          name: finding.name || finding.pattern?.name || 'Unknown Issue',
          description: finding.description || finding.reason || 'No description',
          score_impact: this.getScoreImpact(finding.severity)
        });
      });
    }
    
    // Extract from OWASP findings
    if (scanResult.owasp) {
      scanResult.owasp.forEach(owasp => {
        issues.push({
          category: owasp.id,
          severity: owasp.severity,
          name: owasp.title,
          description: owasp.note,
          score_impact: this.getScoreImpact(owasp.severity)
        });
      });
    }
    
    return issues;
  }

  findNewIssues(baselineIssues, candidateIssues) {
    const newIssues = [];
    
    for (const candidateIssue of candidateIssues) {
      const existsInBaseline = baselineIssues.some(baseline => 
        baseline.category === candidateIssue.category &&
        baseline.name === candidateIssue.name
      );
      
      if (!existsInBaseline) {
        newIssues.push(candidateIssue);
      }
    }
    
    return newIssues;
  }

  shouldBlockPR({ scoreDelta, baselineScore, candidateScore, newIssues, config }) {
    const reasons = [];
    
    // Condition 1: Score increases beyond threshold
    if (config.fail_on_increase && scoreDelta > config.max_risk_score) {
      reasons.push(`Score increase exceeds threshold: ${scoreDelta} > ${config.max_risk_score}`);
    }
    
    // Condition 2: Score decreases significantly (regression)
    if (scoreDelta < config.min_score_delta) {
      reasons.push(`Security regression detected: score dropped by ${Math.abs(scoreDelta)} points`);
    }
    
    // Condition 3: New critical issues
    if (config.block_new_critical) {
      const newCritical = newIssues.filter(i => i.severity === 'CRITICAL');
      if (newCritical.length > 0) {
        reasons.push(`New critical issues introduced: ${newCritical.length}`);
      }
    }
    
    // Condition 4: New high severity issues
    if (config.block_new_high) {
      const newHigh = newIssues.filter(i => i.severity === 'HIGH');
      if (newHigh.length > 0) {
        reasons.push(`New high severity issues introduced: ${newHigh.length}`);
      }
    }
    
    // Condition 5: Absolute score too high
    if (candidateScore > 80) {
      reasons.push(`Candidate score too high: ${candidateScore} > 80`);
    }
    
    return {
      block: reasons.length > 0,
      reasons: reasons
    };
  }

  generatePRComment({ baselineScore, candidateScore, scoreDelta, newIssues, shouldBlock, config, scanDetails }) {
    const riskEmoji = candidateScore >= 70 ? '🚨' : candidateScore >= 40 ? '⚠️' : '✅';
    const deltaEmoji = scoreDelta < -10 ? '📉' : scoreDelta > 10 ? '📈' : '➡️';
    const blockEmoji = shouldBlock.block ? '🚫' : '✅';
    
    let comment = `## ${blockEmoji} AI Security Copilot PR Analysis\n\n`;
    comment += `### Security Score Overview\n\n`;
    comment += `| Metric | Score | Status |\n`;
    comment += `|--------|-------|--------|\n`;
    comment += `| **Previous Score** | ${baselineScore} | ${baselineScore >= 70 ? '🚨 High Risk' : baselineScore >= 40 ? '⚠️ Medium Risk' : '✅ Low Risk'} |\n`;
    comment += `| **New Score** | ${candidateScore} | ${candidateScore >= 70 ? '🚨 High Risk' : candidateScore >= 40 ? '⚠️ Medium Risk' : '✅ Low Risk'} |\n`;
    comment += `| **Delta** | ${scoreDelta >= 0 ? '+' : ''}${scoreDelta} | ${deltaEmoji} ${scoreDelta < -10 ? 'Regressing' : scoreDelta > 10 ? 'Improving' : 'Stable'} |\n\n`;
    
    // Blocking status
    if (shouldBlock.block) {
      comment += `### 🚫 **PR BLOCKED**\n\n`;
      comment += `This PR introduces security risks and cannot be merged.\n\n`;
      comment += `**Blocking Reasons:**\n`;
      shouldBlock.reasons.forEach(reason => {
        comment += `- ${reason}\n`;
      });
      comment += `\n`;
    } else {
      comment += `### ✅ **PR Approved**\n\n`;
      comment += `No critical security issues detected. This PR can be merged.\n\n`;
    }
    
    // New issues
    if (newIssues.length > 0) {
      comment += `### New Security Issues\n\n`;
      newIssues.forEach((issue, index) => {
        const severityEmoji = issue.severity === 'CRITICAL' ? '🚨' : issue.severity === 'HIGH' ? '⚠️' : '⚡';
        comment += `${index + 1}. ${severityEmoji} **${issue.name}** (${issue.category})\n`;
        comment += `   - Severity: ${issue.severity}\n`;
        comment += `   - Description: ${issue.description}\n`;
        comment += `   - Score Impact: +${issue.score_impact}\n\n`;
      });
    }
    
    // Auto-fix suggestions
    if (scanDetails.candidate?.auto_fix_available && scanDetails.candidate?.auto_fixes) {
      comment += `### 🔧 Suggested Fixes\n\n`;
      scanDetails.candidate.auto_fixes.forEach((fix, index) => {
        comment += `#### Fix ${index + 1}: ${fix.name}\n\n`;
        comment += `**Explanation:** ${fix.auto_fix?.explanation}\n\n`;
        
        if (fix.auto_fix?.hardened_prompt) {
          comment += `<details>\n<summary>🔒 View Hardened Prompt</summary>\n\n`;
          comment += '```\\n';
          comment += fix.auto_fix.hardened_prompt;
          comment += '\\n```\\n\\n';
          comment += `</details>\n\n`;
        }
        
        if (fix.exploit_simulation) {
          comment += `<details>\n<summary>⚡ Exploit Simulation</summary>\n\n`;
          comment += `**Attack Input:** ${fix.exploit_simulation.attack_input}\n\n`;
          comment += `**Expected Behavior:** ${fix.exploit_simulation.expected_behavior}\n\n`;
          comment += `**Impact:** ${fix.exploit_simulation.impact}\n\n`;
          comment += `</details>\n\n`;
        }
      });
    }
    
    // Recommendations
    comment += `### Recommendations\n\n`;
    if (shouldBlock.block) {
      comment += `1. **Address blocking issues** before merging\n`;
      comment += `2. **Review new security findings** above\n`;
      comment += `3. **Apply suggested fixes** if available\n`;
      comment += `4. **Re-run scan** after making changes\n`;
    } else {
      comment += `1. **Monitor security score** in future changes\n`;
      if (newIssues.length > 0) {
        comment += `2. **Consider addressing new issues** proactively\n`;
      }
      comment += `3. **Maintain secure coding practices**\n`;
    }
    
    // Footer
    comment += `\n---\n`;
    comment += `*Scan performed with AI Security Copilot v2.3.0* | `;
    comment += `*Configuration: fail_on_increase=${config.fail_on_increase}, max_risk_score=${config.max_risk_score}*`;
    
    return comment;
  }

  getScoreImpact(severity) {
    const impacts = {
      'CRITICAL': 25,
      'HIGH': 15,
      'MEDIUM': 8,
      'LOW': 3
    };
    return impacts[severity] || 5;
  }

  getRiskLevel(score) {
    if (score >= 70) return 'HIGH';
    if (score >= 40) return 'MEDIUM';
    return 'LOW';
  }

  getBlockingReasons(shouldBlock, { scoreDelta, newIssues, config }) {
    if (!shouldBlock.block) return [];
    return shouldBlock.reasons || [];
  }
}

module.exports = { PRBlockerEngine };


/***/ }),

/***/ 436:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const github = __nccwpck_require__(276);

const SEVERITY_ICONS = {
  CRITICAL: '🔴',
  HIGH: '🟠',
  MEDIUM: '🟡',
  LOW: '🔵'
};

async function postPRComment(token, summary, comparison = null) {
  const octokit = github.getOctokit(token);

  const body = formatPRComment(summary, comparison);

  // Check for existing comment
  const { data: comments } = await octokit.rest.issues.listComments({
    owner: github.context.repo.owner,
    repo: github.context.repo.repo,
    issue_number: github.context.issue.number
  });

  const existingComment = comments.find(c =>
    c.user.type === 'Bot' &&
    c.body.includes('AI Security Copilot')
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

function formatPRComment(summary, comparison = null) {
  const { critical, high, medium, low, totalFindings, findings, passed, score = 0, baselineScore = null } = summary;

  // Calculate risk delta if comparison data available
  const currentScore = comparison?.candidate?.score ?? score ?? 0;
  const baseScore = comparison?.baseline?.score ?? baselineScore ?? 0;
  const scoreDelta = currentScore - baseScore;
  const isRiskIncreased = scoreDelta > 0;

  // Determine status
  const isBlocked = !passed || (comparison?.evaluation?.shouldBlock === true);
  const statusHeader = isBlocked ?
    '## 🚫 BLOCKED: Security Risk Increased' :
    '## ✅ SAFE TO MERGE: No Security Regressions';

  let comment = `${statusHeader}

`;

  // Risk Score Section with Delta
  comment += `### Risk Score

`;

  if (baselineScore !== null || comparison?.baseline) {
    comment += `| Before | After | Change |
|--------|-------|--------|
`;
    comment += `| **${baseScore}** | **${currentScore}** | ${isRiskIncreased ? '📈 +' : '📉 '}${scoreDelta} |

`;
  } else {
    comment += `**Current Risk Score:** ${currentScore}/100

`;
  }

  // Plain English Summary
  comment += `### What Changed

`;

  if (isBlocked) {
    if (critical > 0) {
      comment += `🔴 **${critical} critical security issue${critical > 1 ? 's' : ''} introduced.** `;
      comment += `These can lead to prompt injection, data breaches, or unauthorized system access.\n\n`;
    } else if (high > 0) {
      comment += `🟠 **${high} high-risk security issue${high > 1 ? 's' : ''} introduced.** `;
      comment += `These patterns could compromise AI safety or leak sensitive information.\n\n`;
    } else if (isRiskIncreased) {
      comment += `🟡 **Overall security posture degraded.** `;
      comment += `Risk score increased by ${scoreDelta} points due to new potentially dangerous patterns.\n\n`;
    } else {
      comment += `❌ **Security check failed.** Risk threshold exceeded.\n\n`;
    }
  } else {
    comment += `✅ No new security issues detected. This PR does not introduce additional risk.\n\n`;
  }

  // Suggested Fixes (if blocked)
  if (isBlocked && totalFindings > 0) {
    comment += `### Suggested Fixes

`;

    // Generate fix recommendations based on finding types
    const fixRecommendations = generateFixRecommendations(findings);
    for (const rec of fixRecommendations.slice(0, 3)) {
      comment += `- ${rec}\n`;
    }

    comment += `\n`;
  }

  // Finding Details (collapsible)
  if (totalFindings > 0) {
    comment += `### Details

`;

    // Group by severity
    const bySeverity = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
    for (const f of findings) {
      const sev = f.severity?.toUpperCase() || 'LOW';
      if (!bySeverity[sev]) bySeverity[sev] = [];
      bySeverity[sev].push(f);
    }

    // Show findings by severity (most critical first)
    for (const severity of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
      const sevFindings = bySeverity[severity];
      if (!sevFindings || sevFindings.length === 0) continue;

      const icon = SEVERITY_ICONS[severity];
      comment += `<details>
<summary>${icon} <strong>${severity}</strong> — ${sevFindings.length} finding${sevFindings.length > 1 ? 's' : ''}</summary>

`;

      for (const finding of sevFindings.slice(0, 10)) {
        comment += `**${finding.pattern || finding.category}** in \`${finding.file}\`\n`;
        if (finding.description) {
          comment += `> ${finding.description.substring(0, 120)}${finding.description.length > 120 ? '...' : ''}\n`;
        }
        comment += `\n`;
      }

      if (sevFindings.length > 10) {
        comment += `*... and ${sevFindings.length - 10} more ${severity.toLowerCase()} findings*\n`;
      }

      comment += `</details>

`;
    }
  }

  // Footer with clear next steps
  if (isBlocked) {
    comment += `---

**🛠️ Next Steps:**
1. Review the findings above and the suggested fixes
2. Update your code to remove dangerous patterns
3. Commit changes — this comment will auto-update
`;
  } else {
    comment += `---

✅ **No action required.** All security checks passed. Ready to merge.
`;
  }

  comment += `\n*AI Security Copilot — Blocking unsafe AI changes before production*`;

  return comment;
}

function generateFixRecommendations(findings) {
  const recommendations = new Set();

  // Check for specific pattern types and suggest fixes
  const hasInjection = findings.some(f =>
    f.pattern?.toLowerCase().includes('injection') ||
    f.pattern?.toLowerCase().includes('override') ||
    f.pattern?.toLowerCase().includes('jailbreak') ||
    f.category === 'LLM01'
  );

  const hasSecrets = findings.some(f =>
    f.pattern?.toLowerCase().includes('api key') ||
    f.pattern?.toLowerCase().includes('secret') ||
    f.pattern?.toLowerCase().includes('password') ||
    f.pattern?.toLowerCase().includes('private key') ||
    f.category === 'LLM02'
  );

  const hasDangerous = findings.some(f =>
    f.pattern?.toLowerCase().includes('sql') ||
    f.pattern?.toLowerCase().includes('command') ||
    f.pattern?.toLowerCase().includes('destructive') ||
    f.category === 'LLM05' || f.category === 'LLM06'
  );

  const hasPromptLeak = findings.some(f =>
    f.pattern?.toLowerCase().includes('leak') ||
    f.category === 'LLM07'
  );

  if (hasInjection) {
    recommendations.add('Remove instruction override phrases like "ignore previous instructions" or "disregard safety guidelines"');
    recommendations.add('Add input validation before passing user content to the AI system prompt');
  }

  if (hasSecrets) {
    recommendations.add('Move hardcoded credentials to environment variables or a secrets manager');
    recommendations.add('Rotate any exposed API keys immediately');
  }

  if (hasDangerous) {
    recommendations.add('Sanitize or remove shell commands, SQL queries, and file operations from AI outputs');
    recommendations.add('Add approval gates before executing any system-level actions');
  }

  if (hasPromptLeak) {
    recommendations.add('Remove system prompt content from user-facing responses');
    recommendations.add('Add canary tokens to detect if prompts are being extracted');
  }

  // Default recommendation if nothing specific matched
  if (recommendations.size === 0) {
    recommendations.add('Review the flagged patterns and remove or sanitize them');
    recommendations.add('Consider using stricter input validation for AI-generated content');
  }

  return Array.from(recommendations);
}

module.exports = { postPRComment, formatPRComment };


/***/ }),

/***/ 634:
/***/ ((module, __unused_webpack_exports, __nccwpck_require__) => {

const fs = __nccwpck_require__(896);
const https = __nccwpck_require__(692);
const path = __nccwpck_require__(928);

// Import PR Blocker engine
const { PRBlockerEngine } = __nccwpck_require__(500);

const API_URL = process.env.AI_SECURITY_API_URL || 'https://ai-agent-security-copilot.vercel.app/api/scans';
const prBlocker = new PRBlockerEngine();

async function scanFile(filePath, apiKey, options = {}) {
  const content = fs.readFileSync(filePath, 'utf8');
  
  // Skip binary files
  if (isBinary(content)) {
    return { findings: [] };
  }

  return new Promise((resolve, reject) => {
    const postData = JSON.stringify({
      content: content,
      scanContext: options.scanContext || 'github-action',
      sensitivity_tier: options.sensitivity_tier || process.env.SENSITIVITY_TIER || 'MEDIUM',
      skip_decoding: options.skip_decoding || process.env.OFFLINE_MODE === 'true'
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
      }
    };

    const reqModule = url.protocol === 'https:' ? https : __nccwpck_require__(611);
    
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
              findings: result.parsed?.deterministicFindings?.map(f => ({
                pattern: f.pattern || f.name,
                severity: f.severity,
                category: f.category || 'SECURITY',
                description: f.description || f.reason || '',
                score_impact: f.score_impact || 0
              })) || [],
              score: result.parsed?.score || 0,
              label: result.parsed?.label || 'LOW',
              // NEW: Return full result for PR blocking
              full_result: result,
              auto_fixes: result.parsed?.auto_fixes || [],
              context_tier: result.context_tier,
              obfuscation_detected: result.obfuscation_detected || false
            });
          } else if (res.statusCode === 401) {
            reject(new Error('Invalid API key. Please check your API key at https://ai-agent-security-copilot.vercel.app'));
          } else if (res.statusCode === 429) {
            reject(new Error('Rate limit exceeded. Please upgrade your plan or try again later.'));
          } else {
            // Fallback to local scanning if API fails
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
      // Fallback to local scanning on network error
      console.log(`⚠️ API unavailable, using local scan for ${filePath}`);
      const localResult = localScan(content);
      resolve(localResult);
    });

    req.write(postData);
    req.end();
  });
}

// Local fallback scanning using patterns from server.js
function localScan(content) {
  const findings = [];
  
  // Critical patterns (simplified version)
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
  // Check for null bytes or high ratio of non-printable chars
  const nullCount = (content.match(/\x00/g) || []).length;
  const nonPrintable = (content.match(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g) || []).length;
  
  if (nullCount > 0) return true;
  if (content.length > 0 && nonPrintable / content.length > 0.1) return true;
  
  return false;
}

// NEW: PR comparison function
async function compareWithBaseline(baselineFile, candidateFile, apiKey, options = {}) {
  const [baselineScan, candidateScan] = await Promise.all([
    scanFile(baselineFile, apiKey, options),
    scanFile(candidateFile, apiKey, options)
  ]);
  
  const prConfig = {
    fail_on_increase: process.env.FAIL_ON_INCREASE !== 'false',
    max_risk_score: parseInt(process.env.MAX_RISK_SCORE) || 70,
    min_score_delta: parseInt(process.env.MIN_SCORE_DELTA) || -10,
    block_new_critical: process.env.BLOCK_NEW_CRITICAL !== 'false',
    block_new_high: process.env.BLOCK_NEW_HIGH === 'true'
  };
  
  const evaluation = await prBlocker.evaluatePR(
    { parsed: baselineScan.full_result?.parsed || baselineScan },
    { parsed: candidateScan.full_result?.parsed || candidateScan },
    prConfig
  );
  
  return {
    baseline: baselineScan,
    candidate: candidateScan,
    evaluation: evaluation
  };
}

module.exports = { scanFile, localScan, compareWithBaseline };


/***/ }),

/***/ 860:
/***/ ((module) => {

module.exports = eval("require")("@actions/core");


/***/ }),

/***/ 276:
/***/ ((module) => {

module.exports = eval("require")("@actions/github");


/***/ }),

/***/ 275:
/***/ ((module) => {

module.exports = eval("require")("@actions/glob");


/***/ }),

/***/ 896:
/***/ ((module) => {

"use strict";
module.exports = require("fs");

/***/ }),

/***/ 611:
/***/ ((module) => {

"use strict";
module.exports = require("http");

/***/ }),

/***/ 692:
/***/ ((module) => {

"use strict";
module.exports = require("https");

/***/ }),

/***/ 928:
/***/ ((module) => {

"use strict";
module.exports = require("path");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __nccwpck_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		var threw = true;
/******/ 		try {
/******/ 			__webpack_modules__[moduleId](module, module.exports, __nccwpck_require__);
/******/ 			threw = false;
/******/ 		} finally {
/******/ 			if(threw) delete __webpack_module_cache__[moduleId];
/******/ 		}
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat */
/******/ 	
/******/ 	if (typeof __nccwpck_require__ !== 'undefined') __nccwpck_require__.ab = __dirname + "/";
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
const core = __nccwpck_require__(860);
const github = __nccwpck_require__(276);
const glob = __nccwpck_require__(275);
const fs = __nccwpck_require__(896);
const path = __nccwpck_require__(928);
const { scanFile } = __nccwpck_require__(634);
const { postPRComment } = __nccwpck_require__(436);

const API_URL = 'https://ai-agent-security-copilot.vercel.app/api/scans';

async function run() {
  try {
    // Get inputs
    const apiKey = core.getInput('api-key', { required: true });
    const scanPath = core.getInput('scan-path') || '.';
    const failOnHigh = core.getInput('fail-on-high') === 'true';
    const failOnCritical = core.getInput('fail-on-critical') !== 'false'; // default true
    const includePatterns = core.getInput('include-patterns');
    const excludePatterns = core.getInput('exclude-patterns');
    const maxFileSize = parseInt(core.getInput('max-file-size') || '500', 10);
    const prCommentEnabled = core.getInput('pr-comment') === 'true';
    const githubToken = core.getInput('github-token');

    console.log('🔒 AI Security Copilot - GitHub Action');
    console.log(`📁 Scan path: ${scanPath}`);
    console.log(`🎯 Fail on HIGH: ${failOnHigh}, CRITICAL: ${failOnCritical}`);
    console.log('');

    // Find files to scan
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

    // Scan all files
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

            // Count by severity
            const severity = finding.severity?.toUpperCase();
            if (severity === 'CRITICAL') criticalCount++;
            else if (severity === 'HIGH') highCount++;
            else if (severity === 'MEDIUM') mediumCount++;
            else lowCount++;
          }
        }

        // Print progress for large scans
        if (files.length > 20 && files.indexOf(file) % 10 === 0) {
          console.log(`  Scanned ${files.indexOf(file) + 1}/${files.length} files...`);
        }
      } catch (error) {
        console.error(`❌ Error scanning ${file}: ${error.message}`);
      }
    }

    // Calculate overall risk score (simplified from findings)
    const riskScore = (criticalCount * 75) + (highCount * 25) + (mediumCount * 10) + (lowCount * 5);
    const cappedScore = Math.min(100, riskScore);

    // Build summary
    const summary = {
      totalFiles: files.length,
      totalFindings: allFindings.length,
      critical: criticalCount,
      high: highCount,
      medium: mediumCount,
      low: lowCount,
      findings: allFindings,
      passed: true,
      score: cappedScore
    };

    // Determine if scan passed
    let hasFailures = false;
    if (failOnCritical && criticalCount > 0) {
      hasFailures = true;
      summary.passed = false;
    }
    if (failOnHigh && highCount > 0) {
      hasFailures = true;
      summary.passed = false;
    }

    // Set outputs
    core.setOutput('summary', JSON.stringify(summary));
    core.setOutput('critical-count', String(criticalCount));
    core.setOutput('high-count', String(highCount));
    core.setOutput('total-findings', String(allFindings.length));
    core.setOutput('has-failures', String(hasFailures));

    // Print results
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

    // Print findings table
    if (allFindings.length > 0) {
      console.log('🚨 SECURITY FINDINGS:');
      console.log('-'.repeat(60));
      
      // Group by severity
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
        
        for (const finding of findings.slice(0, 10)) { // Show first 10
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

    // Post PR comment if enabled and in PR context
    if (prCommentEnabled && githubToken && github.context.payload.pull_request) {
      await postPRComment(githubToken, summary, null);
    }

    // Final status
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

async function findFiles(scanPath, includePatterns, excludePatterns, maxFileSizeKB) {
  const files = [];
  const maxBytes = maxFileSizeKB * 1024;
  
  // Parse patterns
  const includes = includePatterns.split(',').map(p => p.trim()).filter(Boolean);
  const excludes = excludePatterns.split(',').map(p => p.trim()).filter(Boolean);

  // Use glob for pattern matching
  for (const pattern of includes) {
    const globber = await glob.create(pattern, {
      followSymbolicLinks: false
    });
    
    for await (const file of globber.globGenerator()) {
      // Check excludes
      let excluded = false;
      for (const exclude of excludes) {
        const excludeGlob = await glob.create(exclude);
        const excludedFiles = await excludeGlob.glob();
        if (excludedFiles.includes(file) || file.includes(exclude.replace('**/', '').replace('/*', ''))) {
          excluded = true;
          break;
        }
      }
      
      if (excluded) continue;
      
      // Check file size
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

  // If scanPath is a specific file
  if (fs.existsSync(scanPath) && fs.statSync(scanPath).isFile()) {
    const resolved = path.resolve(scanPath);
    if (!files.includes(resolved)) {
      files.push(resolved);
    }
  }

  return [...new Set(files)]; // Deduplicate
}

run();

module.exports = __webpack_exports__;
/******/ })()
;