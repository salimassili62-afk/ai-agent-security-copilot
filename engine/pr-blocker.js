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
