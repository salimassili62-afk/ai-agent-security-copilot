const github = require('@actions/github');

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
