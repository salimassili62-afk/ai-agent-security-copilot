const github = require('@actions/github');

const SEVERITY_ICONS = {
  CRITICAL: '🔴',
  HIGH: '🟠',
  MEDIUM: '🟡',
  LOW: '🔵'
};

const SEVERITY_COLORS = {
  CRITICAL: '#FF0000',
  HIGH: '#FF6600',
  MEDIUM: '#FFCC00',
  LOW: '#0066CC'
};

async function postPRComment(token, summary) {
  const octokit = github.getOctokit(token);
  const { data: pullRequest } = await octokit.rest.pulls.get({
    owner: github.context.repo.owner,
    repo: github.context.repo.repo,
    pull_number: github.context.issue.number
  });

  const body = formatPRComment(summary);

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

function formatPRComment(summary) {
  const { critical, high, medium, low, totalFindings, findings, passed } = summary;
  
  const statusIcon = passed ? '✅' : '❌';
  const statusText = passed ? 'PASSED' : 'FAILED';
  const statusColor = passed ? 'success' : 'critical';

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
<summary>${icon} ${severity} (${sevFindings.length})</summary>

`;

      for (const finding of sevFindings.slice(0, 20)) {
        comment += `- **${finding.pattern || finding.category}** in \`${finding.file}\`
`;
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

module.exports = { postPRComment, formatPRComment };
