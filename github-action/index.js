const core = require('@actions/core');
const github = require('@actions/github');
const glob = require('@actions/glob');
const fs = require('fs');
const path = require('path');
const { scanFile } = require('./scanner');
const { postPRComment } = require('./pr-comment');

const API_URL = 'https://ai-agent-security-copilot.vercel.app/api/scan';

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

    // Build summary
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
      await postPRComment(githubToken, summary);
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
