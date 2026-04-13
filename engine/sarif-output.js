// SARIF Output Engine
// Generates SARIF format for GitHub Security tab integration

class SARIFOutputEngine {
  constructor() {
    this.toolInfo = {
      name: 'AI Security Copilot',
      version: '2.3.0',
      semanticVersion: '2.3.0',
      informationUri: 'https://github.com/salimassili62-afk/ai-agent-security-copilot'
    };
  }

  generateSARIF(scanResults, filePath, options = {}) {
    const timestamp = new Date().toISOString();
    
    const sarif = {
      $schema: 'https://json.schemastore.org/sarif-2.1.0',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: this.toolInfo
        },
        originalUriBaseIds: {
          SRCROOT: {
            uri: options.baseUri || 'file:///'
          }
        },
        artifacts: [
          {
            location: {
              uri: filePath,
              uriBaseId: 'SRCROOT'
            },
            length: scanResults.content?.length || 0,
            sha256: this.generateSHA256(scanResults.content || '')
          }
        ],
        results: this.convertFindingsToResults(scanResults, filePath, timestamp)
      }]
    };

    return sarif;
  }

  convertFindingsToResults(scanResults, filePath, timestamp) {
    const results = [];
    const parsed = scanResults.parsed || scanResults;

    // Convert deterministic findings
    if (parsed.deterministicFindings) {
      parsed.deterministicFindings.forEach((finding, index) => {
        results.push(this.createResult(finding, filePath, timestamp, index));
      });
    }

    // Convert OWASP findings
    if (parsed.owasp) {
      parsed.owasp.forEach((owasp, index) => {
        results.push(this.createOWASPResult(owasp, filePath, timestamp, index));
      });
    }

    // Add auto-fix information if available
    if (parsed.auto_fixes) {
      parsed.auto_fixes.forEach((fix, index) => {
        const result = results.find(r => r.ruleId === fix.category || r.message.text.includes(fix.name));
        if (result && !result.fixes) {
          result.fixes = [this.createFix(fix)];
        }
      });
    }

    return results;
  }

  createResult(finding, filePath, timestamp, index) {
    const level = this.mapSeverityToLevel(finding.severity);
    const ruleId = finding.category || `SEC${String(index + 1).padStart(3, '0')}`;
    
    return {
      ruleId: ruleId,
      level: level,
      message: {
        text: finding.description || finding.name || 'Security issue detected'
      },
      locations: [{
        physicalLocation: {
          artifactLocation: {
            uri: filePath
          },
          region: {
            startLine: finding.line || 1,
            startColumn: finding.column || 1,
            endLine: finding.endLine || finding.line || 1,
            endColumn: finding.endColumn || finding.column || 1
          }
        }
      }],
      partialFingerprints: {
        primaryLocationLineHash: this.generateFingerprint(finding)
      },
      properties: {
        severity: finding.severity,
        category: finding.category,
        pattern: finding.pattern || finding.name,
        score_impact: finding.score_impact || 0,
        context_tier: finding.context?.tier || 'MEDIUM',
        tags: ['security', 'llm', finding.category?.toLowerCase() || 'security'].filter(Boolean)
      }
    };
  }

  createOWASPResult(owasp, filePath, timestamp, index) {
    const level = this.mapSeverityToLevel(owasp.severity);
    
    return {
      ruleId: owasp.id,
      level: level,
      message: {
        text: owasp.title || `${owasp.id} - Security issue`
      },
      locations: [{
        physicalLocation: {
          artifactLocation: {
            uri: filePath
          },
          region: {
            startLine: 1,
            startColumn: 1,
            endLine: 1,
            endColumn: 1
          }
        }
      }],
      partialFingerprints: {
        primaryLocationLineHash: this.generateFingerprint(owasp)
      },
      properties: {
        severity: owasp.severity,
        category: owasp.id,
        owasp_category: owasp.id,
        owasp_title: owasp.title,
        note: owasp.note,
        tags: ['security', 'llm', 'owasp', owasp.id.toLowerCase()]
      }
    };
  }

  createFix(fix) {
    const fixDescription = fix.auto_fix?.explanation || 'Security hardening applied';
    
    return {
      description: {
        text: fixDescription
      },
      changes: [{
        artifactLocation: {
          uri: '*' // Apply to entire file
        },
        replacements: fix.auto_fix?.hardened_prompt ? [{
          deletedRegion: {
            charOffset: 0,
            charLength: 0 // Will be replaced entirely
          },
          insertedContent: {
            text: fix.auto_fix.hardened_prompt
          }
        }] : []
      }]
    };
  }

  mapSeverityToLevel(severity) {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL':
        return 'error';
      case 'HIGH':
        return 'error';
      case 'MEDIUM':
        return 'warning';
      case 'LOW':
        return 'note';
      default:
        return 'warning';
    }
  }

  generateSHA256(content) {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(content).digest('hex');
  }

  generateFingerprint(finding) {
    const crypto = require('crypto');
    const fingerprint = `${finding.category || 'unknown'}-${finding.severity || 'unknown'}-${finding.name || finding.pattern || 'unknown'}`;
    return crypto.createHash('sha256').update(fingerprint).digest('hex').substring(0, 16);
  }

  // Generate SARIF for multiple files (batch scan)
  generateBatchSARIF(scanResultsList, options = {}) {
    const timestamp = new Date().toISOString();
    const allResults = [];
    const artifacts = [];
    
    scanResultsList.forEach((scanResult, index) => {
      const filePath = scanResult.filePath || `file${index}.txt`;
      const results = this.convertFindingsToResults(scanResult, filePath, timestamp);
      
      allResults.push(...results);
      
      artifacts.push({
        location: {
          uri: filePath,
          uriBaseId: 'SRCROOT'
        },
        length: scanResult.content?.length || 0,
        sha256: this.generateSHA256(scanResult.content || '')
      });
    });
    
    const sarif = {
      $schema: 'https://json.schemastore.org/sarif-2.1.0',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: this.toolInfo
        },
        originalUriBaseIds: {
          SRCROOT: {
            uri: options.baseUri || 'file:///'
          }
        },
        artifacts: artifacts,
        results: allResults
      }]
    };
    
    return sarif;
  }

  // Export SARIF to file
  exportToFile(sarif, outputPath) {
    const fs = require('fs');
    const content = JSON.stringify(sarif, null, 2);
    
    fs.writeFileSync(outputPath, content, 'utf8');
    return outputPath;
  }

  // Generate SARIF summary for CLI output
  generateSummary(sarif) {
    const run = sarif.runs[0];
    const results = run.results || [];
    
    const summary = {
      total: results.length,
      error: results.filter(r => r.level === 'error').length,
      warning: results.filter(r => r.level === 'warning').length,
      note: results.filter(r => r.level === 'note').length,
      categories: [...new Set(results.map(r => r.properties?.category).filter(Boolean))],
      files: [...new Set(run.artifacts?.map(a => a.location.uri) || [])]
    };
    
    return summary;
  }
}

module.exports = { SARIFOutputEngine };
