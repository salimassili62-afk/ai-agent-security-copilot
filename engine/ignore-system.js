// .aisecignore System
// Handles false positive control and rule exclusions

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

class IgnoreSystem {
  constructor() {
    this.ignoreRules = new Map();
    this.globalIgnores = new Set();
    this.pathIgnores = new Map();
  }

  loadIgnoreFile(ignorePath = '.aisecignore') {
    try {
      if (!fs.existsSync(ignorePath)) {
        return { loaded: false, reason: 'File not found' };
      }

      const content = fs.readFileSync(ignorePath, 'utf8');
      const config = this.parseIgnoreContent(content, ignorePath);
      
      this.applyIgnoreConfig(config);
      
      return { 
        loaded: true, 
        rules: config.rules?.length || 0,
        paths: config.paths?.length || 0
      };
    } catch (e) {
      return { loaded: false, reason: e.message };
    }
  }

  parseIgnoreContent(content, filePath) {
    const config = {
      version: '1.0',
      rules: [],
      paths: [],
      global: []
    };

    // Try YAML first
    try {
      const yamlConfig = yaml.load(content);
      if (yamlConfig && typeof yamlConfig === 'object') {
        config.version = yamlConfig.version || '1.0';
        config.rules = yamlConfig.ignore || yamlConfig.rules || [];
        config.paths = yamlConfig.paths || [];
        config.global = yamlConfig.global || [];
        return config;
      }
    } catch (e) {
      // Not YAML, try simple format
    }

    // Simple line-by-line format
    const lines = content.split('\n').map(line => line.trim()).filter(line => 
      line && !line.startsWith('#')
    );

    for (const line of lines) {
      if (line.startsWith('rule:')) {
        const rule = line.substring(5).trim();
        config.rules.push({ rule: rule });
      } else if (line.startsWith('path:')) {
        const pattern = line.substring(5).trim();
        config.paths.push({ pattern: pattern });
      } else if (line.startsWith('global:')) {
        const rule = line.substring(7).trim();
        config.global.push(rule);
      } else if (line.includes(':')) {
        // Try to parse as "rule: LLM01" format
        const [key, value] = line.split(':', 2);
        if (key.trim().toLowerCase() === 'rule') {
          config.rules.push({ rule: value.trim() });
        }
      }
    }

    return config;
  }

  applyIgnoreConfig(config) {
    // Clear existing rules
    this.ignoreRules.clear();
    this.globalIgnores.clear();
    this.pathIgnores.clear();

    // Apply global ignores
    config.global.forEach(rule => {
      this.globalIgnores.add(rule.toUpperCase());
    });

    // Apply rule-specific ignores
    config.rules.forEach(rule => {
      const key = rule.rule?.toUpperCase();
      if (key) {
        if (!this.ignoreRules.has(key)) {
          this.ignoreRules.set(key, []);
        }
        this.ignoreRules.get(key).push(rule);
      }
    });

    // Apply path-specific ignores
    config.paths.forEach(pathRule => {
      const pattern = pathRule.pattern;
      const rules = pathRule.rules || [];
      this.pathIgnores.set(pattern, rules.map(r => r.toUpperCase()));
    });
  }

  shouldIgnore(finding, filePath = '') {
    // Check global ignores first
    if (this.globalIgnores.has(finding.category?.toUpperCase())) {
      return {
        ignored: true,
        reason: `Globally ignored rule: ${finding.category}`,
        type: 'global'
      };
    }

    // Check rule-specific ignores
    const ruleKey = finding.category?.toUpperCase();
    if (this.ignoreRules.has(ruleKey)) {
      const rules = this.ignoreRules.get(ruleKey);
      
      for (const rule of rules) {
        if (this.matchesRule(finding, rule, filePath)) {
          return {
            ignored: true,
            reason: `Rule ignored: ${finding.category}`,
            type: 'rule',
            rule: rule
          };
        }
      }
    }

    // Check path-specific ignores
    for (const [pattern, ignoredRules] of this.pathIgnores.entries()) {
      if (this.matchesPath(filePath, pattern)) {
        if (ignoredRules.includes(ruleKey) || ignoredRules.length === 0) {
          return {
            ignored: true,
            reason: `Path ignored: ${pattern}`,
            type: 'path',
            pattern: pattern
          };
        }
      }
    }

    return { ignored: false };
  }

  matchesRule(finding, rule, filePath) {
    // Simple rule matching - can be extended
    if (rule.severity && finding.severity !== rule.severity) {
      return false;
    }

    if (rule.pattern && !finding.name?.includes(rule.pattern)) {
      return false;
    }

    if (rule.path && !this.matchesPath(filePath, rule.path)) {
      return false;
    }

    return true;
  }

  matchesPath(filePath, pattern) {
    if (!pattern) return true;
    if (!filePath) return false;

    // Convert to relative path
    const relativePath = path.relative(process.cwd(), filePath);
    
    // Simple glob matching
    if (pattern.includes('*')) {
      const regex = new RegExp(
        '^' + pattern.replace(/\*/g, '.*').replace(/\?/g, '.') + '$'
      );
      return regex.test(relativePath) || regex.test(filePath);
    }

    // Exact match or contains
    return relativePath === pattern || 
           filePath === pattern ||
           relativePath.endsWith(pattern) ||
           filePath.endsWith(pattern);
  }

  filterFindings(findings, filePath = '') {
    const filtered = [];
    const ignored = [];

    for (const finding of findings) {
      const ignoreResult = this.shouldIgnore(finding, filePath);
      
      if (ignoreResult.ignored) {
        ignored.push({
          ...finding,
          ignore_reason: ignoreResult.reason,
          ignore_type: ignoreResult.type
        });
      } else {
        filtered.push(finding);
      }
    }

    return {
      allowed: filtered,
      ignored: ignored,
      total_original: findings.length,
      total_allowed: filtered.length,
      total_ignored: ignored.length
    };
  }

  generateIgnoreReport() {
    const report = {
      global_rules: Array.from(this.globalIgnores),
      rule_specific: {},
      path_specific: {},
      summary: {
        total_global_ignores: this.globalIgnores.size,
        total_rule_ignores: 0,
        total_path_ignores: this.pathIgnores.size
      }
    };

    // Rule-specific ignores
    for (const [key, rules] of this.ignoreRules.entries()) {
      report.rule_specific[key] = rules;
      report.summary.total_rule_ignores += rules.length;
    }

    // Path-specific ignores
    for (const [pattern, rules] of this.pathIgnores.entries()) {
      report.path_specific[pattern] = rules;
    }

    return report;
  }

  // Create example .aisecignore file
  static createExampleFile(outputPath = '.aisecignore') {
    const example = `# AI Security Copilot Ignore File
# Version: 1.0
# 
# Use this file to exclude false positives and specific rules

# YAML Format (recommended)
version: "1.0"

# Global ignores - apply to all files
global:
  - "LLM02"  # Ignore insecure output warnings globally

# Rule-specific ignores
ignore:
  - rule: "LLM01"
    severity: "LOW"  # Only ignore low-severity prompt injections
    reason: "False positive for creative writing prompts"
  
  - rule: "LLM06"
    pattern: "system"
    reason: "Legitimate system roleplay"

# Path-specific ignores
paths:
  - pattern: "tests/*"
    rules: ["LLM01", "LLM06"]  # Ignore these rules in test files
    reason: "Test files contain intentional security test cases"
  
  - pattern: "prompts/creative/*"
    rules: ["LLM01"]  # Allow roleplay in creative prompts
    reason: "Creative writing context"
  
  - pattern: "docs/examples/*"
    rules: []  # Ignore all security rules in documentation examples
    reason: "Educational examples only"

# Simple format (alternative):
# rule: LLM01
# rule: LLM02
# path: tests/*
# global: LLM06
`;

    fs.writeFileSync(outputPath, example, 'utf8');
    return outputPath;
  }
}

module.exports = { IgnoreSystem };
