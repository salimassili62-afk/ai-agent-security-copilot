const fs = require('fs');
const https = require('https');

const API_URL = process.env.AI_SECURITY_API_URL || 'https://ai-agent-security-copilot.vercel.app/api/scan';

async function scanFile(filePath, apiKey) {
  const content = fs.readFileSync(filePath, 'utf8');
  
  // Skip binary files
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
      }
    };

    const reqModule = url.protocol === 'https:' ? https : require('http');
    
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

module.exports = { scanFile, localScan };
