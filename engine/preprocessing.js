// Advanced Evasion Detection & Preprocessing
// Handles Base64, hex, URL encoding, and obfuscation bypass attempts

const crypto = require('crypto');

class PreprocessingEngine {
  constructor() {
    this.decodeAttempts = 5; // Max recursive decode depth
    this.suspiciousPatterns = [
      /base64/i,
      /hex/i,
      /url.*encod/i,
      /unicode/i,
      /utf-?8/i,
      /ascii/i,
      /binary/i,
      /obfuscat/i,
      /encode/i,
      /decode/i,
      /transform/i,
      /convert/i
    ];

    this.tokenSmugglingPatterns = [
      // Space-based obfuscation
      { pattern: /i g n o r e/gi, replacement: 'ignore' },
      { pattern: /e x e c u t e/gi, replacement: 'execute' },
      { pattern: /s y s t e m/gi, replacement: 'system' },
      { pattern: /p a s s w o r d/gi, replacement: 'password' },
      { pattern: /a p i.*k e y/gi, replacement: 'api key' },
      
      // Zero-width characters
      { pattern: /[\u200B-\u200D\uFEFF]/g, replacement: '' },
      
      // Homoglyph substitutions (common Cyrillic/Latin lookalikes)
      { pattern: /[а]/g, replacement: 'a' }, // Cyrillic a
      { pattern: /[о]/g, replacement: 'o' }, // Cyrillic o
      { pattern: /[і]/g, replacement: 'i' }, // Cyrillic i
      { pattern: /[ј]/g, replacement: 'j' }, // Cyrillic j
      { pattern: /[с]/g, replacement: 'c' }, // Cyrillic c
      { pattern: /[е]/g, replacement: 'e' }, // Cyrillic e
      
      // Leetspeak variations
      { pattern: /3x3cut3/gi, replacement: 'execute' },
      { pattern: /p455w0rd/gi, replacement: 'password' },
      { pattern: /adm1n/gi, replacement: 'admin' },
      { pattern: /r00t/gi, replacement: 'root' },
      { pattern: /5y5t3m/gi, replacement: 'system' },
      
      // Character insertion
      { pattern: /e.x.e.c.u.t.e/gi, replacement: 'execute' },
      { pattern: /p.a.s.s.w.o.r.d/gi, replacement: 'password' },
      { pattern: /s.y.s.t.e.m/gi, replacement: 'system' }
    ];
  }

  async preprocess(input, options = {}) {
    const result = {
      original: input,
      processed: input,
      transformations: [],
      obfuscation_detected: false,
      confidence: 1.0,
      metadata: {}
    };

    try {
      // Step 1: Detect potential encoding/obfuscation
      const encodingIndicators = this.detectEncodingIndicators(input);
      if (encodingIndicators.length > 0) {
        result.obfuscation_detected = true;
        result.metadata.encoding_indicators = encodingIndicators;
      }

      // Step 2: Apply token smuggling detection
      const desmuggled = this.detectTokenSmuggling(input);
      if (desmuggled.changed) {
        result.processed = desmuggled.text;
        result.transformations.push({
          type: 'token_smuggling',
          description: 'Detected and reversed token smuggling',
          patterns_found: desmuggled.patterns
        });
      }

      // Step 3: Attempt decoding if encoding detected
      if (result.obfuscation_detected && !options.skip_decoding) {
        const decoded = await this.attemptDecoding(result.processed);
        if (decoded.success) {
          result.processed = decoded.text;
          result.transformations.push(...decoded.transformations);
        }
      }

      // Step 4: Check for multi-layer obfuscation
      if (result.transformations.length > 1) {
        result.metadata.suspicion_level = 'HIGH';
        result.confidence = 0.9;
      } else if (result.transformations.length === 1) {
        result.metadata.suspicion_level = 'MEDIUM';
        result.confidence = 0.7;
      }

      // Step 5: Generate obfuscation summary
      result.metadata.obfuscation_summary = this.generateObfuscationSummary(result);

    } catch (e) {
      console.log('[PREPROCESSING] Error during preprocessing:', e.message);
      // Return original if preprocessing fails
      result.processed = input;
      result.error = e.message;
    }

    return result;
  }

  detectEncodingIndicators(text) {
    const indicators = [];
    
    this.suspiciousPatterns.forEach(pattern => {
      if (pattern.test(text)) {
        indicators.push({
          type: 'encoding_keyword',
          pattern: pattern.source,
          matches: text.match(pattern)
        });
      }
    });

    // Check for common encoded patterns
    if (/^[A-Za-z0-9+/]+=*$/.test(text) && text.length % 4 === 0) {
      indicators.push({
        type: 'potential_base64',
        reason: 'Text matches Base64 pattern'
      });
    }

    if (/^[0-9a-fA-F\s]+$/.test(text) && text.length % 2 === 0) {
      indicators.push({
        type: 'potential_hex',
        reason: 'Text contains only hex characters'
      });
    }

    if (/%[0-9A-Fa-f]{2}/.test(text)) {
      indicators.push({
        type: 'url_encoded',
        reason: 'URL encoding patterns detected'
      });
    }

    return indicators;
  }

  detectTokenSmuggling(text) {
    let modified = text;
    const patternsFound = [];

    this.tokenSmugglingPatterns.forEach(({ pattern, replacement }) => {
      const matches = modified.match(pattern);
      if (matches) {
        modified = modified.replace(pattern, replacement);
        patternsFound.push({
          pattern: pattern.source,
          matches: matches.length,
          replacement: replacement
        });
      }
    });

    return {
      text: modified,
      changed: modified !== text,
      patterns: patternsFound
    };
  }

  async attemptDecoding(text) {
    const result = {
      success: false,
      text: text,
      transformations: []
    };

    let current = text;
    let attempts = 0;

    while (attempts < this.decodeAttempts) {
      let decoded = null;
      let transformation = null;

      // Try Base64 decode
      if (/^[A-Za-z0-9+/]+=*$/.test(current) && current.length % 4 === 0) {
        try {
          decoded = Buffer.from(current, 'base64').toString('utf8');
          if (decoded && decoded !== current && this.isValidText(decoded)) {
            transformation = {
              type: 'base64_decode',
              from: current.substring(0, 50) + (current.length > 50 ? '...' : ''),
              to: decoded.substring(0, 50) + (decoded.length > 50 ? '...' : '')
            };
          }
        } catch (e) {
          // Invalid Base64, continue
        }
      }

      // Try URL decode
      if (!decoded && /%[0-9A-Fa-f]{2}/.test(current)) {
        try {
          decoded = decodeURIComponent(current);
          if (decoded !== current) {
            transformation = {
              type: 'url_decode',
              from: current.substring(0, 50) + (current.length > 50 ? '...' : ''),
              to: decoded.substring(0, 50) + (decoded.length > 50 ? '...' : '')
            };
          }
        } catch (e) {
          // Invalid URL encoding, continue
        }
      }

      // Try hex decode
      if (!decoded && /^[0-9a-fA-F\s]+$/.test(current)) {
        try {
          const cleanHex = current.replace(/\s/g, '');
          if (cleanHex.length % 2 === 0) {
            decoded = Buffer.from(cleanHex, 'hex').toString('utf8');
            if (decoded && this.isValidText(decoded)) {
              transformation = {
                type: 'hex_decode',
                from: current.substring(0, 50) + (current.length > 50 ? '...' : ''),
                to: decoded.substring(0, 50) + (decoded.length > 50 ? '...' : '')
              };
            }
          }
        } catch (e) {
          // Invalid hex, continue
        }
      }

      // If no decoding succeeded, break
      if (!decoded) {
        break;
      }

      // Apply successful decoding
      current = decoded;
      result.transformations.push(transformation);
      result.success = true;
      attempts++;

      // Safety check to prevent infinite loops
      if (current.length > text.length * 10) {
        break;
      }
    }

    result.text = current;
    return result;
  }

  isValidText(text) {
    // Check if decoded text is meaningful (not just random bytes)
    const printableChars = text.match(/[a-zA-Z0-9\s\p{P}\p{S}]/gu);
    return printableChars && printableChars.length / text.length > 0.7;
  }

  generateObfuscationSummary(result) {
    const summary = {
      total_transformations: result.transformations.length,
      transformation_types: result.transformations.map(t => t.type),
      suspicion_level: result.metadata.suspicion_level || 'LOW',
      recommendations: []
    };

    // Add recommendations based on detected obfuscation
    if (result.transformations.some(t => t.type.includes('decode'))) {
      summary.recommendations.push('Encoding detected - this is a common evasion technique');
    }

    if (result.transformations.some(t => t.type === 'token_smuggling')) {
      summary.recommendations.push('Token smuggling detected - characters were obfuscated to bypass filters');
    }

    if (result.transformations.length > 2) {
      summary.recommendations.push('Multi-layer obfuscation detected - highly suspicious');
      summary.suspicion_level = 'HIGH';
    }

    return summary;
  }

  // Generate hash for caching preprocessed results
  generateHash(input) {
    return crypto.createHash('sha256').update(input).digest('hex');
  }
}

module.exports = { PreprocessingEngine };
