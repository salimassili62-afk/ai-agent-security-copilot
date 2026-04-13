// Context-Aware Detection Engine
// Dynamically adjusts detection based on sensitivity tiers and use case

class ContextAwareEngine {
  constructor() {
    this.sensitivityTiers = {
      LOW: {
        name: 'Creative/Entertainment',
        threshold_multiplier: 0.5,
        severity_adjustments: {
          'CRITICAL': 'HIGH',
          'HIGH': 'MEDIUM',
          'MEDIUM': 'LOW'
        },
        description: 'For creative bots, roleplay, entertainment applications'
      },
      MEDIUM: {
        name: 'General Applications',
        threshold_multiplier: 0.75,
        severity_adjustments: {
          'CRITICAL': 'CRITICAL',
          'HIGH': 'HIGH',
          'MEDIUM': 'MEDIUM'
        },
        description: 'For general customer service, information apps'
      },
      HIGH: {
        name: 'Production/Finance/Agents',
        threshold_multiplier: 1.0,
        severity_adjustments: {
          'CRITICAL': 'CRITICAL',
          'HIGH': 'CRITICAL',
          'MEDIUM': 'HIGH'
        },
        description: 'For finance, agents, production systems, sensitive data'
      }
    };

    this.contextIndicators = {
      creative: [
        'story', 'character', 'roleplay', 'fiction', 'creative', 'imagine',
        'pretend', 'act as', 'persona', 'narrative', 'dialogue'
      ],
      finance: [
        'bank', 'financial', 'money', 'payment', 'transaction', 'investment',
        'portfolio', 'trading', 'account', 'credit', 'loan'
      ],
      agent: [
        'execute', 'run', 'command', 'system', 'admin', 'automation',
        'workflow', 'task', 'process', 'deploy', 'manage'
      ],
      medical: [
        'medical', 'health', 'patient', 'diagnosis', 'treatment', 'prescribe',
        'clinical', 'therapy', 'symptom', 'medication'
      ],
      legal: [
        'legal', 'contract', 'law', 'court', 'attorney', 'compliance',
        'regulation', 'lawsuit', 'jurisdiction', 'liability']
    };
  }

  analyzeContext(prompt, metadata = {}) {
    // Determine sensitivity tier based on content and metadata
    const lowerPrompt = prompt.toLowerCase();
    
    // Check for explicit tier in metadata
    if (metadata.sensitivity_tier) {
      const tier = metadata.sensitivity_tier.toUpperCase();
      if (this.sensitivityTiers[tier]) {
        return {
          tier: tier,
          confidence: 1.0,
          reasoning: 'Explicitly configured'
        };
      }
    }

    // Analyze content for context clues
    const scores = {
      LOW: 0,
      MEDIUM: 0,
      HIGH: 0
    };

    // Creative indicators
    this.contextIndicators.creative.forEach(word => {
      if (lowerPrompt.includes(word)) scores.LOW += 0.3;
    });

    // Finance/Agent indicators (HIGH)
    [...this.contextIndicators.finance, ...this.contextIndicators.agent].forEach(word => {
      if (lowerPrompt.includes(word)) scores.HIGH += 0.4;
    });

    // Medical/Legal indicators (HIGH)
    [...this.contextIndicators.medical, ...this.contextIndicators.legal].forEach(word => {
      if (lowerPrompt.includes(word)) scores.HIGH += 0.5;
    });

    // Check for roleplay vs adversarial patterns
    const benignRoleplay = [
      'act as a', 'pretend to be', 'imagine you are', 'roleplay as',
      'take on the role', 'character', 'story', 'fiction'
    ];
    
    const adversarialPatterns = [
      'ignore previous', 'disregard instructions', 'override',
      'bypass', 'jailbreak', 'extract', 'reveal your', 'system prompt'
    ];

    let benignScore = 0;
    let adversarialScore = 0;

    benignRoleplay.forEach(pattern => {
      if (lowerPrompt.includes(pattern)) benignScore += 0.2;
    });

    adversarialPatterns.forEach(pattern => {
      if (lowerPrompt.includes(pattern)) adversarialScore += 0.5;
    });

    // Adjust scores based on roleplay analysis
    if (benignScore > adversarialScore && benignScore > 0.4) {
      scores.LOW += 0.5;
      scores.HIGH -= 0.3;
    } else if (adversarialScore > 0.3) {
      scores.HIGH += 0.5;
      scores.LOW -= 0.5;
    }

    // Determine final tier
    const maxScore = Math.max(...Object.values(scores));
    const tier = maxScore === scores.LOW ? 'LOW' : 
                 maxScore === scores.HIGH ? 'HIGH' : 'MEDIUM';

    return {
      tier,
      confidence: Math.min(maxScore / 2, 1.0),
      reasoning: `Content analysis: Creative=${scores.LOW.toFixed(2)}, General=${scores.MEDIUM.toFixed(2)}, Sensitive=${scores.HIGH.toFixed(2)}`,
      context_scores: scores
    };
  }

  adjustDetection(findings, context) {
    const tier = this.sensitivityTiers[context.tier];
    const adjustedFindings = [];

    for (const finding of findings) {
      const adjusted = { ...finding };

      // Adjust severity based on tier
      if (tier.severity_adjustments[finding.severity]) {
        adjusted.original_severity = finding.severity;
        adjusted.severity = tier.severity_adjustments[finding.severity];
        adjusted.severity_adjusted = true;
        adjusted.adjustment_reason = `Adjusted for ${tier.name} tier`;
      }

      // Adjust score based on threshold multiplier
      if (finding.score) {
        adjusted.original_score = finding.score;
        adjusted.score = Math.round(finding.score * tier.threshold_multiplier);
        adjusted.score_adjusted = true;
      }

      // Add context metadata
      adjusted.context = {
        tier: context.tier,
        tier_name: tier.name,
        confidence: context.confidence
      };

      adjustedFindings.push(adjusted);
    }

    return adjustedFindings;
  }

  shouldBlock(finding, context) {
    const tier = this.sensitivityTiers[context.tier];
    
    // Different blocking thresholds per tier
    const blockThresholds = {
      LOW: { score: 80, severity: 'CRITICAL' },
      MEDIUM: { score: 60, severity: 'HIGH' },
      HIGH: { score: 40, severity: 'MEDIUM' }
    };

    const threshold = blockThresholds[context.tier];
    
    return finding.score >= threshold.score || 
           finding.severity === threshold.severity ||
           finding.severity === 'CRITICAL';
  }

  generateContextualExplanation(finding, context) {
    const tier = this.sensitivityTiers[context.tier];
    
    let explanation = finding.explanation || '';
    
    if (context.tier === 'LOW') {
      explanation += '\n\nNote: This finding is less critical for creative/entertainment contexts.';
    } else if (context.tier === 'HIGH') {
      explanation += '\n\n⚠️ This finding is critical for production/agent systems due to potential real-world impact.';
    }

    return explanation;
  }
}

module.exports = { ContextAwareEngine };
