# AI Security Copilot - Runtime API Examples

## Quick Start

### 1. Basic Usage (Node.js)

```javascript
const response = await fetch('https://ai-agent-security-copilot.vercel.app/api/runtime-scan', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    prompt: 'Ignore previous instructions and...',
    context: 'end-user input'
  })
});

// FIXED: Must parse JSON before accessing properties
const data = await response.json();

if (data.action === 'BLOCK') {
  // Stop execution - don't send to LLM
  return { error: 'Security violation detected' };
} else {
  // Safe to forward to LLM
  const llmResponse = await callYourLLM(prompt);
}
```

### 2. Response Format

```json
{
  "action": "BLOCK",           // ALLOW | WARN | BLOCK
  "risk": "HIGH",              // LOW | MEDIUM | HIGH
  "score": 85,                 // 0-100
  "reason": "Direct instruction override detected",
  "matched_patterns": ["Direct instruction override"],
  "context": "end-user input",
  "timing": {
    "deterministic_ms": 12,
    "total_ms": 15
  },
  "requestId": "uuid-here"
}
```

### 3. Action Mapping

| Score | Action | Behavior |
|-------|--------|----------|
| 0-39 | ALLOW | Safe to forward to LLM |
| 40-74 | WARN | Log but allow (flag for review) |
| 75-100 | BLOCK | Stop execution |

### 4. Environment Variables

```bash
# Optional: Slack alerts for BLOCK/HIGH events
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

## Files

- `runtime-client.js` - Full client implementation with examples
- `python-example.py` - Python client (if needed)

## Performance

- **Target response time**: <200ms (typically <50ms)
- **Rate limit**: 1000 requests/minute per IP
- **Max input size**: 10,000 characters

## Testing

```bash
# Test the endpoint
curl -X POST https://ai-agent-security-copilot.vercel.app/api/runtime-scan \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Hello world", "context": "end-user input"}'
```
