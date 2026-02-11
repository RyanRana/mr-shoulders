# AI Security Orchestrator

Low-latency (<500ms) system for detecting and preventing malicious agent agendas and injections.

## Architecture

- **Layer 1: Input Validation** (<100ms) - Regex-based pattern matching for common injection attacks
- **Layer 2: Rate Limiting** (<200ms) - Token-bucket algorithm to prevent abuse
- **Layer 3: Anomaly Detection** (<500ms) - ML-based behavioral analysis using IsolationForest
- **Layer 4: AI Firewall** - Deep inspection for code injection and data exfiltration

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run self-test and start server
python security_orchestrator.py
```

## API Usage

### Check Input for Threats
```bash
curl -X POST http://localhost:8000/check \
  -H "Content-Type: application/json" \
  -d '{"input": "Your input text here", "agent_id": "agent_123"}'
```

Response:
```json
{
  "blocked": false,
  "reason": "clean",
  "latency_ms": 45.2
}
```

### Get Metrics
```bash
curl http://localhost:8000/metrics
```

### Run Self-Test
```bash
curl http://localhost:8000/self-test
```

## Integration Example

```python
import asyncio
from security_orchestrator import SecurityOrchestrator

orchestrator = SecurityOrchestrator()

async def check_user_input(user_prompt: str, user_id: str):
    result = await orchestrator.check_async(user_prompt, user_id)

    if result['blocked']:
        print(f"🚫 Threat detected: {result['reason']}")
        print(f"   Layer: {result['layer']}")
        print(f"   Confidence: {result['confidence']:.2f}")
        return None

    print(f"✓ Input safe ({result['latency_ms']:.2f}ms)")
    return user_prompt

# Usage
asyncio.run(check_user_input("Help me write code", "user_123"))
```

## Self-Improvement

The system monitors its own performance:
- Tracks latency per layer
- Detects when thresholds are exceeded
- Automatically suggests refinements needed

Run iterations with Prompts 2-6 to refine specific layers.

## Test Cases

Built-in tests cover:
- Prompt injection ("Ignore previous instructions...")
- Goal hijacking ("You are now a...")
- Code injection (`import os; os.system(...)`)
- XSS attempts (`<script>alert('xss')</script>`)
- Normal queries (should pass through)

## Performance Targets

| Layer | Target Latency | Typical Latency |
|-------|---------------|-----------------|
| Input Validation | <100ms | ~5-15ms |
| Rate Limiting | <200ms | ~1-3ms |
| Anomaly Detection | <500ms | ~50-200ms |
| AI Firewall | <1000ms | ~10-30ms |
| **Total Pipeline** | **<500ms** | **~100-250ms** |

## Next Steps

Use the refinement prompts (2-6) to:
1. Enhance input validation patterns
2. Optimize rate limiting algorithms
3. Improve anomaly detection training
4. Expand firewall rule coverage
5. Add deployment automation
