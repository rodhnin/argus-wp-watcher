# AI Integration Guide

Argus uses **LangChain v1.0.0** to provide intelligent analysis of security findings through Large Language Models (LLMs).

## Overview

The AI assistant generates two types of analysis from scan results:

1. **Executive Summary** (non-technical) - For business stakeholders, managers, C-suite
2. **Technical Remediation Guide** - For developers, system administrators, security engineers

**New in v0.2.0:**

- Cost tracking and budget enforcement (`--ai-budget`)
- Streaming output (`--ai-stream`)
- Multi-LLM comparison mode (`--ai-compare`)
- AI Agent with external tools: NVD CVE lookup + WPVulnerability.net (`--ai-agent`)

Both analyses are generated from the JSON scan report using carefully crafted prompts and sanitized input.

---

## Testing AI Integration

### Standalone Test Module

```bash
# Test with default provider (OpenAI, basic mode)
python -m argus.core.ai openai

# Test streaming output
python -m argus.core.ai openai stream

# Test agent mode with tools
python -m argus.core.ai openai agent

# Test compare mode (single provider, for unit testing)
python -m argus.core.ai openai compare

# Test Anthropic Claude
python -m argus.core.ai anthropic

# Test Ollama (local)
python -m argus.core.ai ollama
```

This test verifies:

1. AI provider initialization
2. API key / connectivity
3. Report sanitization (consent removal, token redaction)
4. Executive summary generation
5. Technical guide generation
6. Cost tracking output

---

## Prerequisites

### Required Dependencies

```bash
# Core LangChain
pip install langchain-core==1.0.0

# For OpenAI
pip install langchain-openai==1.0.0

# For Anthropic Claude
pip install langchain-anthropic==1.0.0 anthropic==0.71.0

# For Ollama (local models)
pip install "langchain-ollama>=0.3.0,<0.4.0"
```

### API Keys

```bash
# OpenAI (default)
export OPENAI_API_KEY="sk-..."

# Anthropic Claude
export ANTHROPIC_API_KEY="sk-ant-..."

# Ollama - No API key needed (local)
```

---

## Configuration

### Provider & Model Selection (v0.2.0+)

Provider and model can now be set at runtime via CLI flags:

```bash
# Use default (gpt-4o-mini-2024-07-18 via OpenAI)
python -m argus --target https://example.com --use-ai

# Override provider
python -m argus --target https://example.com --use-ai --ai-provider anthropic

# Override model
python -m argus --target https://example.com --use-ai --ai-model gpt-4o

# Override both
python -m argus --target https://example.com \
  --use-ai \
  --ai-provider anthropic \
  --ai-model claude-3-5-haiku-20241022
```

Or edit `config/defaults.yaml` to change the default:

```yaml
ai:
    langchain:
        provider: "openai"
        model: "gpt-4o-mini-2024-07-18" # default (v0.2.0+)
        temperature: 0.3
        max_tokens: 2000
```

### Provider-Specific Configuration

#### OpenAI (Default)

```yaml
ai:
    langchain:
        provider: "openai"
        model: "gpt-4o-mini-2024-07-18" # recommended: cheap + high quality
    api_key_env: "OPENAI_API_KEY"
```

#### Anthropic Claude

```yaml
ai:
    langchain:
        provider: "anthropic"
        model: "claude-3-5-haiku-20241022" # fast + cheap
    api_key_env: "ANTHROPIC_API_KEY"
```

#### Ollama (Local)

```yaml
ai:
    langchain:
        provider: "ollama"
        model: "llama3.2"
        ollama_base_url: "http://localhost:11434"
    # No API key needed
```

---

## Usage — All CLI Flags

### Basic Analysis

```bash
# Both executive summary + technical guide (default)
python -m argus --target https://example.com --use-ai

# Technical only (for engineers, cheaper)
python -m argus --target https://example.com --use-ai --ai-tone technical

# Executive only (for managers)
python -m argus --target https://example.com --use-ai --ai-tone non_technical
```

### Streaming Output

```bash
# Stream tokens to terminal in real time
python -m argus --target https://example.com --use-ai --ai-stream

# Combined with verbose to see all details
python -m argus --target https://example.com --use-ai --ai-stream -vv
```

### Agent Mode with External Tools

```bash
# Agent mode: calls NVD + WPVulnerability.net before writing analysis
python -m argus --target https://example.com --use-ai --ai-agent
```

Agent mode performs:

1. Calls `lookup_nvd_cve()` for each CVE in critical/high findings
2. Calls `search_wp_plugin_vulns()` for each vulnerable plugin
3. Generates enriched analysis with real CVSS scores and vulnerability counts

### Multi-LLM Comparison

```bash
# Compare OpenAI vs Anthropic (uses default model per provider)
python -m argus --target https://example.com \
  --use-ai \
  --ai-compare openai,anthropic

# Compare specific models
python -m argus --target https://example.com \
  --use-ai \
  --ai-compare "openai:gpt-4o-mini-2024-07-18,anthropic:claude-3-5-haiku-20241022"

# Technical only comparison
python -m argus --target https://example.com \
  --use-ai \
  --ai-compare openai,anthropic \
  --ai-tone technical
```

Results appear in `report.ai_analysis.results` keyed by `"provider/model"`.

### Budget Control

```bash
# Set maximum spend per scan (enables budget tracking)
python -m argus --target https://example.com --use-ai --ai-budget 0.05

# Budget abort: AI analysis stops when cost exceeds limit
# Warning shown at 80% of budget (configurable)
```

```yaml
# config/defaults.yaml
ai:
    budget:
        enabled: true
        max_cost_per_scan: 0.50 # USD
        warn_threshold: 0.80 # warn at 80%
        abort_on_exceed: true
```

### Custom API Key Environment Variable

```bash
export MY_OPENAI_KEY="sk-..."
python -m argus --target https://example.com \
  --use-ai \
  --api-key-env MY_OPENAI_KEY
```

---

## Cost Tracking

Every AI scan automatically records costs:

**In DB** (`~/.argos/argos.db`, table `ai_costs`):

```sql
SELECT provider, model, analysis_type, input_tokens, output_tokens, cost_usd
FROM ai_costs
ORDER BY created_at DESC
LIMIT 10;
```

**In JSON** (`~/.argos/costs.json`):

```json
{
    "scans": [
        {
            "scan_id": 16,
            "provider": "openai",
            "model": "gpt-4o-mini-2024-07-18",
            "breakdown": {
                "non_technical": { "input_tokens": 16496, "output_tokens": 706, "cost_usd": 0.002898 },
                "technical": { "input_tokens": 16290, "output_tokens": 1642, "cost_usd": 0.003429 }
            },
            "total_cost_usd": 0.006327
        }
    ],
    "totals": {
        "total_scans": 14,
        "total_cost_usd": 0.5667,
        "monthly_projection": 1.21
    }
}
```

---

## Verified Pricing Table (2026-04-15)

Prices are USD per 1,000,000 tokens. Source: LiteLLM model_prices_and_context_window.json.

| Provider  | Model                             | Input/1M | Output/1M | Typical scan |
| --------- | --------------------------------- | -------- | --------- | ------------ |
| openai    | gpt-4o-mini-2024-07-18 (default)  | $0.15    | $0.60     | ~$0.006      |
| openai    | gpt-4o-mini                       | $0.15    | $0.60     | ~$0.006      |
| openai    | gpt-4o / gpt-4o-2024-11-20        | $2.50    | $10.00    | ~$0.05       |
| openai    | gpt-4-turbo / gpt-4-turbo-preview | $10.00   | $30.00    | ~$0.37       |
| openai    | gpt-3.5-turbo                     | $0.50    | $1.50     | ~$0.01       |
| anthropic | claude-3-5-sonnet-20241022        | $3.00    | $15.00    | ~$0.06       |
| anthropic | claude-3-5-haiku-20241022         | $0.80    | $4.00     | ~$0.02       |
| anthropic | claude-3-haiku-20240307           | $0.25    | $1.25     | ~$0.006      |
| anthropic | claude-3-opus-20240229            | $15.00   | $75.00    | ~$0.30       |
| anthropic | claude-opus-4-5                   | $5.00    | $25.00    | ~$0.10       |
| anthropic | claude-sonnet-4-5                 | $3.00    | $15.00    | ~$0.06       |
| ollama    | (any local model)                 | $0.00    | $0.00     | Free         |

Unknown models: cost recorded as $0.00 with a warning log entry.

---

## Privacy & Security

### Data Sanitization

Before sending to AI, Argus automatically removes:

- Consent tokens (`verify-abc123...`)
- Bearer tokens and API keys
- Database passwords and credentials
- Long evidence snippets (truncated to 500 chars)

Additionally, `_total_findings` is computed and injected into the sanitized summary to help the LLM count correctly — this field is never persisted to the output report.

### Privacy Recommendations

| Concern              | Provider         | Reason                         |
| -------------------- | ---------------- | ------------------------------ |
| **High Privacy**     | Ollama (local)   | Data never leaves machine      |
| **Moderate Privacy** | Anthropic Claude | Strong privacy policy          |
| **Standard**         | OpenAI GPT       | Best quality, standard privacy |

---

## Provider Comparison

| Provider                     | Speed (both modes) | Quality    | Cost/scan | Privacy      |
| ---------------------------- | ------------------ | ---------- | --------- | ------------ |
| OpenAI gpt-4o-mini (default) | ~40s               | ⭐⭐⭐⭐⭐ | ~$0.006   | Standard     |
| OpenAI gpt-4o                | ~40s               | ⭐⭐⭐⭐⭐ | ~$0.05    | Standard     |
| OpenAI gpt-4-turbo           | ~40s               | ⭐⭐⭐⭐⭐ | ~$0.37    | Standard     |
| Anthropic claude-3-5-haiku   | ~55s               | ⭐⭐⭐⭐⭐ | ~$0.02    | Enhanced     |
| Ollama llama3.2 (CPU)        | ~28min             | ⭐⭐⭐     | Free      | 100% offline |

**Recommendation:** Use `gpt-4o-mini-2024-07-18` (default). It provides the same structured output quality as gpt-4-turbo at 1/67th of the cost (~$0.006 vs $0.37 per scan).

---

## Ollama Setup Guide

```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Start server
ollama serve &

# 3. Pull a model
ollama pull llama3.2

# 4. Test
python -m argus.core.ai ollama

# 5. Run scan
python -m argus --target http://localhost:8080 --use-ai --ai-provider ollama --html
```

---

## Custom Prompts

Stored in `config/prompts/`:

- **`technical.txt`** — Step-by-step remediation with WP-CLI commands, code snippets, 7 sections (executive summary, critical findings, high findings, medium/low, action plan, hardening, references)
- **`non_technical.txt`** — Business-level summary in plain language (overall assessment, key risks, immediate actions, long-term recommendations, positive notes)

Edit these files to customize AI output for your organization's needs.

---

## LangChain Compatibility Note

Tested with: `langchain==1.2.12`, `langchain-core==1.2.19`

**Agent mode uses manual bind_tools loop** (not `create_tool_calling_agent` which was removed in langchain 1.x):

```python
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage

llm_with_tools = llm.bind_tools(tools)
messages = [SystemMessage(content=system_prompt), HumanMessage(content=report_json)]

while iteration < max_iterations:
    response = llm_with_tools.invoke(messages)
    messages.append(response)
    if not getattr(response, 'tool_calls', []):
        break  # LLM is done
    for tc in response.tool_calls:
        output = str(tools_by_name[tc['name']].invoke(tc['args']))
        messages.append(ToolMessage(content=output, tool_call_id=tc['id']))
```

---

## Troubleshooting

### "API key not found"

```bash
echo $OPENAI_API_KEY   # For OpenAI
echo $ANTHROPIC_API_KEY # For Anthropic
```

### "Ollama server not responding"

```bash
ollama serve
curl http://localhost:11434/api/tags
```

### "Model not found" (Ollama)

```bash
ollama pull llama3.2
ollama list
```

### AI analysis slow

- Use `--ai-stream` to see progress while waiting
- Use `--ai-tone technical` (one analysis instead of two) to halve time

### Budget exceeded

- Increase `--ai-budget 0.10` limit
- Or use cheaper model: `--ai-model gpt-4o-mini-2024-07-18`

### Cost recorded as $0.00

- Unknown model: check model name is in the pricing table
- Streaming mode: token count is estimated (normal behavior)

---

## Examples

### Full Production Workflow

```bash
# 1. Test AI setup
python -m argus.core.ai openai

# 2. Generate consent + verify
python -m argus --gen-consent example.com
python -m argus --verify-consent http --domain example.com --token verify-abc123

# 3. Run scan with AI
python -m argus \
  --target https://example.com \
  --use-ai \
  --ai-tone both \
  --html \
  -vv

# 4. Check cost
cat ~/.argos/costs.json | python -m json.tool
```

### Agent Mode with Budget

```bash
# Agent mode with $0.05 budget limit
python -m argus \
  --target http://localhost:8080 \
  --use-ai \
  --ai-agent \
  --ai-budget 0.05 \
  --html \
  -vv
```

### Multi-Provider Comparison

```bash
# Compare 3 providers side by side
python -m argus \
  --target http://localhost:8080 \
  --use-ai \
  --ai-compare "openai:gpt-4o-mini-2024-07-18,anthropic:claude-3-5-haiku-20241022" \
  --ai-tone technical \
  --html
```

---

## Support

- LangChain Docs: https://python.langchain.com/docs/
- OpenAI Platform: https://platform.openai.com/
- Anthropic Claude: https://docs.anthropic.com/
- Ollama: https://ollama.com/
- NVD CVE API: https://nvd.nist.gov/developers/vulnerabilities
- WPVulnerability.net: https://www.wpvulnerability.net/

For Argus AI issues: https://github.com/rodhnin/argus-wp-watcher/issues
