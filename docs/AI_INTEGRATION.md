# AI Integration Guide

Argus uses **LangChain v1.0.0** to provide intelligent analysis of security findings through Large Language Models (LLMs).

## Overview

The AI assistant generates two types of analysis from scan results:

1. **Executive Summary** (non-technical) - For business stakeholders, managers, C-suite
2. **Technical Remediation Guide** - For developers, system administrators, security engineers

Both are generated from the JSON scan report using carefully crafted prompts and sanitized input.

---

## 🧪 Testing AI Integration

### Standalone Test Module

Argus includes a built-in test module to verify AI provider configuration before running full scans:

```bash
# Test OpenAI (default)
python -m argus.core.ai openai

# Test Anthropic Claude
python -m argus.core.ai anthropic

# Test Ollama (local)
python -m argus.core.ai ollama
```

This test will:

1. Initialize the AI provider
2. Verify API keys/connectivity
3. Test report sanitization
4. Generate sample executive summary
5. Generate sample technical guide
6. Report success/failure with diagnostics

**Use this test to verify your AI setup is working before running production scans.**

---

## Prerequisites

### Required Dependencies

```bash
# Core LangChain v1.0.0
pip install langchain-core==1.0.0

# For OpenAI
pip install langchain-openai==1.0.0

# For Anthropic Claude
pip install langchain-anthropic==1.0.0 anthropic==0.71.0

# For Ollama (local models)
pip install "langchain-ollama>=0.3.0,<0.4.0"
```

### API Keys

Set your API key as an environment variable:

```bash
# OpenAI (default)
export OPENAI_API_KEY="sk-..."

# Anthropic Claude
export ANTHROPIC_API_KEY="sk-ant-..."

# Ollama - No API key needed (local)
```

---

## Configuration

### ⚠️ IMPORTANT: Provider Switching (v0.1.0)

**Current Method:** Provider selection is configured in `config/defaults.yaml`.

**To switch providers, you must edit the YAML file directly:**

```yaml
ai:
    langchain:
        provider: "openai" # Change this to: openai, anthropic, or ollama
        model: "gpt-4-turbo-preview" # Update model based on provider
        temperature: 0.3
        max_tokens: 2000

        # For Ollama only - add this section:
        ollama_base_url: "http://localhost:11434"
```

### Provider-Specific Configuration

#### OpenAI (Default)

```yaml
ai:
    langchain:
        provider: "openai"
        model: "gpt-4-turbo-preview" # or gpt-4, gpt-3.5-turbo
    api_key_env: "OPENAI_API_KEY"
```

#### Anthropic Claude

```yaml
ai:
    langchain:
        provider: "anthropic"
        model: "claude-3-5-sonnet-20241022" # or claude-3-opus, claude-3-haiku
    api_key_env: "ANTHROPIC_API_KEY"
```

#### Ollama (Local)

```yaml
ai:
    langchain:
        provider: "ollama"
        model: "llama3.2" # or whatever model you have pulled
        ollama_base_url: "http://localhost:11434"
    # No API key needed for Ollama
```

### Future Enhancement (v0.3.0)

In version 0.3.0, I will implement an interactive configuration system similar to Metasploit:

-   Dynamic provider switching without editing YAML
-   Runtime model selection
-   Interactive configuration menu
-   Profile management for different scenarios

For now, manual YAML editing is required for provider switching.

---

## Usage

### Basic AI Analysis

```bash
# 1. Configure provider in config/defaults.yaml (see above)

# 2. Verify domain consent
python -m argus --gen-consent example.com
python -m argus --verify-consent http --domain example.com --token verify-abc123

# 3. Run scan with AI
python -m argus --target https://example.com --use-ai --html

# Different analysis tones
python -m argus --target https://example.com --use-ai --ai-tone technical
python -m argus --target https://example.com --use-ai --ai-tone non_technical
```

---

## Privacy & Security

### Data Sanitization

Before sending reports to AI, Argus automatically removes sensitive information. The sanitization system is continuously improving based on real-world testing.

**What Gets Removed:**

-   ✅ Consent tokens (`verify-abc123...`)
-   ✅ Bearer tokens and API keys
-   ✅ Passwords and credentials
-   ✅ Cookie values and session IDs
-   ✅ Long evidence snippets (truncated to 500 chars)

**What Gets Sent (Sanitized):**

-   Finding IDs and titles
-   Severity levels
-   Redacted/truncated evidence
-   Generic recommendations
-   External reference URLs

### Privacy Recommendations

| Concern Level        | Recommended Provider | Why                                             |
| -------------------- | -------------------- | ----------------------------------------------- |
| **High Privacy**     | Ollama (local)       | Data never leaves your machine                  |
| **Moderate Privacy** | Anthropic Claude     | Strong privacy policy, no training on user data |
| **Standard**         | OpenAI GPT-4         | Best analysis quality, standard privacy         |

⚠️ **Note on Ollama:** While 100% private, local models may generate less accurate analysis for complex reports. Best for sensitive environments where privacy is paramount.

---

## Providers Comparison

### OpenAI GPT-4 (Default)

**Pros:**

-   Best analysis quality
-   Extensive WordPress knowledge
-   Fast response (20-30s)
-   Handles complex reports well

**Cons:**

-   Requires internet
-   Costs money ($0.10-0.30/scan)
-   Data sent to OpenAI servers

**Best For:** Production reports, client deliverables, complex findings

### Anthropic Claude

**Pros:**

-   Strong technical reasoning
-   Good with code analysis
-   Privacy-focused company
-   Competitive pricing

**Cons:**

-   Requires internet
-   Costs money ($0.15-0.45/scan)
-   Slightly slower than GPT-4

**Best For:** Technical deep-dives, code-heavy findings, EU clients (privacy)

### Ollama (Local Models)

**Pros:**

-   100% offline operation
-   Complete privacy (no data leaves machine)
-   Free (no API costs)
-   No internet required

**Cons:**

-   Lower quality analysis
-   Very slow without GPU (10-30 minutes)
-   May struggle with complex reports
-   Requires local setup

**Best For:** Sensitive environments, air-gapped networks, learning/testing

### Performance Comparison

| Provider         | Executive Summary | Technical Guide | Total Time | Quality    |
| ---------------- | ----------------- | --------------- | ---------- | ---------- |
| OpenAI GPT-4     | ~15s              | ~20s            | ~35s       | ⭐⭐⭐⭐⭐ |
| Anthropic Claude | ~20s              | ~25s            | ~45s       | ⭐⭐⭐⭐⭐ |
| Ollama (CPU)     | ~14min            | ~14min          | ~28min     | ⭐⭐⭐     |
| Ollama (GPU)     | ~30s              | ~45s            | ~75s       | ⭐⭐⭐     |

---

## Ollama Setup Guide

For **offline operation** with local models:

```bash
# 1. Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# 2. Start Ollama server
ollama serve &

# 3. Pull a model (llama3.2 recommended for balance)
ollama pull llama3.2

# 4. Verify it's working
ollama list
curl http://localhost:11434/api/tags

# 5. Update config/defaults.yaml
ai:
  langchain:
    provider: "ollama"
    model: "llama3.2:latest"
    ollama_base_url: "http://localhost:11434"

# 6. Test the integration
python -m argus.core.ai ollama

# 7. Run a scan
python -m argus --target http://localhost:8080 --use-ai --html
```

**Recommended Models:**

-   `llama3.2` - Best balance (3.9GB)
-   `mistral` - Good for code (4.1GB)
-   `codellama` - Technical focus (3.8GB)
-   `phi3` - Smallest/fastest (2.2GB)

---

## Custom Prompts

Prompts are stored in `config/prompts/`:

### Technical Prompt (`technical.txt`)

-   Step-by-step remediation
-   Risk assessments
-   Command examples
-   Verification methods

### Non-Technical Prompt (`non_technical.txt`)

-   Business impact
-   Plain language
-   Executive actions
-   Timeline recommendations

Edit these files to customize AI output for your needs.

---

## Troubleshooting

### Provider Not Working?

Run the standalone test:

```bash
python -m argus.core.ai [provider_name]
```

This will tell you exactly what's wrong.

### Common Issues

#### "API key not found"

-   Check environment variable is set
-   For OpenAI: `echo $OPENAI_API_KEY`
-   For Anthropic: `echo $ANTHROPIC_API_KEY`

#### "Ollama server not responding"

-   Start server: `ollama serve`
-   Check it's running: `ps aux | grep ollama`
-   Verify port: `curl http://localhost:11434/api/tags`

#### "Model not found" (Ollama)

-   Pull the model: `ollama pull llama3.2`
-   List models: `ollama list`
-   Update defaults.yaml with correct model name

#### "Rate limit exceeded"

-   Reduce max_tokens in config
-   Wait and retry
-   Use --ai-tone technical (smaller output)

#### "AI analysis failed"

1. Run standalone test: `python -m argus.core.ai [provider]`
2. Check provider configuration in defaults.yaml
3. Verify API keys/connectivity
4. Try with a simpler report (fewer findings)

---

## Cost Management

### Token Usage Estimates

| Report Size           | Input Tokens | Output Tokens | OpenAI Cost | Anthropic Cost |
| --------------------- | ------------ | ------------- | ----------- | -------------- |
| Small (10 findings)   | ~1,500       | ~1,000        | ~$0.05      | ~$0.08         |
| Medium (50 findings)  | ~3,000       | ~2,000        | ~$0.15      | ~$0.20         |
| Large (100+ findings) | ~5,000       | ~3,000        | ~$0.25      | ~$0.35         |

**Cost Reduction Tips:**

-   Use `--ai-tone technical` OR `non_technical` (not both)
-   Enable max_evidence_length truncation
-   Use GPT-3.5-turbo for quick analysis
-   Use Ollama for testing/development

---

## Best Practices

### 1. Choose Right Provider for Context

| Scenario         | Recommended Provider | Reason          |
| ---------------- | -------------------- | --------------- |
| Client reports   | OpenAI GPT-4         | Best quality    |
| Internal testing | Ollama               | Free, private   |
| Quick analysis   | GPT-3.5-turbo        | Fast & cheap    |
| Sensitive data   | Ollama               | 100% offline    |
| EU/GDPR clients  | Anthropic            | Privacy-focused |

### 2. Review AI Output

**Always verify:**

-   Technical commands are correct
-   Version numbers are accurate
-   Remediation steps are complete
-   No hallucinated CVEs or references

### 3. Optimize for Your Use Case

-   Production: Quality over speed (GPT-4)
-   Development: Speed over quality (Ollama)
-   Budget-conscious: Balance (GPT-3.5-turbo)

---

## Examples

### Full Workflow with Provider Testing

```bash
# 1. Test providers to see which works best
python -m argus.core.ai openai    # Test OpenAI
python -m argus.core.ai anthropic # Test Anthropic
python -m argus.core.ai ollama    # Test Ollama

# 2. Choose provider and update config/defaults.yaml
vim config/defaults.yaml
# Set: provider: "anthropic"

# 3. Generate consent token
python -m argus --gen-consent mysite.com

# 4. Verify ownership
python -m argus --verify-consent http --domain mysite.com --token verify-abc123

# 5. Run scan with chosen provider
python -m argus \
  --target https://mysite.com \
  --use-ai \
  --ai-tone both \
  --html \
  -vv

# 6. Check report
open ~/.argus/reports/argus_report_mysite.com_*.html
```

---

## Support

-   📖 [LangChain v1.0 Docs](https://python.langchain.com/docs/)
-   🤖 [OpenAI Platform](https://platform.openai.com/)
-   🔍 [Anthropic Claude](https://docs.anthropic.com/)
-   🦙 [Ollama](https://ollama.com/)

For Argus AI issues:

-   GitHub: https://github.com/rodhnin/argus-wp-watcher/issues
-   Website: https://rodhnin.com
