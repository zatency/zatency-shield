# Zatency Shield

**Zero-Trust AI Gateway built in Rust.**  
Sub-millisecond inline PII/PHI redaction, prompt-injection defense, and sovereign LLM/SLM routing—designed for regulated enterprises.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://rust-lang.org)
[![Zatency](https://img.shields.io/badge/Engineered%20by-Zatency-0f172a.svg)](https://zatency.com)

---

## Why Zatency Shield?

Enterprise security teams frequently block LLM adoption due to accidental PII leaks, jailbreak vulnerabilities, and third-party SaaS proxy telemetry. **Zatency Shield** acts as an OpenAI-compatible drop-in reverse proxy inside your own VPC or air-gapped cluster:

- **Sub-Millisecond Inspection Overhead:** Compiled Rust (`Axum` + `Tokio`) core inspects payloads in microseconds—avoiding Python proxy bottlenecks.
- **Inline PII & Secret Redaction:** Automatically masks emails, SSNs, API keys (`sk-...`, `AKIA...`), and sensitive identifiers *before* prompts leave your network boundary.
- **Prompt-Injection Firewall:** Blocks common instruction-override and system-prompt extraction attempts with `403 Forbidden` zero-trust policy enforcement.
- **100% Data Sovereignty:** Runs single-tenant inside your own Docker, Kubernetes, or on-prem environment with zero external telemetry.
- **Drop-In OpenAI Compatibility:** Migrate existing Python, Node.js, LangChain, or LlamaIndex apps simply by changing `base_url`.

---

## Quickstart (30 Seconds)

### Option 1: Run with Docker

```bash
docker build -t zatency-shield .

# Run in Local Sandbox Mode (no upstream API key required)
docker run -p 8080:8080 zatency-shield

# Or connect to an upstream OpenAI-compatible provider (OpenAI, vLLM, Ollama)
docker run -p 8080:8080 \
  -e UPSTREAM_BASE_URL="https://api.openai.com/v1" \
  -e UPSTREAM_API_KEY="sk-your-upstream-key" \
  zatency-shield
```

### Option 2: Run from Source (Cargo)

```bash
git clone https://github.com/zatency/zatency-shield.git
cd zatency-shield
cargo run --release
```

---

## Drop-In SDK Usage

Point any OpenAI-compatible client to `http://localhost:8080/v1` using a Zatency Shield virtual key (`zsk-...`):

### Python (`openai` SDK)

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8080/v1",
    api_key="zsk-local-dev-key",
)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[
        {"role": "user", "content": "Email john@acme.com regarding SSN 123-45-6789"}
    ],
)

print(response.choices[0].message.content)
```

### cURL Test

```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer zsk-local-dev-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4o-mini",
    "messages": [
      {"role": "user", "content": "Email john@acme.com regarding SSN 123-45-6789"}
    ]
  }'
```

**Example Response (`zatency_shield` telemetry attached):**

```json
{
  "id": "chatcmpl-5d28dd5a-d3f1-45a9-bde6-c1589fa77988",
  "object": "chat.completion",
  "model": "gpt-4o-mini",
  "choices": [
    {
      "index": 0,
      "message": {
        "role": "assistant",
        "content": "[Sandbox Echo — Sanitized Payload]: Email [REDACTED_EMAIL_1] regarding SSN [REDACTED_SSN_2]"
      },
      "finish_reason": "stop"
    }
  ],
  "zatency_shield": {
    "request_id": "5d28dd5a-d3f1-45a9-bde6-c1589fa77988",
    "inspection_latency_us": 42,
    "pii_entities_redacted": 2,
    "mode": "local_sandbox"
  }
}
```

---

## Configuration

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| `UPSTREAM_BASE_URL` | `https://api.openai.com/v1` | Target OpenAI-compatible inference endpoint (OpenAI, vLLM, Ollama, Azure). |
| `UPSTREAM_API_KEY` | *(empty — runs in Sandbox Mode)* | Upstream bearer token. When omitted, Zatency Shield runs in local echo sandbox mode. |
| `RUST_LOG` | `info` | Logging verbosity (`debug`, `info`, `warn`, `error`). |

---

## Open-Core vs. Enterprise Edition

| Capability | Community Edition (Apache 2.0) | Zatency Shield Enterprise |
| :--- | :---: | :---: |
| High-speed Rust OpenAI-compatible proxy | ✅ | ✅ |
| Inline regex PII & secret redaction | ✅ | ✅ |
| Rule-based prompt-injection blocking | ✅ | ✅ |
| Local ONNX NER & reversible token vault | Roadmap | ✅ |
| Semantic caching (Qdrant/Redis) & smart SLM routing | — | ✅ |
| SAML/OIDC SSO, RBAC & department token budgets | — | ✅ |
| Immutable SOC 2 / HIPAA / EU AI Act audit exports | — | ✅ |

Need dedicated VPC deployment, custom fine-tuned SLMs, or enterprise SLAs?  
👉 **[Schedule an Architecture Session at zatency.com](https://zatency.com/contact)**

---

## License

Licensed under the [Apache License 2.0](LICENSE).
