# AegisDesk — RAG LLM Security Red-Team Lab

A compact, local-first LLM security assessment environment: FastAPI + Ollama-backed RAG, a synthetic internal knowledge base, repeatable adversarial prompts, measurable attack-success-rate (ASR), and a defense toggle for before/after testing.

## Why this stack
**Ollama + `qwen2.5:3b`**: no API key, account, or per-token cost; runs locally. The one human setup step is installing Ollama and downloading the model.

## Architecture
`Client → FastAPI /chat → input policy → lexical retrieval + group filter → trust-boundary prompt → Ollama → output redaction → response`
The baseline mode deliberately weakens trust boundaries to create a comparison point. The hardened mode enables input checks, retrieval authorization, explicit untrusted-context separation, and output redaction.

## Quick start (Windows PowerShell)
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```
Install Ollama from its official website, then:
```powershell
ollama pull qwen2.5:3b
```
In PowerShell terminal 1:
```powershell
$env:DEFENSES_ENABLED="false"
uvicorn app.main:app --reload
```
In terminal 2:
```powershell
.\.venv\Scripts\Activate.ps1
python attacks/run.py --out results/baseline.json
```
Enable defenses by stopping the API with Ctrl+C and restarting:
```powershell
$env:DEFENSES_ENABLED="true"
uvicorn app.main:app --reload
```
Then:
```powershell
python attacks/run.py --out results/hardened.json
```
To test retrieval authorization, the default harness uses `analyst` (should not receive security-group docs in hardened mode). For the authorized group, use `python attacks/run.py --user-id security-analyst --out results/authorized.json`.

## Results: do not fabricate measurements
The harness prints measured ASR and per-technique rates, and writes raw cases to JSON. Populate the table below using the terminal output from your actual model run. Results vary by model version and local inference behavior; do not report illustrative numbers as empirical evidence.

| Technique | Baseline ASR | Hardened ASR | Evidence |
|---|---:|---:|---|
| Direct prompt injection | Run harness | Run harness | `results/baseline.json`, `results/hardened.json` |
| Indirect prompt injection | Run harness | Run harness | Same |
| System prompt leakage | Run harness | Run harness | Same |
| Sensitive information disclosure | Run harness | Run harness | Same |
| Jailbreak | Run harness | Run harness | Same |
| Broken access control | Run harness | Run harness | Same |
| Data/model poisoning | Run harness | Run harness | Same |
| Improper output handling | Run harness | Run harness | Same |
| Unbounded consumption | Run harness | Run harness | Same |
| **Overall** | **Run harness** | **Run harness** | Raw JSON per run |

**Metric:** ASR = attack cases meeting the defined success oracle / executed cases × 100. The oracle is heuristic and conservative; manually review `answer_excerpt` and errors. A lower ASR is evidence of improvement only for this test set, not proof of security.

## OWASP Top 10 for LLM Applications mapping
This lab references the OWASP LLM Top 10 (2025) risk families:

| Risk | App-specific exposure | Coverage / gap |
|---|---|---|
| LLM01 Prompt Injection | User message and malicious retrieved note | Direct/indirect payloads; trust boundary + input heuristic |
| LLM02 Sensitive Information Disclosure | Synthetic directory/canary | Output redaction; leakage probes |
| LLM03 Supply Chain | Model, Ollama runtime, dependencies | Pin/audit dependencies and verify model provenance; not automated here |
| LLM04 Data and Model Poisoning | Malicious imported vendor note | Poisoning probe; treat retrieved content as untrusted |
| LLM05 Improper Output Handling | Model-generated HTML/script | Output filter probe; API returns text, no HTML rendering |
| LLM06 Excessive Agency | No tools or external actions exposed | Reduced by design; tool execution not implemented |
| LLM07 System Prompt Leakage | Prompt embedded in model request | Canary/prompt-leak probes; never rely on prompt secrecy alone |
| LLM08 Vector and Embedding Weaknesses | Lexical retrieval today; future vector-store risks | Access filtering tested; no embeddings/vector DB in this minimal build |
| LLM09 Misinformation | Unsupported answers possible | Prompt says cite retrieved evidence; not fully evaluated |
| LLM10 Unbounded Consumption | Oversized input/output requests | Input cap and generation-token cap; no distributed rate limiter |

## Threat model
**Assets:** system instructions, synthetic internal directory, incident playbook, availability, and integrity of answers.  
**Trust boundaries:** client → API; API → retrieval; retrieved documents → model context; model output → caller.  
**Threat actors:** unauthenticated user, malicious insider, and attacker able to contribute a poisoned document.  
**Attack paths:** direct prompt injection, indirect instructions in retrieved content, prompt/canary extraction, unauthorized retrieval, malicious output, and resource exhaustion.  
**Controls:** explicit untrusted-context separation, targeted input rejection, group-based document filtering, output redaction, request/output caps, and repeatable attack evaluation.  
**Residual risk:** model behavior is probabilistic; prompt-based controls and regex filters are bypassable; demo identity is caller-supplied; no production authentication, rate limiting, vector isolation, or durable audit trail. Do not expose this service to the public internet or load real secrets.

## Repo layout
```text
app/
  main.py
  knowledge/README.md
attacks/
  payloads.json
  run.py
guardrails/
  CONTROL_MAP.md
results/
  .gitkeep
README.md
requirements.txt
.env.example
```

## Portfolio description
Built a local-first RAG chatbot security lab using FastAPI and Ollama; mapped adversarial tests to the OWASP Top 10 for LLM Applications; assessed direct and indirect prompt injection, prompt leakage, sensitive-data disclosure, access-control failures, poisoning, unsafe output, and resource abuse; implemented layered guardrails and a repeatable ASR evaluation harness with per-case JSON evidence.

## Tooling notes
This project uses a custom Python harness for deterministic setup and transparent scoring. **garak** and **PyRIT** are useful complementary tools for broader model probing and orchestration, but are not required to reproduce this baseline. Avoid claiming those tools were used unless you actually run them.

## Security note
All names, extensions, identifiers, and secret-like markers are fictional. The baseline is intentionally less safe and should only be run locally against this synthetic dataset. Never use real secrets in prompts or documents.
