# Guardrail control map

Implemented in `app/main.py` and toggled with `DEFENSES_ENABLED=true`:

- Input policy: targeted injection-pattern rejection, request length cap, control-character rejection.
- Trust boundaries: system prompt labels retrieved documents and user content as untrusted; retrieved instructions must not override policy.
- Retrieval access control: `group=security` documents excluded for users other than `security-analyst`.
- Output filtering: redacts the synthetic canary, credential-shaped strings, SSN-shaped values, and email addresses.
- Resource control: input length and model `num_predict` cap.

Limitations: keyword filters are bypassable; regex PII detection is not a DLP system; this lexical retriever is not a production vector database; the user identity is a demo parameter, not authenticated identity. Production deployment requires real authentication/authorization, audit logs, rate limits, a secrets manager, adversarial evaluation, and tenant-isolated retrieval.
