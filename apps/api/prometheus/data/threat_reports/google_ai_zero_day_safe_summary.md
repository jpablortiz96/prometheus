Zero-Day Sentinel Safe Threat Summary

Source context:
- Public reporting described attackers using AI assistance to accelerate vulnerability research and triage.
- Reporting suggested possible exploit generation intent and possible authentication bypass testing.
- No exploit code, no proof-of-concept payloads, and no targeting steps are included here.

Enterprise relevance:
- A compromised or over-permissioned enterprise agent could be pushed toward exploit-development-adjacent workflows.
- Risk increases if agents can launch scanners without review, test identity controls autonomously, or write unsafe outputs into downstream systems.
- Security research agents still need safe read-only tooling and clear human review boundaries.

Required controls:
- Block exploit generation requests by default.
- Block exploit execution requests by default.
- Quarantine or block authentication bypass testing.
- Require human review for scanner activity.
- Allow defensive summarization and report writing inside a sandbox only.

Desired outcome:
- Convert this threat report into enforceable policy recommendations, a safe adversarial scenario, and audit-ready evidence that risky cyber tools were blocked before execution.
