<!-- cortex:auto:begin v=1.2.0 sha=7af3b9eea92bb9babfe195238fc98e1273d3a3204847abc38bbc4a33e9229179 -->
# Cognitive Procedure (auto)

Standard procedure (scale to model tier):
1. Plan   - state goal and steps.
2. Read   - read files before editing (never assume paths exist).
3. Edit   - minimal change, no unrelated refactors.
4. Verify - test, lint, typecheck (use run_verification).
5. Review - diff + self_critique before final.

Anti-blunder checklist:
- Do not assume paths exist.
- Do not edit without reading.
- Do not skip verification.
- Do not store secrets.
- Destructive actions require a backup + rollback plan.
- High-risk tasks require manual review.

When to use:
- self_critique before final (returns percent / verdict / severity).
- retrieve_exemplars when unsure.
- model_decision for tier/risk/route.
- get_guardrails before risky actions.
- task_list / task_create to track work.
- run_verification before marking done.

Browser accuracy (web-based tasks):
- Prefer OpenCode browser tools (browser.*) for JS-rendered pages, screenshots, forms.
- Fall back to MCP webfetch (SSRF-guarded) when browser tools unavailable.
- Use webfetch_validate for untrusted URLs. Never store secrets from fetched content.
- See .opencode/skills/browser-accuracy/SKILL.md.
<!-- cortex:auto:end -->
