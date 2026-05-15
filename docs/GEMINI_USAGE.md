# Gemini Usage

PROMETHEUS uses environment-based model routing and never hardcodes old model names in application logic or UI.

## Required environment variables

```bash
GEMINI_API_KEY=
GEMINI_REASONING_MODEL=gemini-3.1-pro-preview
GEMINI_FAST_MODEL=gemini-3-flash-preview
GEMINI_LITE_MODEL=gemini-3.1-flash-lite-preview
```

## Model router

- reasoning tasks -> `GEMINI_REASONING_MODEL`
- fast prediction -> `GEMINI_FAST_MODEL`
- cheap classification -> `GEMINI_LITE_MODEL`

If `GEMINI_API_KEY` is missing, the backend stays fully operational in deterministic demo mode.

## Guardian mapping

- `Oracle`
  This iteration keeps Oracle baselines in local JSON so the demo is deterministic. The intended live routing target is `GEMINI_REASONING_MODEL`.
- `Prophet`
  Uses `GEMINI_FAST_MODEL` for expected-next-action prediction and divergence explanation.
- `Tribunal`
  Uses `GEMINI_REASONING_MODEL` for structured judge voting when available.
- `Historian`
  Uses `GEMINI_REASONING_MODEL` for audit narratives and incident timelines when available.
- `Watcher`
  Deterministic by default. `GEMINI_LITE_MODEL` is reserved for future low-cost classifier expansion.

## Prompt contract

All Gemini calls request strict JSON and fall back to deterministic JSON on any error. The demo should never stall on a model failure.
