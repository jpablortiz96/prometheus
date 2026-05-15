import type { IntegrationStatus } from "@prometheus/shared";

export function getGeminiStatusCopy(status: IntegrationStatus) {
  if (status.geminiAvailable) {
    return {
      headline: "Gemini connected",
      detail: `${status.geminiReasoningModel} / ${status.geminiFastModel}`,
      streamLabel: "Gemini routed",
      error: null,
    };
  }

  if (status.geminiConfigured) {
    return {
      headline: "Gemini configured · fallback active",
      detail: "Backend validation failed. Deterministic fallback is active.",
      streamLabel: "Fallback active",
      error: status.geminiLastError,
    };
  }

  return {
    headline: "Gemini simulated · deterministic fallback active",
    detail: "No backend Gemini API key detected.",
    streamLabel: "Deterministic fallback",
    error: null,
  };
}

export function getLobsterTrapStatusCopy(status: IntegrationStatus) {
  if (status.lobsterTrapMode === "live_cli" && status.lobsterTrapAvailable) {
    return {
      headline: "Veea Lobster Trap DPI floor: LIVE CLI",
      detail: "Binary and policy are available. Prompt inspection runs through the real CLI.",
      badge: "Inspected by Veea Lobster Trap CLI",
      note: null,
    };
  }

  if (status.lobsterTrapEnabled) {
    return {
      headline: "Veea Lobster Trap configured · fallback active",
      detail: "PROMETHEUS is configured for Lobster Trap, but deterministic fallback is currently active.",
      badge: "Deterministic fallback active",
      note: status.lobsterTrapLastError,
    };
  }

  return {
    headline: "Veea Lobster Trap simulated",
    detail: "The deterministic DPI simulator is active because live CLI mode is disabled.",
    badge: "Simulated DPI floor",
    note: null,
  };
}

export function splitTenantLabel(label: string) {
  const [tenantName, ...rest] = label.split(" - ");
  return {
    tenantName: tenantName.trim(),
    tenantDescriptor: rest.join(" - ").trim(),
  };
}
