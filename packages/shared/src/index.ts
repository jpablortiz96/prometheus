export type AgentStatus = "normal" | "watching" | "blocked" | "quarantine";

export type Severity = "low" | "medium" | "high" | "critical";

export type Decision = "ALLOW" | "BLOCK" | "QUARANTINE";

export type ConnectionMode = "live" | "fallback";

export type ReviewStatus =
  | "pending"
  | "approved"
  | "denied"
  | "quarantined"
  | "escalated";

export type ToolDecision = "ALLOW" | "BLOCK" | "QUARANTINE" | "HUMAN_REVIEW";

export type PermissionState = "allowed" | "denied" | "human_review" | "quarantine";

export interface PolicySignal {
  id: string;
  label: string;
  severity: Severity;
}

export interface PolicyPackDefinition {
  id: string;
  label: string;
  summary: string;
  thresholdBlock: number;
  thresholdQuarantine: number;
  decisionLabels: {
    allow: string;
    block: string;
    quarantine: string;
  };
  complianceLabels: string[];
  sponsorHint: string;
}

export interface EnterpriseMetric {
  id: string;
  label: string;
  value: string;
  trend: string;
  emphasis: "positive" | "watch" | "critical" | "neutral";
}

export interface IntegrationStatus {
  geminiConfigured: boolean;
  geminiConnected: boolean;
  geminiAvailable: boolean;
  geminiMode: "connected" | "simulated";
  geminiReasoningModel: string;
  geminiFastModel: string;
  geminiLiteModel: string;
  geminiLastError: string | null;
  lobsterTrapEnabled: boolean;
  lobsterTrapAvailable: boolean;
  lobsterTrapBinFound: boolean;
  lobsterTrapMode: "simulated" | "live_cli" | "configured_but_unavailable";
  lobsterTrapBinPath: string;
  lobsterTrapPolicyPath: string;
  lobsterTrapLastError: string | null;
  policyFileFound: boolean;
  policyRuleCount: number;
  policyRulesCount: number;
  demoFallbackActive: boolean;
  auditTrailOnline: boolean;
  databaseAvailable: boolean;
  activePolicyPack: string;
  models: {
    reasoning: string;
    fast: string;
    lite: string;
  };
}

export interface AgentRecord {
  id: string;
  name: string;
  role: string;
  model: string;
  baseline: string;
  status: AgentStatus;
  trustScore: number;
  trustDelta: number;
  lastAction: string;
  lastEventAt: string;
  predictedAction: string;
  divergenceScore: number;
  policyPack: string;
  sparkline: number[];
  modelSource: "gemini" | "deterministic";
  accessLevel: string;
  policyExposure: string[];
}

export interface KPISet {
  attacksBlocked: number;
  quarantined: number;
  activeAgents: number;
  averageLatencyMs: number;
  trustFloor: number;
  incidents24h: number;
}

export interface JudgeVote {
  judge: string;
  role: string;
  vote: Decision;
  reasoning: string;
  modelUsed: string;
}

export interface TribunalDecision {
  scenarioId: string;
  agentId: string;
  consensus: Decision;
  latencyMs: number;
  explanation: string;
  modelUsed: string;
  judges: JudgeVote[];
}

export interface EventEvidence {
  rawPrompt: string;
  dpiSource: "veea_lobstertrap_cli" | "simulated";
  dpiMode: "live_cli" | "live_cli_error" | "simulated";
  dpiFindings: string[];
  detectedPii: string[];
  credentialPatterns: string[];
  targetDomains: string[];
  sensitivePaths: string[];
  riskyCommands: string[];
  matchedPolicyRules: string[];
  divergenceScore: number;
  trustDelta: number;
  recommendedAction: string;
  timeline: string[];
  rawLobstertrapOutput: string | null;
  fallbackUsed: boolean;
  fallbackReason: string | null;
  lobsterTrapMetadata?: Record<string, unknown>;
  lobstertrapMetadata?: Record<string, unknown>;
}

export interface EventImpact {
  businessImpact: string;
  regulatoryImpact: string;
  complianceConcern: string;
  department: string;
  mitreTacticLabel: string;
  blockedAction: string;
  recommendedRemediation: string;
  auditSummary: string;
  enterpriseValue: string;
}

export interface EventRecord {
  id: string;
  scenarioId: string;
  agentId: string;
  title: string;
  declaredIntent: string;
  detectedIntent: string;
  observedAction: string;
  predictedAction: string;
  divergenceScore: number;
  severity: Severity;
  decision: Decision;
  decisionLabel: string;
  explanation: string;
  timestamp: string;
  tribunalConsensus: string;
  policySignals: PolicySignal[];
  policyPack: string;
  riskScore: number;
  reviewStatus: ReviewStatus;
  modelUsed: string;
  evidence: EventEvidence;
  impact: EventImpact;
  affectedResources: string[];
}

export interface IncidentCommandCenter {
  incidentId: string;
  severity: Severity;
  affectedAgent: string;
  declaredIntent: string;
  detectedIntent: string;
  predictedAction: string;
  observedAction: string;
  policyMatched: string[];
  finalDecision: Decision;
  decisionLabel: string;
  businessImpact: string;
  regulatoryImpact: string;
  department: string;
  complianceConcern: string;
  riskScore: number;
  trustDelta: number;
}

export interface ReviewQueueItem {
  eventId: string;
  incidentId: string;
  severity: Severity;
  agentId: string;
  requestedAction: Decision;
  businessOwner: string;
  policyPack: string;
  status: ReviewStatus;
}

export interface KnowledgeNode {
  id: string;
  label: string;
  type: "agent" | "tool" | "data_store" | "policy_rule" | "incident";
  x: number;
  y: number;
  emphasis?: boolean;
  trustScore?: number;
  accessLevel?: string;
  policyExposure?: string[];
  relatedEventIds?: string[];
}

export interface KnowledgeEdge {
  from: string;
  to: string;
  type: "normal" | "blocked" | "watch" | "tool" | "policy";
}

export interface KnowledgeGraph {
  nodes: KnowledgeNode[];
  edges: KnowledgeEdge[];
}

export interface DashboardSnapshot {
  agents: AgentRecord[];
  events: EventRecord[];
  kpis: KPISet;
  knowledgeGraph: KnowledgeGraph;
  activeTribunal: TribunalDecision | null;
  activeIncident: IncidentCommandCenter | null;
  reviewQueue: ReviewQueueItem[];
  policyPacks: PolicyPackDefinition[];
  integrationStatus: IntegrationStatus;
  enterpriseMetrics: EnterpriseMetric[];
  productVersion: string;
  tenantLabel: string;
  complianceLabels: string[];
  statusMessage: string;
  sponsorStatus: string;
  activePolicyPack: string;
  demoRunning: boolean;
  demoMode: boolean;
  countdownSeconds: number;
  demoStage: string;
  demoProgressPercent: number;
  reportReady: boolean;
  lastToolCall: ToolCallDecisionRecord | null;
  recentToolCalls: ToolCallDecisionRecord[];
  permissionMatrix: GatewayPermissionMatrix;
  connectionMode: ConnectionMode;
  lastUpdated: string;
}

export interface TribunalEvaluateRequest {
  agentId: string;
  scenarioId: string;
  userPrompt: string;
  declaredIntent: string;
  detectedIntent: string;
  expectedDecision: Decision;
  riskScore: number;
  policyPack: string;
  observedAction: string;
}

export interface AuditReportRequest {
  scenarioId?: string;
  incidentId?: string;
}

export interface AuditReportExport {
  title: string;
  format: "html" | "markdown";
  content: string;
  fileName: string;
  generatedAt: string;
  modelUsed: string;
}

export interface AuditBundle {
  incidentId: string;
  generatedAt: string;
  tenant: string;
  policyPack: string;
  decision: string;
  riskScore: number;
  evidence: EventEvidence;
  timeline: string[];
  tribunalVotes: JudgeVote[];
  remediation: string;
  markdownReport: string;
  htmlReport: string;
  auditHash: string;
  tamperNotice: string;
}

export interface AuditReportArchiveItem {
  incidentId: string;
  title: string;
  generatedAt: string;
  format: "bundle" | "html" | "markdown";
  decision: string;
  policyPack: string;
  auditHash: string;
  modelUsed: string;
}

export interface IncidentSummary {
  incidentId: string;
  title: string;
  agentId: string;
  severity: Severity;
  decision: Decision;
  decisionLabel: string;
  policyPack: string;
  riskScore: number;
  timestamp: string;
}

export interface IncidentDetail {
  incident: IncidentCommandCenter;
  event: EventRecord;
  reports: AuditReportArchiveItem[];
}

export interface ScenarioRecord {
  id: string;
  name: string;
  userPrompt: string;
  declaredIntent: string;
  detectedIntent: string;
  expectedDecision: Decision;
  riskScore: number;
  policyPack: string;
  explanation: string;
  agentId: string;
  observedAction: string;
  predictedAction: string;
  mitreTacticLabel: string;
  department: string;
  businessImpact: string;
  regulatoryImpact: string;
  complianceConcern: string;
  blockedAction: string;
  recommendedRemediation: string;
  auditSummary: string;
  enterpriseValue: string;
  affectedResources: string[];
}

export interface LobsterTrapInspectRequest {
  prompt: string;
  declaredIntent: string;
  agentId: string;
  policyPack: string;
  detectedIntent?: string;
}

export interface NormalizedDpiResult {
  source: "veea_lobstertrap_cli" | "simulated";
  mode: "live_cli" | "live_cli_error" | "simulated";
  verdict: string;
  action: Decision;
  riskScore: number;
  matchedRules: string[];
  detectedIntent: string;
  containsPii: boolean;
  containsCredentials: boolean;
  containsInjectionPatterns: boolean;
  containsSystemCommands: boolean;
  containsUrls: boolean;
  targetDomains: string[];
  sensitivePaths: string[];
  rawLobstertrapOutput: string | null;
  fallbackUsed: boolean;
  fallbackReason: string | null;
}

export interface LobsterTrapInspectResponse {
  agentId: string;
  inspection: {
    declaredIntent: string;
    detectedIntent: string;
    riskScore: number;
    floorDecision: Decision;
    dpiSource: "veea_lobstertrap_cli" | "simulated";
    dpiMode: "live_cli" | "live_cli_error" | "simulated";
    policySignals: PolicySignal[];
    metadata: Record<string, unknown>;
    dpiFindings: string[];
    detectedPii: string[];
    credentialPatterns: string[];
    targetDomains: string[];
    sensitivePaths: string[];
    riskyCommands: string[];
    matchedPolicyRules: string[];
    rawLobstertrapOutput: string | null;
    fallbackUsed: boolean;
    fallbackReason: string | null;
    recommendedAction: string;
  };
  statusLabel: string;
  policyRuleCount: number;
  policyRulesCount: number;
}

export interface RedTeamRunRequest {
  mode: "drill" | "demo";
}

export interface RedTeamRunResponse {
  started: boolean;
  mode: "drill" | "demo";
  message: string;
}

export interface PolicyPackSelectRequest {
  policyPackId: string;
}

export interface PolicyPackSelectResponse {
  activePolicyPack: string;
}

export interface ReviewQueueActionRequest {
  eventId: string;
  action: ReviewStatus;
}

export interface ReviewQueueActionResponse {
  eventId: string;
  status: ReviewStatus;
  message: string;
}

export interface ScenarioRunRequest {
  scenarioId: string;
}

export interface SandboxToolResult {
  toolName: string;
  executed: boolean;
  result: Record<string, unknown>;
  sideEffectSummary: string;
  dataClassification: string;
}

export interface PermissionEvaluation {
  agentId: string;
  toolName: string;
  policyPack: string;
  permissionState: PermissionState;
  allowed: boolean;
  requiresHumanReview: boolean;
  externalEgress: boolean;
  dataClassification: string;
  reason: string;
  matchedRestrictions: string[];
}

export interface ToolCallRequest {
  agentId: string;
  toolName: string;
  declaredIntent: string;
  prompt: string;
  payload: Record<string, unknown>;
  policyPack: string;
  requiresHumanReview?: boolean;
}

export interface ToolCallDecisionRecord {
  requestId: string;
  agentId: string;
  toolName: string;
  declaredIntent: string;
  detectedIntent: string;
  predictedAction: string;
  observedAction: string;
  dpiSource: "veea_lobstertrap_cli" | "simulated";
  dpiMode: "live_cli" | "live_cli_error" | "simulated";
  decision: ToolDecision;
  toolExecuted: boolean;
  riskScore: number;
  matchedRules: string[];
  reason: string;
  rawLobstertrapOutput: string | null;
  rawLobstertrapOutputPreview?: string | null;
  evidencePreview?: string | null;
  tribunalVotes: JudgeVote[];
  auditHash: string;
  createdAt: string;
  permissionEvaluation: PermissionEvaluation;
  toolResult: SandboxToolResult | null;
  sideEffectPrevented: string | null;
  sideEffectPreventedFlag: boolean;
  sourceEventId: string | null;
}

export interface PermissionMatrixRow {
  agentId: string;
  agentName: string;
  cells: Record<string, PermissionState>;
}

export interface GatewayPermissionMatrix {
  tools: string[];
  rows: PermissionMatrixRow[];
}

export interface DocumentInspectRequest {
  documentName: string;
  documentContent: string;
  agentId: string;
  declaredIntent: string;
  toolName: string;
  policyPack: string;
  requiresHumanReview?: boolean;
}

export interface DocumentInspectResponse {
  documentName: string;
  contentExcerpt: string;
  documentContentPreview?: string | null;
  evidencePreview?: string | null;
  toolDecision: ToolCallDecisionRecord;
  incidentId: string | null;
  auditHash: string;
}

export interface LobsterTrapDebugResponse {
  enabled: boolean;
  available: boolean;
  mode: string;
  binPath: string;
  binExists: boolean;
  binIsFile: boolean;
  policyPath: string;
  policyExists: boolean;
  policyRulesCount: number;
  versionReturncode: number | null;
  versionStdoutPreview: string | null;
  versionStderrPreview: string | null;
  versionElapsedMs: number | null;
  inspectTestReturncode: number | null;
  inspectTestStdoutPreview: string | null;
  inspectTestStderrPreview: string | null;
  inspectTestElapsedMs: number | null;
  lastError: string | null;
}

export interface PolicyPatchRecommendation {
  ruleName: string;
  condition: string;
  action: string;
  reason: string;
}

export interface PermissionChangeRecommendation {
  agentId: string;
  toolName: string;
  recommendedState: PermissionState;
  reason: string;
}

export interface ThreatIntelScenarioDraft {
  name: string;
  declaredIntent: string;
  detectedIntent: string;
  attemptedTool: string;
  prompt: string;
  expectedDecision: ToolDecision;
  safetyNote: string;
}

export interface ThreatIntelInput {
  title: string;
  source: string;
  reportText: string;
  policyPack: string;
  industry: string;
  createScenario?: boolean;
  runSimulation?: boolean;
}

export interface ThreatIntelExtraction {
  threatSummary: string;
  attackerGoal: string;
  aiMisusePattern: string;
  suspectedTactics: string[];
  affectedEnterpriseFunctions: string[];
  riskyAgentBehaviors: string[];
  dangerousToolCalls: string[];
  recommendedPolicyRules: PolicyPatchRecommendation[];
  recommendedPermissionChanges: PermissionChangeRecommendation[];
  safeScenario: ThreatIntelScenarioDraft;
}

export interface ThreatIntelAuditRecord {
  incidentId: string;
  decision: string;
  policyPack: string;
  auditHash: string;
  generatedAt: string;
}

export interface ThreatIntelRunResult {
  runId: string;
  title: string;
  source: string;
  policyPack: string;
  industry: string;
  extraction: ThreatIntelExtraction;
  generatedScenario: ThreatIntelScenarioDraft | null;
  policyPatch: PolicyPatchRecommendation[];
  gatewayDecision: ToolCallDecisionRecord | null;
  auditBundle: ThreatIntelAuditRecord | null;
  blockedBeforeExecution: boolean | null;
  createdAt: string;
}

export interface ThreatIntelRunSummary {
  runId: string;
  title: string;
  source: string;
  policyPack: string;
  industry: string;
  decision: string | null;
  attemptedTool: string | null;
  toolExecuted: boolean | null;
  incidentId: string | null;
  blockedBeforeExecution: boolean | null;
  createdAt: string;
}
