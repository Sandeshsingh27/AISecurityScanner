export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface SecurityFinding {
  id: string;
  title: string;
  filePath: string;
  line: number;
  rule: string;
  stack?: string;
  severity: Severity;
  evidence?: string;
  taintChain?: string;
  fix?: string;
  explanation?: string;
  verifiedByLlm?: boolean;
  suggestedCode?: string;
  vulnerabilityType?: string;
  category?: string;
}

export interface DependencyFinding {
  packageName: string;
  currentVersion: string;
  vulnerableBelow: string;
  cve: string;
  severity: Severity;
}

export interface ComplexityHotspot {
  filePath: string;
  method: string;
  complexity: number;
  rating: Severity;
}

export interface QualityGateMetric {
  name: string;
  value: string;
  threshold: string;
  passed: boolean;
}

export interface SecurityScanReport {
  projectPath: string;
  date: string | [number, number, number] | null;
  stacksDetected: string[];
  filesScanned: number;
  qualityGateStatus: "PASS" | "FAIL" | string;
  qualityGateMetrics: QualityGateMetric[];
  findings: SecurityFinding[];
  dependencyAudit: DependencyFinding[];
  complexityHotspots: ComplexityHotspot[];
  attackSurface: string[];
}

export interface ScanRequest {
  targetPath: string;
  semgrepConfig: string;
  fastScan: boolean;
  llmEnabled: boolean;
  includeDependencyAudit: boolean;
  maxFindingsForLlm: number;
  autoImportAgentFindings: boolean;
  externalFindings: unknown[];
}

