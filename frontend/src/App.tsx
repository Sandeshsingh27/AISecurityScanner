import { useMemo, useState } from "react";
import { Bar, BarChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { requestScan } from "./api";
import type { ScanRequest, SecurityFinding, SecurityScanReport, Severity } from "./types";

const STORAGE_KEY = "aiss-last-request";

const severityOrder: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

const severityColor: Record<Severity, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#f59e0b",
  LOW: "#22c55e",
  INFO: "#38bdf8"
};

const defaultRequest: ScanRequest = {
  targetPath: "",
  semgrepConfig: "semgrep-rules/offline-security.yml",
  fastScan: true,
  llmEnabled: false,
  includeDependencyAudit: true,
  maxFindingsForLlm: 15,
  autoImportAgentFindings: false,
  externalFindings: []
};

type DashboardTab = "overview" | "findings" | "quality" | "dependencies" | "hotspots" | "details";

function readInitialRequest(): ScanRequest {
  const saved = localStorage.getItem(STORAGE_KEY);
  if (!saved) {
    return defaultRequest;
  }
  try {
    return { ...defaultRequest, ...(JSON.parse(saved) as Partial<ScanRequest>) };
  } catch {
    return defaultRequest;
  }
}

function formatDate(value: SecurityScanReport["date"]): string {
  if (!value) {
    return "n/a";
  }
  if (Array.isArray(value) && value.length === 3) {
    const [year, month, day] = value;
    return `${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
  }
  return value;
}

function bySeverity<T extends { severity: Severity }>(list: T[]): Record<Severity, number> {
  return list.reduce(
    (acc, item) => {
      acc[item.severity] += 1;
      return acc;
    },
    { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
  );
}

function App(): JSX.Element {
  const [request, setRequest] = useState<ScanRequest>(readInitialRequest);
  const [report, setReport] = useState<SecurityScanReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<Severity | "ALL">("ALL");
  const [categoryFilter, setCategoryFilter] = useState<string>("ALL");
  const [llmOnly, setLlmOnly] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<SecurityFinding | null>(null);
  const [activeTab, setActiveTab] = useState<DashboardTab>("overview");

  const findings = report?.findings ?? [];
  const categories = useMemo(() => {
    const set = new Set<string>();
    findings.forEach((finding) => {
      if (finding.category && finding.category.trim()) {
        set.add(finding.category);
      }
    });
    return Array.from(set).sort();
  }, [findings]);

  const filteredFindings = useMemo(() => {
    const keyword = search.toLowerCase().trim();
    return findings
      .filter((finding) => (severityFilter === "ALL" ? true : finding.severity === severityFilter))
      .filter((finding) => (categoryFilter === "ALL" ? true : (finding.category || "") === categoryFilter))
      .filter((finding) => (llmOnly ? Boolean(finding.verifiedByLlm) : true))
      .filter((finding) => {
        if (!keyword) {
          return true;
        }
        return [finding.title, finding.filePath, finding.rule, finding.evidence, finding.category]
          .filter(Boolean)
          .join(" ")
          .toLowerCase()
          .includes(keyword);
      })
      .sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity));
  }, [findings, severityFilter, categoryFilter, llmOnly, search]);

  const severityStats = useMemo(() => bySeverity(findings), [findings]);
  const severityChartData = severityOrder.map((severity) => ({
    name: severity,
    value: severityStats[severity]
  }));

  const categoryChartData = useMemo(() => {
    const counts = new Map<string, number>();
    findings.forEach((finding) => {
      const key = finding.category || "Uncategorized";
      counts.set(key, (counts.get(key) || 0) + 1);
    });
    return Array.from(counts.entries())
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 8);
  }, [findings]);

  const criticalAndHigh = severityStats.CRITICAL + severityStats.HIGH;

  async function runScan(): Promise<void> {
    setLoading(true);
    setError(null);
    setSelectedFinding(null);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(request));
      const data = await requestScan(request);
      setReport(data);
      setActiveTab("overview");
    } catch (scanError) {
      setError(scanError instanceof Error ? scanError.message : "Unexpected error");
      setReport(null);
    } finally {
      setLoading(false);
    }
  }

  function exportJson(): void {
    if (!report) {
      return;
    }
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "security-report.json";
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="app-shell">
      <aside className="panel request-panel">
        <h1>AI Security Scanner</h1>
        <p className="muted">SonarQube-style dashboard for API scans.</p>

        <label>Target path</label>
        <input
          value={request.targetPath}
          onChange={(event) => setRequest({ ...request, targetPath: event.target.value })}
          placeholder="C:/repos/my-service"
        />

        <label>Semgrep config</label>
        <input
          value={request.semgrepConfig}
          onChange={(event) => setRequest({ ...request, semgrepConfig: event.target.value })}
          placeholder="semgrep-rules/offline-security.yml"
        />

        <div className="toggle-row">
          <label>
            <input
              type="checkbox"
              checked={request.fastScan}
              onChange={(event) => setRequest({ ...request, fastScan: event.target.checked })}
            />
            Fast scan
          </label>
          <label>
            <input
              type="checkbox"
              checked={request.llmEnabled}
              onChange={(event) => setRequest({ ...request, llmEnabled: event.target.checked })}
            />
            LLM triage
          </label>
        </div>

        <div className="toggle-row">
          <label>
            <input
              type="checkbox"
              checked={request.includeDependencyAudit}
              onChange={(event) => setRequest({ ...request, includeDependencyAudit: event.target.checked })}
            />
            Dependency audit
          </label>
          <label>
            <input
              type="checkbox"
              checked={request.autoImportAgentFindings}
              onChange={(event) => setRequest({ ...request, autoImportAgentFindings: event.target.checked })}
            />
            Import agent findings
          </label>
        </div>

        <label>Max findings for LLM</label>
        <input
          type="number"
          min={1}
          max={100}
          value={request.maxFindingsForLlm}
          onChange={(event) =>
            setRequest({ ...request, maxFindingsForLlm: Number.parseInt(event.target.value, 10) || 15 })
          }
        />

        <button className="primary" onClick={runScan} disabled={loading || !request.targetPath.trim()}>
          {loading ? "Scanning..." : "Run scan"}
        </button>

        <button onClick={exportJson} disabled={!report}>
          Export JSON
        </button>

        {error ? <p className="error">{error}</p> : null}
      </aside>

      <main className="dashboard-panel">
        {!report ? (
          <section className="panel empty-state">
            <h2>No report loaded</h2>
            <p>Run a scan to view vulnerabilities, quality gate metrics, dependency CVEs, and hotspots.</p>
          </section>
        ) : (
          <>
            <section className="panel tab-panel">
              <button className={activeTab === "overview" ? "tab-btn active" : "tab-btn"} onClick={() => setActiveTab("overview")}>
                Overview
              </button>
              <button className={activeTab === "findings" ? "tab-btn active" : "tab-btn"} onClick={() => setActiveTab("findings")}>
                Findings
              </button>
              <button className={activeTab === "quality" ? "tab-btn active" : "tab-btn"} onClick={() => setActiveTab("quality")}>
                Quality Gate
              </button>
              <button className={activeTab === "dependencies" ? "tab-btn active" : "tab-btn"} onClick={() => setActiveTab("dependencies")}>
                Dependencies
              </button>
              <button className={activeTab === "hotspots" ? "tab-btn active" : "tab-btn"} onClick={() => setActiveTab("hotspots")}>
                Hotspots
              </button>
              <button className={activeTab === "details" ? "tab-btn active" : "tab-btn"} onClick={() => setActiveTab("details")}>
                Finding details
              </button>
            </section>

            {activeTab === "overview" ? (
              <>
                <section className="stats-grid">
                  <article className="panel stat-card">
                    <span className="label">Project</span>
                    <strong>{report.projectPath}</strong>
                    <span className="muted">Scanned on {formatDate(report.date)}</span>
                  </article>
                  <article className="panel stat-card">
                    <span className="label">Quality gate</span>
                    <strong className={report.qualityGateStatus === "PASS" ? "ok" : "bad"}>{report.qualityGateStatus}</strong>
                    <span className="muted">{report.filesScanned} files scanned</span>
                  </article>
                  <article className="panel stat-card">
                    <span className="label">Findings</span>
                    <strong>{findings.length}</strong>
                    <span className="muted">{criticalAndHigh} critical/high</span>
                  </article>
                  <article className="panel stat-card">
                    <span className="label">Dependencies</span>
                    <strong>{report.dependencyAudit.length}</strong>
                    <span className="muted">Potential vulnerable packages</span>
                  </article>
                </section>

                <section className="charts-grid">
                  <article className="panel chart-card">
                    <h3>Findings by severity</h3>
                    <ResponsiveContainer width="100%" height={220}>
                      <BarChart data={severityChartData}>
                        <XAxis dataKey="name" />
                        <YAxis allowDecimals={false} />
                        <Tooltip />
                        <Bar dataKey="value">
                          {severityChartData.map((item) => (
                            <Cell key={item.name} fill={severityColor[item.name as Severity]} />
                          ))}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </article>
                  <article className="panel chart-card">
                    <h3>Top finding categories</h3>
                    <ResponsiveContainer width="100%" height={220}>
                      <PieChart>
                        <Pie data={categoryChartData} dataKey="value" nameKey="name" outerRadius={80} label>
                          {categoryChartData.map((item, index) => (
                            <Cell key={item.name} fill={["#2563eb", "#7c3aed", "#0891b2", "#d946ef", "#ea580c", "#16a34a", "#e11d48", "#4f46e5"][index % 8]} />
                          ))}
                        </Pie>
                        <Tooltip />
                      </PieChart>
                    </ResponsiveContainer>
                  </article>
                </section>
              </>
            ) : null}

            {activeTab === "findings" ? (
              <section className="panel">
                <h3>Findings</h3>
              <div className="filters-row">
                <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search title, file, rule" />
                <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value as Severity | "ALL")}>
                  <option value="ALL">All severities</option>
                  {severityOrder.map((severity) => (
                    <option key={severity} value={severity}>
                      {severity}
                    </option>
                  ))}
                </select>
                <select value={categoryFilter} onChange={(event) => setCategoryFilter(event.target.value)}>
                  <option value="ALL">All categories</option>
                  {categories.map((category) => (
                    <option key={category} value={category}>
                      {category}
                    </option>
                  ))}
                </select>
                <label>
                  <input type="checkbox" checked={llmOnly} onChange={(event) => setLlmOnly(event.target.checked)} />
                  LLM verified only
                </label>
              </div>

              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Category</th>
                      <th>Title</th>
                      <th>Rule</th>
                      <th>Location</th>
                      <th>LLM</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredFindings.map((finding) => (
                      <tr
                        key={finding.id}
                        onClick={() => {
                          setSelectedFinding(finding);
                          setActiveTab("details");
                        }}>
                        <td>
                          <span className="severity-pill" style={{ backgroundColor: severityColor[finding.severity] }}>
                            {finding.severity}
                          </span>
                        </td>
                        <td>{finding.category || "-"}</td>
                        <td>{finding.title}</td>
                        <td>{finding.rule}</td>
                        <td>
                          {finding.filePath}:{finding.line}
                        </td>
                        <td>{finding.verifiedByLlm ? "Yes" : "No"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              </section>
            ) : null}

            {activeTab === "quality" ? (
              <section className="panel">
                <h3>Quality gate metrics</h3>
                <table>
                  <thead>
                    <tr>
                      <th>Metric</th>
                      <th>Value</th>
                      <th>Threshold</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.qualityGateMetrics.map((metric) => (
                      <tr key={metric.name}>
                        <td>{metric.name}</td>
                        <td>{metric.value}</td>
                        <td>{metric.threshold}</td>
                        <td className={metric.passed ? "ok" : "bad"}>{metric.passed ? "PASS" : "FAIL"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </section>
            ) : null}

            {activeTab === "dependencies" ? (
              <section className="panel">
                <h3>Dependency audit</h3>
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th>Package</th>
                        <th>Current</th>
                        <th>Vulnerable below</th>
                        <th>CVE</th>
                        <th>Severity</th>
                      </tr>
                    </thead>
                    <tbody>
                      {report.dependencyAudit.map((item) => (
                        <tr key={`${item.packageName}-${item.cve}`}>
                          <td>{item.packageName}</td>
                          <td>{item.currentVersion}</td>
                          <td>{item.vulnerableBelow}</td>
                          <td>{item.cve}</td>
                          <td>{item.severity}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            ) : null}

            {activeTab === "hotspots" ? (
              <section className="panel">
              <h3>Complexity hotspots</h3>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>File</th>
                      <th>Method</th>
                      <th>Complexity</th>
                      <th>Rating</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.complexityHotspots.map((hotspot, index) => (
                      <tr key={`${hotspot.filePath}-${hotspot.method}-${index}`}>
                        <td>{hotspot.filePath}</td>
                        <td>{hotspot.method}</td>
                        <td>{hotspot.complexity}</td>
                        <td>{hotspot.rating}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              </section>
            ) : null}

            {activeTab === "details" ? (
              <section className="panel">
                <h3>Finding details</h3>
                {!selectedFinding ? (
                  <p className="muted">Select a finding from the Findings tab to inspect evidence, taint chain, and remediation.</p>
                ) : (
                  <>
                    <h3>{selectedFinding.title}</h3>
                    <p>
                      <strong>Severity:</strong> {selectedFinding.severity}
                    </p>
                    <p>
                      <strong>Category:</strong> {selectedFinding.category || "-"}
                    </p>
                    <p>
                      <strong>Location:</strong> {selectedFinding.filePath}:{selectedFinding.line}
                    </p>
                    <p>
                      <strong>Rule:</strong> {selectedFinding.rule}
                    </p>
                    <p>
                      <strong>LLM verified:</strong> {selectedFinding.verifiedByLlm ? "Yes" : "No"}
                    </p>

                    <h4>Evidence</h4>
                    <pre>{selectedFinding.evidence || "No evidence provided."}</pre>

                    <h4>Taint chain</h4>
                    <pre>{selectedFinding.taintChain || "No taint chain provided."}</pre>

                    <h4>Explanation</h4>
                    <pre>{selectedFinding.explanation || "No explanation provided."}</pre>

                    <h4>Fix guidance</h4>
                    <pre>{selectedFinding.fix || "No fix guidance provided."}</pre>

                    {selectedFinding.suggestedCode ? (
                      <>
                        <h4>Suggested code</h4>
                        <pre>{selectedFinding.suggestedCode}</pre>
                      </>
                    ) : null}
                  </>
                )}
              </section>
            ) : null}
          </>
        )}
      </main>
    </div>
  );
}

export default App;

