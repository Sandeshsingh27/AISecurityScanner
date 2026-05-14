package com.aisecurityscanner.service;

import com.aisecurityscanner.model.ComplexityHotspot;
import com.aisecurityscanner.model.DependencyFinding;
import com.aisecurityscanner.model.QualityGateMetric;
import com.aisecurityscanner.model.QualityGateStatus;
import com.aisecurityscanner.model.SecurityFinding;
import com.aisecurityscanner.model.SecurityScanReport;
import com.aisecurityscanner.model.SemgrepFinding;
import com.aisecurityscanner.model.Severity;
import com.aisecurityscanner.model.StackType;
import com.aisecurityscanner.model.TriageResult;
import com.aisecurityscanner.web.dto.ExternalFindingRequest;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.stereotype.Service;

@Service
public class ReportAssemblerService {

    public SecurityScanReport assemble(String projectPath,
                                       List<StackType> stacks,
                                       int filesScanned,
                                       List<String> attackSurface,
                                       List<SemgrepFinding> semgrepFindings,
                                       List<TriageResult> triageResults,
                                       List<ExternalFindingRequest> externalFindings,
                                       List<DependencyFinding> dependencyAudit,
                                       List<ComplexityHotspot> complexityHotspots) {
        SecurityScanReport report = new SecurityScanReport();
        report.setProjectPath(projectPath);
        report.setDate(LocalDate.now());
        report.setStacksDetected(stacks);
        report.setFilesScanned(filesScanned);
        report.setAttackSurface(attackSurface);
        report.setDependencyAudit(dependencyAudit);
        report.setComplexityHotspots(complexityHotspots);
        report.setFindings(buildFindings(semgrepFindings, triageResults, externalFindings));
        report.setQualityGateMetrics(buildMetrics(report));
        report.setQualityGateStatus(report.getQualityGateMetrics().stream().allMatch(QualityGateMetric::isPassed)
            ? QualityGateStatus.PASSED : QualityGateStatus.FAILED);
        return report;
    }

    private List<SecurityFinding> buildFindings(List<SemgrepFinding> semgrepFindings,
                                                List<TriageResult> triageResults,
                                                List<ExternalFindingRequest> externalFindings) {
        List<SecurityFinding> findings = new ArrayList<SecurityFinding>();
        AtomicInteger critical = new AtomicInteger(1);
        AtomicInteger high = new AtomicInteger(1);
        AtomicInteger medium = new AtomicInteger(1);
        AtomicInteger low = new AtomicInteger(1);
        AtomicInteger info = new AtomicInteger(1);

        for (int i = 0; i < semgrepFindings.size(); i++) {
            SemgrepFinding semgrepFinding = semgrepFindings.get(i);
            TriageResult triageResult = triageResults.get(i);
            SecurityFinding finding = new SecurityFinding();
            finding.setSeverity(semgrepFinding.getSeverity());
            finding.setId(nextId(semgrepFinding.getSeverity(), critical, high, medium, low, info));
            finding.setTitle(semgrepFinding.getTitle());
            finding.setFilePath(semgrepFinding.getFilePath());
            finding.setLine(semgrepFinding.getLine());
            finding.setRule(semgrepFinding.getRule());
            finding.setStack(semgrepFinding.getStack());
            finding.setEvidence(semgrepFinding.getRawSnippet());
            finding.setTaintChain(defaultTaintChain(semgrepFinding));
            finding.setFix(triageResult.getFix());
            finding.setExplanation(triageResult.getExplanation());
            finding.setVerifiedByLlm(triageResult.isLlmVerified());
            finding.setSuggestedCode(triageResult.getSuggestedCode());
            finding.setVulnerabilityType(semgrepFinding.getVulnerabilityType());
            findings.add(finding);
        }

        for (ExternalFindingRequest external : externalFindings) {
            SecurityFinding finding = new SecurityFinding();
            Severity severity = external.getSeverity() == null ? Severity.MEDIUM : external.getSeverity();
            finding.setSeverity(severity);
            finding.setId(external.getId() != null ? external.getId() : nextId(severity, critical, high, medium, low, info));
            finding.setTitle(external.getTitle());
            finding.setFilePath(external.getFilePath());
            finding.setLine(external.getLine() == null ? 1 : external.getLine());
            finding.setRule(external.getRule());
            finding.setStack(external.getStack() == null ? StackType.UNKNOWN : external.getStack());
            finding.setEvidence(external.getEvidence());
            finding.setTaintChain(external.getTaintChain());
            finding.setFix(external.getFix());
            finding.setExplanation("Imported from external security agent.");
            finding.setVerifiedByLlm(false);
            finding.setSuggestedCode("");
            finding.setVulnerabilityType(external.getRule());
            findings.add(finding);
        }
        return findings;
    }

    private List<QualityGateMetric> buildMetrics(SecurityScanReport report) {
        List<QualityGateMetric> metrics = new ArrayList<QualityGateMetric>();
        long criticalCount = countBySeverity(report, Severity.CRITICAL);
        long highCount = countBySeverity(report, Severity.HIGH);
        long hardcodedSecrets = report.getFindings().stream().filter(this::isHardcodedSecret).count();
        long unauthenticatedEndpoints = report.getFindings().stream().filter(this::isUnauthenticatedEndpoint).count();
        double averageComplexity = report.getComplexityHotspots().isEmpty()
            ? 0.0
            : report.getComplexityHotspots().stream().mapToInt(ComplexityHotspot::getComplexity).average().orElse(0.0);

        metrics.add(new QualityGateMetric("Critical/Blocker Issues", String.valueOf(criticalCount), "0", criticalCount == 0));
        metrics.add(new QualityGateMetric("High Issues", String.valueOf(highCount), "≤ 2", highCount <= 2));
        metrics.add(new QualityGateMetric("Hardcoded Secrets", String.valueOf(hardcodedSecrets), "0", hardcodedSecrets == 0));
        metrics.add(new QualityGateMetric("Unauthenticated Endpoints", String.valueOf(unauthenticatedEndpoints), "0", unauthenticatedEndpoints == 0));
        metrics.add(new QualityGateMetric("Avg Complexity (hot paths)", String.format(Locale.US, "%.1f", averageComplexity), "≤ 15", averageComplexity <= 15.0));
        return metrics;
    }

    private long countBySeverity(SecurityScanReport report, Severity severity) {
        return report.getFindings().stream().filter(finding -> finding.getSeverity() == severity).count();
    }

    private boolean isHardcodedSecret(SecurityFinding finding) {
        String text = (finding.getTitle() + " " + finding.getRule() + " " + finding.getEvidence()).toLowerCase(Locale.ROOT);
        return text.contains("secret") || text.contains("password") || text.contains("api key") || text.contains("apikey") || text.contains("token");
    }

    private boolean isUnauthenticatedEndpoint(SecurityFinding finding) {
        String text = (finding.getTitle() + " " + finding.getRule() + " " + finding.getExplanation()).toLowerCase(Locale.ROOT);
        return text.contains("unauth") || text.contains("missing auth") || text.contains("permitall") || text.contains("no auth");
    }

    private String defaultTaintChain(SemgrepFinding finding) {
        return "HTTP input near line " + finding.getLine() + " → vulnerable sink matched by Semgrep rule '" + finding.getCheckId() + "'";
    }

    private String nextId(Severity severity,
                          AtomicInteger critical,
                          AtomicInteger high,
                          AtomicInteger medium,
                          AtomicInteger low,
                          AtomicInteger info) {
        switch (severity) {
            case CRITICAL:
                return String.format("C-%03d", critical.getAndIncrement());
            case HIGH:
                return String.format("H-%03d", high.getAndIncrement());
            case MEDIUM:
                return String.format("M-%03d", medium.getAndIncrement());
            case LOW:
                return String.format("L-%03d", low.getAndIncrement());
            default:
                return String.format("I-%03d", info.getAndIncrement());
        }
    }
}
