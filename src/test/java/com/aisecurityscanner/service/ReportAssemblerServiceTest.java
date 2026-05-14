package com.aisecurityscanner.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.aisecurityscanner.model.ComplexityHotspot;
import com.aisecurityscanner.model.SecurityScanReport;
import com.aisecurityscanner.model.SemgrepFinding;
import com.aisecurityscanner.model.Severity;
import com.aisecurityscanner.model.StackType;
import com.aisecurityscanner.model.TriageResult;
import java.util.Arrays;
import java.util.Collections;
import org.junit.jupiter.api.Test;

class ReportAssemblerServiceTest {

    @Test
    void assembleBuildsFailedQualityGateWhenHighRiskIssuesExist() {
        ReportAssemblerService service = new ReportAssemblerService();

        SemgrepFinding finding = new SemgrepFinding();
        finding.setCheckId("java.lang.security.audit.hardcoded-password");
        finding.setTitle("Hardcoded secret in source");
        finding.setFilePath("src/main/java/com/example/AuthConfig.java");
        finding.setLine(14);
        finding.setRule("OWASP A02 / CWE-798");
        finding.setSeverity(Severity.CRITICAL);
        finding.setRawSnippet("private static final String PASSWORD = \"admin123\";");
        finding.setStack(StackType.JAVA_SPRING_BOOT);
        finding.setVulnerabilityType("Hardcoded Secret");

        TriageResult triage = new TriageResult();
        triage.setExploitable(true);
        triage.setExplanation("The password is stored directly in source code and can be reused by anyone with repository access.");
        triage.setFix("Move the secret to environment variables and rotate it.");
        triage.setLlmVerified(false);

        SecurityScanReport report = service.assemble(
            "C:/repo",
            Arrays.asList(StackType.JAVA_SPRING_BOOT),
            12,
            Collections.singletonList("AuthController -> @PostMapping(\"/login\")"),
            Collections.singletonList(finding),
            Collections.singletonList(triage),
            Collections.emptyList(),
            Collections.emptyList(),
            Collections.singletonList(new ComplexityHotspot("src/main/java/com/example/AuthService.java", "validateAndRoute", 18, Severity.MEDIUM))
        );

        assertThat(report.getQualityGateStatus().name()).isEqualTo("FAILED");
        assertThat(report.getFindings()).hasSize(1);
        assertThat(report.getFindings().get(0).getId()).isEqualTo("C-001");
        assertThat(report.getQualityGateMetrics()).extracting("name")
            .contains("Critical/Blocker Issues", "Hardcoded Secrets", "Avg Complexity (hot paths)");
    }
}
