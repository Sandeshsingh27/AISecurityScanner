package com.aisecurityscanner.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.aisecurityscanner.model.QualityGateMetric;
import com.aisecurityscanner.model.QualityGateStatus;
import com.aisecurityscanner.model.SecurityScanReport;
import com.aisecurityscanner.model.StackType;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.Collections;
import org.junit.jupiter.api.Test;

class MarkdownReportRendererTest {

    @Test
    void renderIncludesExpectedSections() {
        SecurityScanReport report = new SecurityScanReport();
        report.setProjectPath("C:/repo");
        report.setDate(LocalDate.of(2026, 5, 14));
        report.setStacksDetected(Arrays.asList(StackType.JAVA_SPRING_BOOT));
        report.setFilesScanned(8);
        report.setQualityGateStatus(QualityGateStatus.PASSED);
        report.setQualityGateMetrics(Collections.singletonList(new QualityGateMetric("Critical/Blocker Issues", "0", "0", true)));

        MarkdownReportRenderer renderer = new MarkdownReportRenderer();

        String markdown = renderer.render(report);

        assertThat(markdown).contains("# 🔒 Security & Quality Scan Report");
        assertThat(markdown).contains("## Quality Gate: ✅ PASSED");
        assertThat(markdown).contains("## Findings");
        assertThat(markdown).contains("## Dependency Audit");
        assertThat(markdown).contains("## Complexity Hotspots");
    }
}
