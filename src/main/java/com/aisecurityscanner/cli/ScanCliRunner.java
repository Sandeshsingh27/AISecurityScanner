package com.aisecurityscanner.cli;

import com.aisecurityscanner.config.ScannerProperties;
import com.aisecurityscanner.model.QualityGateStatus;
import com.aisecurityscanner.model.SecurityScanReport;
import com.aisecurityscanner.service.MarkdownReportRenderer;
import com.aisecurityscanner.service.ScanOrchestratorService;
import com.aisecurityscanner.web.dto.ScanRequest;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

@Component
public class ScanCliRunner implements ApplicationRunner {

    private final ScannerProperties properties;
    private final ScanOrchestratorService scanOrchestratorService;
    private final MarkdownReportRenderer markdownReportRenderer;

    public ScanCliRunner(ScannerProperties properties,
                         ScanOrchestratorService scanOrchestratorService,
                         MarkdownReportRenderer markdownReportRenderer) {
        this.properties = properties;
        this.scanOrchestratorService = scanOrchestratorService;
        this.markdownReportRenderer = markdownReportRenderer;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!properties.getCli().isEnabled()) {
            return;
        }

        ScanRequest request = new ScanRequest();
        request.setTargetPath(properties.getCli().getTargetPath());
        request.setSemgrepConfig(properties.getSemgrep().getDefaultConfig());
        request.setLlmEnabled(properties.getLlm().isEnabled());
        request.setIncludeDependencyAudit(true);
        request.setMaxFindingsForLlm(properties.getReport().getMaxFindingsForLlm());
        request.setExternalFindings(new ArrayList<com.aisecurityscanner.web.dto.ExternalFindingRequest>());

        SecurityScanReport report = scanOrchestratorService.scan(request);
        printToStdout(markdownReportRenderer.render(report));

        if (properties.getCli().isFailOnQualityGate() && report.getQualityGateStatus() == QualityGateStatus.FAILED) {
            throw new IllegalStateException("Quality gate failed.");
        }
    }

    private void printToStdout(String content) {
        PrintWriter writer = new PrintWriter(new OutputStreamWriter(new FileOutputStream(FileDescriptor.out), StandardCharsets.UTF_8), true);
        writer.println(content);
        writer.flush();
    }
}
