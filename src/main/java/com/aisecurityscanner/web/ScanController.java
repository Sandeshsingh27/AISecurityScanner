package com.aisecurityscanner.web;

import com.aisecurityscanner.model.SecurityScanReport;
import com.aisecurityscanner.service.MarkdownReportRenderer;
import com.aisecurityscanner.service.ScanOrchestratorService;
import com.aisecurityscanner.web.dto.ScanRequest;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/scans")
public class ScanController {

    private final ScanOrchestratorService scanOrchestratorService;
    private final MarkdownReportRenderer markdownReportRenderer;

    public ScanController(ScanOrchestratorService scanOrchestratorService, MarkdownReportRenderer markdownReportRenderer) {
        this.scanOrchestratorService = scanOrchestratorService;
        this.markdownReportRenderer = markdownReportRenderer;
    }

    @PostMapping(path = "/report", produces = MediaType.APPLICATION_JSON_VALUE)
    public SecurityScanReport generateReport(@Valid @RequestBody ScanRequest request) {
        return scanOrchestratorService.scan(request);
    }

    @PostMapping(path = "/report/markdown", produces = "text/markdown")
    public String generateMarkdownReport(@Valid @RequestBody ScanRequest request) {
        SecurityScanReport report = scanOrchestratorService.scan(request);
        return markdownReportRenderer.render(report);
    }
}
