package com.aisecurityscanner.service;

import com.aisecurityscanner.config.ScannerProperties;
import com.aisecurityscanner.model.ComplexityHotspot;
import com.aisecurityscanner.model.DependencyFinding;
import com.aisecurityscanner.model.SecurityScanReport;
import com.aisecurityscanner.model.SemgrepFinding;
import com.aisecurityscanner.model.StackType;
import com.aisecurityscanner.model.TriageResult;
import com.aisecurityscanner.web.dto.ScanRequest;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;

@Service
public class ScanOrchestratorService {

    private final ScannerProperties properties;
    private final ProjectDiscoveryService projectDiscoveryService;
    private final SemgrepService semgrepService;
    private final ContextSnippetService contextSnippetService;
    private final LlmTriageService llmTriageService;
    private final DependencyAuditService dependencyAuditService;
    private final ComplexityAnalyzerService complexityAnalyzerService;
    private final ReportAssemblerService reportAssemblerService;

    public ScanOrchestratorService(ScannerProperties properties,
                                   ProjectDiscoveryService projectDiscoveryService,
                                   SemgrepService semgrepService,
                                   ContextSnippetService contextSnippetService,
                                   LlmTriageService llmTriageService,
                                   DependencyAuditService dependencyAuditService,
                                   ComplexityAnalyzerService complexityAnalyzerService,
                                   ReportAssemblerService reportAssemblerService) {
        this.properties = properties;
        this.projectDiscoveryService = projectDiscoveryService;
        this.semgrepService = semgrepService;
        this.contextSnippetService = contextSnippetService;
        this.llmTriageService = llmTriageService;
        this.dependencyAuditService = dependencyAuditService;
        this.complexityAnalyzerService = complexityAnalyzerService;
        this.reportAssemblerService = reportAssemblerService;
    }

    public SecurityScanReport scan(ScanRequest request) {
        Path targetPath = Paths.get(request.getTargetPath()).toAbsolutePath().normalize();
        if (!Files.exists(targetPath)) {
            throw new IllegalArgumentException("Target path does not exist: " + targetPath);
        }

        Set<StackType> stacks = projectDiscoveryService.detectStacks(targetPath);
        int filesScanned = projectDiscoveryService.countFiles(targetPath);
        List<String> attackSurface = projectDiscoveryService.discoverAttackSurface(targetPath);
        List<SemgrepFinding> semgrepFindings = semgrepService.scan(targetPath, request.getSemgrepConfig());

        List<TriageResult> triageResults = new ArrayList<TriageResult>();
        int llmLimit = request.getMaxFindingsForLlm() > 0 ? request.getMaxFindingsForLlm() : properties.getReport().getMaxFindingsForLlm();
        for (int i = 0; i < semgrepFindings.size(); i++) {
            SemgrepFinding finding = semgrepFindings.get(i);
            String context = contextSnippetService.extract(targetPath, finding.getFilePath(), finding.getLine(), properties.getReport().getContextLines());
            if ((finding.getRawSnippet() == null || finding.getRawSnippet().trim().isEmpty()) && context != null && !context.isEmpty()) {
                finding.setRawSnippet(context);
            }
            triageResults.add(llmTriageService.triage(finding, context, request.isLlmEnabled() && i < llmLimit));
        }

        List<DependencyFinding> dependencyFindings = request.isIncludeDependencyAudit()
            ? dependencyAuditService.audit(targetPath)
            : new ArrayList<DependencyFinding>();
        List<ComplexityHotspot> complexityHotspots = complexityAnalyzerService.analyze(targetPath).stream()
            .sorted((left, right) -> Integer.compare(right.getComplexity(), left.getComplexity()))
            .limit(10)
            .collect(Collectors.toList());

        return reportAssemblerService.assemble(
            targetPath.toString(),
            new ArrayList<StackType>(stacks),
            filesScanned,
            attackSurface,
            semgrepFindings,
            triageResults,
            request.getExternalFindings() == null ? new ArrayList<com.aisecurityscanner.web.dto.ExternalFindingRequest>() : request.getExternalFindings(),
            dependencyFindings,
            complexityHotspots
        );
    }
}
