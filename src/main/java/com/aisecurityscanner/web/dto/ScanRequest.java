package com.aisecurityscanner.web.dto;

import java.util.ArrayList;
import java.util.List;
import jakarta.validation.constraints.NotBlank;

public class ScanRequest {

    @NotBlank
    private String targetPath;
    private String semgrepConfig = "auto";
    private boolean llmEnabled;
    private boolean includeDependencyAudit = true;
    private int maxFindingsForLlm = 15;
    private List<ExternalFindingRequest> externalFindings = new ArrayList<ExternalFindingRequest>();

    public String getTargetPath() {
        return targetPath;
    }

    public void setTargetPath(String targetPath) {
        this.targetPath = targetPath;
    }

    public String getSemgrepConfig() {
        return semgrepConfig;
    }

    public void setSemgrepConfig(String semgrepConfig) {
        this.semgrepConfig = semgrepConfig;
    }

    public boolean isLlmEnabled() {
        return llmEnabled;
    }

    public void setLlmEnabled(boolean llmEnabled) {
        this.llmEnabled = llmEnabled;
    }

    public boolean isIncludeDependencyAudit() {
        return includeDependencyAudit;
    }

    public void setIncludeDependencyAudit(boolean includeDependencyAudit) {
        this.includeDependencyAudit = includeDependencyAudit;
    }

    public int getMaxFindingsForLlm() {
        return maxFindingsForLlm;
    }

    public void setMaxFindingsForLlm(int maxFindingsForLlm) {
        this.maxFindingsForLlm = maxFindingsForLlm;
    }

    public List<ExternalFindingRequest> getExternalFindings() {
        return externalFindings;
    }

    public void setExternalFindings(List<ExternalFindingRequest> externalFindings) {
        this.externalFindings = externalFindings;
    }
}

