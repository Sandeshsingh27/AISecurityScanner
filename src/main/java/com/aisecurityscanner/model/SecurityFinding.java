package com.aisecurityscanner.model;

public class SecurityFinding {

    private String id;
    private String title;
    private String filePath;
    private int line;
    private String rule;
    private StackType stack;
    private Severity severity;
    private String evidence;
    private String taintChain;
    private String fix;
    private String explanation;
    private boolean verifiedByLlm;
    private String suggestedCode;
    private String vulnerabilityType;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public int getLine() {
        return line;
    }

    public void setLine(int line) {
        this.line = line;
    }

    public String getRule() {
        return rule;
    }

    public void setRule(String rule) {
        this.rule = rule;
    }

    public StackType getStack() {
        return stack;
    }

    public void setStack(StackType stack) {
        this.stack = stack;
    }

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public String getEvidence() {
        return evidence;
    }

    public void setEvidence(String evidence) {
        this.evidence = evidence;
    }

    public String getTaintChain() {
        return taintChain;
    }

    public void setTaintChain(String taintChain) {
        this.taintChain = taintChain;
    }

    public String getFix() {
        return fix;
    }

    public void setFix(String fix) {
        this.fix = fix;
    }

    public String getExplanation() {
        return explanation;
    }

    public void setExplanation(String explanation) {
        this.explanation = explanation;
    }

    public boolean isVerifiedByLlm() {
        return verifiedByLlm;
    }

    public void setVerifiedByLlm(boolean verifiedByLlm) {
        this.verifiedByLlm = verifiedByLlm;
    }

    public String getSuggestedCode() {
        return suggestedCode;
    }

    public void setSuggestedCode(String suggestedCode) {
        this.suggestedCode = suggestedCode;
    }

    public String getVulnerabilityType() {
        return vulnerabilityType;
    }

    public void setVulnerabilityType(String vulnerabilityType) {
        this.vulnerabilityType = vulnerabilityType;
    }
}

