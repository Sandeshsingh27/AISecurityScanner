package com.aisecurityscanner.web.dto;

import com.aisecurityscanner.model.Severity;
import com.aisecurityscanner.model.StackType;

public class ExternalFindingRequest {

    private String id;
    private String title;
    private Severity severity;
    private String filePath;
    private Integer line;
    private String rule;
    private StackType stack = StackType.UNKNOWN;
    private String evidence;
    private String taintChain;
    private String fix;

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

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public Integer getLine() {
        return line;
    }

    public void setLine(Integer line) {
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
}

