package com.aisecurityscanner.model;

public class TriageResult {

    private boolean exploitable;
    private String explanation;
    private String fix;
    private String suggestedCode;
    private boolean llmVerified;

    public boolean isExploitable() {
        return exploitable;
    }

    public void setExploitable(boolean exploitable) {
        this.exploitable = exploitable;
    }

    public String getExplanation() {
        return explanation;
    }

    public void setExplanation(String explanation) {
        this.explanation = explanation;
    }

    public String getFix() {
        return fix;
    }

    public void setFix(String fix) {
        this.fix = fix;
    }

    public String getSuggestedCode() {
        return suggestedCode;
    }

    public void setSuggestedCode(String suggestedCode) {
        this.suggestedCode = suggestedCode;
    }

    public boolean isLlmVerified() {
        return llmVerified;
    }

    public void setLlmVerified(boolean llmVerified) {
        this.llmVerified = llmVerified;
    }
}

