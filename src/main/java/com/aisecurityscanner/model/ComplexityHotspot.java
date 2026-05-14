package com.aisecurityscanner.model;

public class ComplexityHotspot {

    private String filePath;
    private String method;
    private int complexity;
    private Severity rating;

    public ComplexityHotspot() {
    }

    public ComplexityHotspot(String filePath, String method, int complexity, Severity rating) {
        this.filePath = filePath;
        this.method = method;
        this.complexity = complexity;
        this.rating = rating;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public int getComplexity() {
        return complexity;
    }

    public void setComplexity(int complexity) {
        this.complexity = complexity;
    }

    public Severity getRating() {
        return rating;
    }

    public void setRating(Severity rating) {
        this.rating = rating;
    }
}

