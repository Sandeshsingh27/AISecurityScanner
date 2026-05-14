package com.aisecurityscanner.model;

public class QualityGateMetric {

    private String name;
    private String value;
    private String threshold;
    private boolean passed;

    public QualityGateMetric() {
    }

    public QualityGateMetric(String name, String value, String threshold, boolean passed) {
        this.name = name;
        this.value = value;
        this.threshold = threshold;
        this.passed = passed;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getThreshold() {
        return threshold;
    }

    public void setThreshold(String threshold) {
        this.threshold = threshold;
    }

    public boolean isPassed() {
        return passed;
    }

    public void setPassed(boolean passed) {
        this.passed = passed;
    }
}

