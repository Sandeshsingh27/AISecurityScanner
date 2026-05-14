package com.aisecurityscanner.model;

public class DependencyFinding {

    private String packageName;
    private String currentVersion;
    private String vulnerableBelow;
    private String cve;
    private Severity severity;

    public DependencyFinding() {
    }

    public DependencyFinding(String packageName, String currentVersion, String vulnerableBelow, String cve, Severity severity) {
        this.packageName = packageName;
        this.currentVersion = currentVersion;
        this.vulnerableBelow = vulnerableBelow;
        this.cve = cve;
        this.severity = severity;
    }

    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    public String getCurrentVersion() {
        return currentVersion;
    }

    public void setCurrentVersion(String currentVersion) {
        this.currentVersion = currentVersion;
    }

    public String getVulnerableBelow() {
        return vulnerableBelow;
    }

    public void setVulnerableBelow(String vulnerableBelow) {
        this.vulnerableBelow = vulnerableBelow;
    }

    public String getCve() {
        return cve;
    }

    public void setCve(String cve) {
        this.cve = cve;
    }

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }
}

