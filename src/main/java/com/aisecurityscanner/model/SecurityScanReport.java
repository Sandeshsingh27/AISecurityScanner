package com.aisecurityscanner.model;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

public class SecurityScanReport {

    private String projectPath;
    private LocalDate date;
    private List<StackType> stacksDetected = new ArrayList<StackType>();
    private int filesScanned;
    private QualityGateStatus qualityGateStatus;
    private List<QualityGateMetric> qualityGateMetrics = new ArrayList<QualityGateMetric>();
    private List<SecurityFinding> findings = new ArrayList<SecurityFinding>();
    private List<DependencyFinding> dependencyAudit = new ArrayList<DependencyFinding>();
    private List<ComplexityHotspot> complexityHotspots = new ArrayList<ComplexityHotspot>();
    private List<String> attackSurface = new ArrayList<String>();

    public String getProjectPath() {
        return projectPath;
    }

    public void setProjectPath(String projectPath) {
        this.projectPath = projectPath;
    }

    public LocalDate getDate() {
        return date;
    }

    public void setDate(LocalDate date) {
        this.date = date;
    }

    public List<StackType> getStacksDetected() {
        return stacksDetected;
    }

    public void setStacksDetected(List<StackType> stacksDetected) {
        this.stacksDetected = stacksDetected;
    }

    public int getFilesScanned() {
        return filesScanned;
    }

    public void setFilesScanned(int filesScanned) {
        this.filesScanned = filesScanned;
    }

    public QualityGateStatus getQualityGateStatus() {
        return qualityGateStatus;
    }

    public void setQualityGateStatus(QualityGateStatus qualityGateStatus) {
        this.qualityGateStatus = qualityGateStatus;
    }

    public List<QualityGateMetric> getQualityGateMetrics() {
        return qualityGateMetrics;
    }

    public void setQualityGateMetrics(List<QualityGateMetric> qualityGateMetrics) {
        this.qualityGateMetrics = qualityGateMetrics;
    }

    public List<SecurityFinding> getFindings() {
        return findings;
    }

    public void setFindings(List<SecurityFinding> findings) {
        this.findings = findings;
    }

    public List<DependencyFinding> getDependencyAudit() {
        return dependencyAudit;
    }

    public void setDependencyAudit(List<DependencyFinding> dependencyAudit) {
        this.dependencyAudit = dependencyAudit;
    }

    public List<ComplexityHotspot> getComplexityHotspots() {
        return complexityHotspots;
    }

    public void setComplexityHotspots(List<ComplexityHotspot> complexityHotspots) {
        this.complexityHotspots = complexityHotspots;
    }

    public List<String> getAttackSurface() {
        return attackSurface;
    }

    public void setAttackSurface(List<String> attackSurface) {
        this.attackSurface = attackSurface;
    }
}

