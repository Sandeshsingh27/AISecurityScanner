package com.aisecurityscanner.service;

import com.aisecurityscanner.model.ComplexityHotspot;
import com.aisecurityscanner.model.DependencyFinding;
import com.aisecurityscanner.model.QualityGateMetric;
import com.aisecurityscanner.model.SecurityFinding;
import com.aisecurityscanner.model.SecurityScanReport;
import com.aisecurityscanner.model.Severity;
import com.aisecurityscanner.model.StackType;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;

@Service
public class MarkdownReportRenderer {

    public String render(SecurityScanReport report) {
        StringBuilder builder = new StringBuilder();
        builder.append("---\n\n");
        builder.append("# 🔒 Security & Quality Scan Report\n\n");
        builder.append("**Scanned:** `").append(report.getProjectPath()).append("`\n");
        builder.append("**Date:** `").append(report.getDate()).append("`\n");
        builder.append("**Stacks Detected:** `").append(report.getStacksDetected().stream().map(StackType::getDisplayName).collect(Collectors.joining(" | "))).append("`\n");
        builder.append("**Files Scanned:** `").append(report.getFilesScanned()).append("`\n\n");
        builder.append("---\n\n");
        builder.append("## Quality Gate: ").append(report.getQualityGateStatus().toEmojiLabel()).append("\n\n");
        builder.append("| Metric | Value | Threshold | Status |\n");
        builder.append("|---|---|---|---|\n");
        for (QualityGateMetric metric : report.getQualityGateMetrics()) {
            builder.append("| ").append(metric.getName())
                .append(" | ").append(metric.getValue())
                .append(" | ").append(metric.getThreshold())
                .append(" | ").append(metric.isPassed() ? "✅" : "❌")
                .append(" |\n");
        }
        builder.append("\n---\n\n");
        builder.append("## Findings\n\n");
        appendQualityProfile(builder, report.getFindings());
        appendDetailedFindings(builder, report.getFindings(), Severity.CRITICAL);
        appendDetailedFindings(builder, report.getFindings(), Severity.HIGH);
        appendMediumFindings(builder, report.getFindings());
        appendCategoryTable(builder, "🐞 Bugs", report.getFindings(), "Bug");
        appendCategoryTable(builder, "🔥 Security Hotspots (manual review)", report.getFindings(), "Security Hotspot");
        appendCategoryTable(builder, "💨 Code Smells", report.getFindings(), "Code Smell");
        appendCompactLowAndInfo(builder, report.getFindings());
        builder.append("\n---\n\n");
        builder.append("## Dependency Audit\n\n");
        builder.append("| Package | Current Version | Vulnerable | CVE | Severity |\n");
        builder.append("|---|---|---|---|---|\n");
        for (DependencyFinding finding : report.getDependencyAudit()) {
            builder.append("| `").append(finding.getPackageName()).append("` | `").append(finding.getCurrentVersion())
                .append("` | `< ").append(finding.getVulnerableBelow())
                .append("` | ").append(finding.getCve())
                .append(" | ").append(toSeverityBadge(finding.getSeverity())).append(" |\n");
        }
        if (report.getDependencyAudit().isEmpty()) {
            builder.append("| None | - | - | - | - |\n");
        }
        builder.append("\n---\n\n");
        builder.append("## Complexity Hotspots\n\n");
        builder.append("| File | Method | Complexity | Rating |\n");
        builder.append("|---|---|---|---|\n");
        for (ComplexityHotspot hotspot : report.getComplexityHotspots()) {
            builder.append("| `").append(hotspot.getFilePath()).append("` | `").append(hotspot.getMethod())
                .append("()` | ").append(hotspot.getComplexity())
                .append(" | ").append(toSeverityBadge(hotspot.getRating())).append(" |\n");
        }
        if (report.getComplexityHotspots().isEmpty()) {
            builder.append("| None | - | - | - |\n");
        }
        builder.append("\n---\n\n");
        builder.append("## Recommended Fix Order\n\n");
        builder.append("1. 🔴 CRITICAL — Resolve all C-### findings before any deployment\n");
        builder.append("2. 🟠 HIGH — Address H-### within current sprint\n");
        builder.append("3. 🟡 MEDIUM — Schedule M-### for next sprint\n");
        builder.append("4. 🔵 LOW / ⚪ — Track in backlog\n");
        return builder.toString();
    }

    private void appendDetailedFindings(StringBuilder builder, List<SecurityFinding> findings, Severity severity) {
        builder.append("### ").append(severity.toEmojiLabel()).append("\n\n");
        List<SecurityFinding> scoped = findings.stream().filter(finding -> finding.getSeverity() == severity).collect(Collectors.toList());
        if (scoped.isEmpty()) {
            builder.append("None.\n\n");
            return;
        }
        for (SecurityFinding finding : scoped) {
            builder.append("#### [").append(finding.getId()).append("] ").append(finding.getTitle()).append("\n");
            builder.append("- **File:** `").append(finding.getFilePath()).append(":").append(finding.getLine()).append("`\n");
            builder.append("- **Rule:** ").append(finding.getRule()).append("\n");
            builder.append("- **Stack:** ").append(finding.getStack().getDisplayName()).append("\n");
            builder.append("- **Evidence:**\n");
            builder.append("  ```text\n").append(nullSafe(finding.getEvidence())).append("\n  ```\n");
            builder.append("- **Taint Chain:** `").append(nullSafe(finding.getTaintChain())).append("`\n");
            builder.append("- **Fix:** ").append(nullSafe(finding.getFix())).append("\n");
            if (!nullSafe(finding.getExplanation()).isEmpty()) {
                builder.append("- **Explanation:** ").append(finding.getExplanation()).append("\n");
            }
            if (!nullSafe(finding.getSuggestedCode()).isEmpty()) {
                builder.append("- **Suggested Code:**\n");
                builder.append("  ```text\n").append(finding.getSuggestedCode()).append("\n  ```\n");
            }
            builder.append("\n---\n\n");
        }
    }

    private void appendQualityProfile(StringBuilder builder, List<SecurityFinding> findings) {
        String[] categories = {"Vulnerability", "Bug", "Security Hotspot", "Code Smell", "Hardcoded Secret"};
        String[] icons = {"🛡️ Vulnerabilities", "🐞 Bugs", "🔥 Security Hotspots", "💨 Code Smells", "🔑 Hardcoded Secrets"};
        Severity[] severities = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO};
        builder.append("### 📊 Quality Profile (SonarQube-style)\n\n");
        builder.append("| Category | 🔴 Critical | 🟠 High | 🟡 Medium | 🔵 Low | ⚪ Info | Total |\n");
        builder.append("|---|---|---|---|---|---|---|\n");
        long grandTotal = 0;
        for (int i = 0; i < categories.length; i++) {
            String category = categories[i];
            long total = 0;
            builder.append("| ").append(icons[i]);
            for (Severity severity : severities) {
                final String cat = category;
                final Severity sev = severity;
                long count = findings.stream()
                    .filter(f -> cat.equals(f.getCategory()) && f.getSeverity() == sev)
                    .count();
                total += count;
                builder.append(" | ").append(count);
            }
            builder.append(" | **").append(total).append("** |\n");
            grandTotal += total;
        }
        builder.append("| **Total** | | | | | | **").append(grandTotal).append("** |\n\n");
    }

    private void appendMediumFindings(StringBuilder builder, List<SecurityFinding> findings) {
        List<SecurityFinding> medium = findings.stream()
            .filter(f -> f.getSeverity() == Severity.MEDIUM)
            .collect(Collectors.toList());
        builder.append("### 🟡 MEDIUM\n\n");
        if (medium.isEmpty()) {
            builder.append("None.\n\n");
            return;
        }
        // If many, render as compact table to keep the report readable.
        if (medium.size() > 10) {
            builder.append("_Showing ").append(medium.size()).append(" medium findings (compact view)._\n\n");
            builder.append("| ID | Category | File | Line | Rule | Finding |\n");
            builder.append("|---|---|---|---|---|---|\n");
            for (SecurityFinding finding : medium) {
                builder.append("| ").append(finding.getId())
                    .append(" | ").append(nullSafe(finding.getCategory()))
                    .append(" | `").append(finding.getFilePath()).append("` | ").append(finding.getLine())
                    .append(" | ").append(nullSafe(finding.getRule()))
                    .append(" | ").append(escapeCell(finding.getTitle()))
                    .append(" |\n");
            }
            builder.append("\n");
            return;
        }
        appendDetailedFindings(builder, findings, Severity.MEDIUM);
    }

    private void appendCategoryTable(StringBuilder builder, String header, List<SecurityFinding> findings, String category) {
        List<SecurityFinding> scoped = findings.stream()
            .filter(f -> category.equals(f.getCategory()))
            .filter(f -> f.getSeverity() != Severity.CRITICAL && f.getSeverity() != Severity.HIGH) // already shown above
            .collect(Collectors.toList());
        builder.append("### ").append(header).append("\n\n");
        if (scoped.isEmpty()) {
            builder.append("None.\n\n");
            return;
        }
        builder.append("| ID | Severity | File | Line | Rule | Finding |\n");
        builder.append("|---|---|---|---|---|---|\n");
        int maxRows = 80;
        int shown = 0;
        for (SecurityFinding finding : scoped) {
            if (shown >= maxRows) {
                builder.append("| … | … | … | … | … | _").append(scoped.size() - shown).append(" more truncated_ |\n");
                break;
            }
            builder.append("| ").append(finding.getId())
                .append(" | ").append(toSeverityBadge(finding.getSeverity()))
                .append(" | `").append(finding.getFilePath()).append("` | ").append(finding.getLine())
                .append(" | ").append(nullSafe(finding.getRule()))
                .append(" | ").append(escapeCell(finding.getTitle()))
                .append(" |\n");
            shown++;
        }
        builder.append("\n");
    }

    private String escapeCell(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("|", "\\|").replace("\n", " ").replace("\r", " ");
    }

    private void appendCompactLowAndInfo(StringBuilder builder, List<SecurityFinding> findings) {
        builder.append("### 🔵 LOW / ⚪ INFO\n\n");
        List<SecurityFinding> scoped = findings.stream()
            .filter(finding -> finding.getSeverity() == Severity.LOW || finding.getSeverity() == Severity.INFO)
            // Skip ones already listed under a category table to avoid duplication.
            .filter(finding -> finding.getCategory() == null
                || (!"Bug".equals(finding.getCategory())
                    && !"Code Smell".equals(finding.getCategory())
                    && !"Security Hotspot".equals(finding.getCategory())))
            .collect(Collectors.toList());
        builder.append("| ID | File | Line | Rule | Finding |\n");
        builder.append("|---|---|---|---|---|\n");
        int maxRows = 100;
        int shown = 0;
        for (SecurityFinding finding : scoped) {
            if (shown >= maxRows) {
                builder.append("| … | … | … | … | _").append(scoped.size() - shown).append(" more truncated_ |\n");
                break;
            }
            builder.append("| ").append(finding.getId())
                .append(" | `").append(finding.getFilePath()).append("` | ").append(finding.getLine())
                .append(" | ").append(nullSafe(finding.getRule()))
                .append(" | ").append(escapeCell(finding.getTitle()))
                .append(" |\n");
            shown++;
        }
        if (scoped.isEmpty()) {
            builder.append("| - | - | - | - | No additional low/info findings |\n");
        }
        builder.append("\n");
    }

    private String toSeverityBadge(Severity severity) {
        switch (severity) {
            case CRITICAL:
                return "🔴 CRITICAL";
            case HIGH:
                return "🟠 HIGH";
            case MEDIUM:
                return "🟡 MEDIUM";
            case LOW:
                return "🔵 LOW";
            default:
                return "⚪ INFO";
        }
    }

    private String nullSafe(String value) {
        return value == null ? "" : value;
    }
}
