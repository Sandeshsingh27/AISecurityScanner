package com.aisecurityscanner.service;

import com.aisecurityscanner.config.ScannerProperties;
import com.aisecurityscanner.model.Severity;
import com.aisecurityscanner.model.StackType;
import com.aisecurityscanner.web.dto.ExternalFindingRequest;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class AgentFindingService {

    private final ScannerProperties properties;
    private final ObjectMapper objectMapper;

    public AgentFindingService(ScannerProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    public List<ExternalFindingRequest> collect(Path targetPath, boolean requestEnabled, String requestCommandOverride) {
        if (!requestEnabled && !properties.getAgent().isEnabled()) {
            return new ArrayList<ExternalFindingRequest>();
        }

        String command = StringUtils.hasText(requestCommandOverride)
            ? requestCommandOverride.trim()
            : properties.getAgent().getCommand();

        if (!StringUtils.hasText(command)) {
            return new ArrayList<ExternalFindingRequest>();
        }

        boolean usesPlaceholder = command.contains("{targetPath}");
        String rendered = command.replace("{targetPath}", quoteForPowerShell(targetPath.toAbsolutePath().toString()));
        if (!usesPlaceholder) {
            rendered = rendered + " " + quoteForPowerShell(targetPath.toAbsolutePath().toString());
        }

        List<String> processCommand = new ArrayList<String>();
        processCommand.add("powershell.exe");
        processCommand.add("-NoProfile");
        processCommand.add("-Command");
        processCommand.add(rendered);

        try {
            // External agent execution is an explicit feature; command is assembled with quoted targetPath.
            Process process = new ProcessBuilder(processCommand).start(); // nosemgrep: semgrep-rules.java-processbuilder-user-input
            boolean finished = process.waitFor(properties.getAgent().getTimeoutSeconds(), TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                throw new IllegalStateException("External security agent timed out after " + properties.getAgent().getTimeoutSeconds() + " seconds");
            }

            String stdout = read(process.getInputStream());
            String stderr = read(process.getErrorStream());
            int exitCode = process.exitValue();
            if (exitCode != 0) {
                throw new IllegalStateException("External security agent failed with exit code " + exitCode + ": " + stderr);
            }
            return parseFindings(stdout);
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to execute external security agent command: " + command, ex);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("External security agent execution was interrupted", ex);
        }
    }

    private List<ExternalFindingRequest> parseFindings(String output) {
        List<ExternalFindingRequest> findings = new ArrayList<ExternalFindingRequest>();
        if (!StringUtils.hasText(output)) {
            return findings;
        }

        try {
            JsonNode root = objectMapper.readTree(output);
            JsonNode list = root.isArray() ? root : root.path("findings");
            if (!list.isArray()) {
                return findings;
            }
            for (JsonNode node : list) {
                ExternalFindingRequest finding = new ExternalFindingRequest();
                finding.setId(text(node, "id", "EXT-UNKNOWN"));
                finding.setTitle(text(node, "title", "Imported external finding"));
                finding.setFilePath(text(node, "filePath", text(node, "file", "unknown")));
                finding.setLine(number(node, "line", 1));
                finding.setRule(text(node, "rule", "External Agent Rule"));
                finding.setEvidence(text(node, "evidence", ""));
                finding.setTaintChain(text(node, "taintChain", ""));
                finding.setFix(text(node, "fix", "Review and remediate according to external agent guidance."));
                finding.setSeverity(parseSeverity(text(node, "severity", "MEDIUM")));
                finding.setStack(parseStack(text(node, "stack", "UNKNOWN")));
                findings.add(finding);
            }
            return findings;
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to parse external security agent output. Expected JSON array or object with 'findings'.", ex);
        }
    }

    private String text(JsonNode node, String field, String fallback) {
        String value = node.path(field).asText("").trim();
        return value.isEmpty() ? fallback : value;
    }

    private int number(JsonNode node, String field, int fallback) {
        return node.path(field).asInt(fallback);
    }

    private Severity parseSeverity(String value) {
        try {
            return Severity.valueOf(value.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return Severity.MEDIUM;
        }
    }

    private StackType parseStack(String value) {
        try {
            return StackType.valueOf(value.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return StackType.UNKNOWN;
        }
    }

    private String quoteForPowerShell(String value) {
        return "'" + value.replace("'", "''") + "'";
    }

    private String read(InputStream inputStream) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8));
        StringBuilder builder = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            builder.append(line).append('\n');
        }
        return builder.toString();
    }
}


