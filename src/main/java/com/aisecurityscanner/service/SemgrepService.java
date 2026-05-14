package com.aisecurityscanner.service;

import com.aisecurityscanner.config.ScannerProperties;
import com.aisecurityscanner.model.SemgrepFinding;
import com.aisecurityscanner.model.Severity;
import com.aisecurityscanner.model.StackType;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import org.springframework.stereotype.Service;

@Service
public class SemgrepService {

    private final ScannerProperties properties;
    private final ObjectMapper objectMapper;

    public SemgrepService(ScannerProperties properties, ObjectMapper objectMapper) {
        this.properties = properties;
        this.objectMapper = objectMapper;
    }

    public List<SemgrepFinding> scan(Path targetPath, String semgrepConfig) {
        String configToUse = semgrepConfig == null || semgrepConfig.trim().isEmpty()
            ? properties.getSemgrep().getDefaultConfig()
            : semgrepConfig.trim();

        List<List<String>> commandCandidates = buildCommandCandidates();
        List<String> failures = new ArrayList<String>();
        for (List<String> commandPrefix : commandCandidates) {
            List<String> command = new ArrayList<String>(commandPrefix);
            command.addAll(Arrays.asList(
                "scan",
                "--config",
                configToUse,
                "--json",
                targetPath.toAbsolutePath().toString()
            ));
            try {
                CommandExecutionResult result = executeCommand(command);
                if (result.exitCode != 0 && result.exitCode != 1) {
                    failures.add(String.join(" ", commandPrefix) + " -> exit code " + result.exitCode + ": " + result.stderr.trim());
                    continue;
                }
                return parse(result.stdout);
            } catch (IOException ex) {
                failures.add(String.join(" ", commandPrefix) + " -> " + ex.getMessage());
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Semgrep scan was interrupted", ex);
            }
        }
        throw new IllegalStateException("Failed to execute Semgrep. Tried multiple launch commands: " + String.join(" | ", failures));
    }

    private List<List<String>> buildCommandCandidates() {
        List<List<String>> commands = new ArrayList<List<String>>();
        String configured = properties.getSemgrep().getCommand();
        commands.add(Arrays.asList(configured));

        Path venvSemgrep = Path.of(".venv", "Scripts", "semgrep.exe").toAbsolutePath().normalize();
        if (Files.exists(venvSemgrep)) {
            commands.add(Arrays.asList(venvSemgrep.toString()));
        }

        commands.add(Arrays.asList("python", "-m", "semgrep"));
        return commands;
    }

    private CommandExecutionResult executeCommand(List<String> command) throws IOException, InterruptedException {
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.redirectErrorStream(false);
        Process process = processBuilder.start();
        boolean finished = process.waitFor(properties.getSemgrep().getTimeoutSeconds(), TimeUnit.SECONDS);
        if (!finished) {
            process.destroyForcibly();
            throw new IllegalStateException("Semgrep scan timed out after " + properties.getSemgrep().getTimeoutSeconds() + " seconds");
        }
        CommandExecutionResult result = new CommandExecutionResult();
        result.stdout = read(process.getInputStream());
        result.stderr = read(process.getErrorStream());
        result.exitCode = process.exitValue();
        return result;
    }

    private static class CommandExecutionResult {
        private String stdout;
        private String stderr;
        private int exitCode;
    }

    List<SemgrepFinding> parse(String json) {
        List<SemgrepFinding> findings = new ArrayList<SemgrepFinding>();
        try {
            JsonNode root = objectMapper.readTree(json);
            JsonNode results = root.path("results");
            if (!results.isArray()) {
                return findings;
            }
            for (JsonNode result : results) {
                SemgrepFinding finding = new SemgrepFinding();
                finding.setCheckId(result.path("check_id").asText("unknown-check"));
                finding.setTitle(defaultTitle(result));
                finding.setFilePath(result.path("path").asText());
                finding.setLine(result.path("start").path("line").asInt(1));
                finding.setEndLine(result.path("end").path("line").asInt(finding.getLine()));
                finding.setMessage(result.path("extra").path("message").asText("Potential vulnerability detected"));
                finding.setRule(buildRule(result));
                finding.setSeverity(mapSeverity(result.path("extra").path("severity").asText("INFO"), finding.getCheckId(), finding.getMessage()));
                finding.setRawSnippet(result.path("extra").path("lines").asText(""));
                finding.setCwe(result.path("extra").path("metadata").path("cwe").asText(""));
                finding.setVulnerabilityType(classifyVulnerabilityType(finding));
                finding.setStack(detectStackFromPath(finding.getFilePath()));
                findings.add(finding);
            }
            return findings;
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to parse Semgrep JSON output", ex);
        }
    }

    private String defaultTitle(JsonNode result) {
        String message = result.path("extra").path("message").asText("");
        if (!message.isEmpty()) {
            return message;
        }
        return result.path("check_id").asText("Semgrep Finding");
    }

    private String buildRule(JsonNode result) {
        String cwe = result.path("extra").path("metadata").path("cwe").asText("");
        String owasp = result.path("extra").path("metadata").path("owasp").asText("");
        String check = result.path("check_id").asText("semgrep");
        StringBuilder builder = new StringBuilder();
        if (!owasp.isEmpty()) {
            builder.append(owasp);
        }
        if (!cwe.isEmpty()) {
            if (builder.length() > 0) {
                builder.append(" / ");
            }
            builder.append(cwe);
        }
        if (builder.length() == 0) {
            builder.append(check);
        }
        return builder.toString();
    }

    private Severity mapSeverity(String semgrepSeverity, String checkId, String message) {
        String text = (semgrepSeverity + " " + checkId + " " + message).toLowerCase(Locale.ROOT);
        if (text.contains("critical") || text.contains("rce") || text.contains("remote code") || text.contains("hardcoded secret")) {
            return Severity.CRITICAL;
        }
        if (text.contains("error") || text.contains("high") || text.contains("sql injection") || text.contains("xss") || text.contains("idor") || text.contains("path traversal")) {
            return Severity.HIGH;
        }
        if (text.contains("warning") || text.contains("medium") || text.contains("csrf") || text.contains("misconfig") || text.contains("token")) {
            return Severity.MEDIUM;
        }
        if (text.contains("info") || text.contains("low")) {
            return Severity.LOW;
        }
        return Severity.MEDIUM;
    }

    private String classifyVulnerabilityType(SemgrepFinding finding) {
        String text = (finding.getCheckId() + " " + finding.getMessage()).toLowerCase(Locale.ROOT);
        if (text.contains("sql")) {
            return "SQL Injection";
        }
        if (text.contains("xss") || text.contains("html")) {
            return "Cross-Site Scripting";
        }
        if (text.contains("secret") || text.contains("password") || text.contains("apikey") || text.contains("api key")) {
            return "Hardcoded Secret";
        }
        if (text.contains("auth") || text.contains("permission") || text.contains("idor") || text.contains("access")) {
            return "Broken Access Control";
        }
        if (text.contains("path traversal") || text.contains("traversal")) {
            return "Path Traversal";
        }
        if (text.contains("command") || text.contains("exec")) {
            return "Command Injection";
        }
        return "Security Hotspot";
    }

    private StackType detectStackFromPath(String path) {
        String normalized = path == null ? "" : path.toLowerCase(Locale.ROOT);
        if (normalized.endsWith(".java") || normalized.endsWith(".kt")) {
            return StackType.JAVA_SPRING_BOOT;
        }
        if (normalized.endsWith(".tsx") || normalized.endsWith(".jsx") || normalized.endsWith(".ts") || normalized.endsWith(".js")) {
            return StackType.REACT_TYPESCRIPT;
        }
        if (normalized.endsWith(".py")) {
            return StackType.PYTHON_FASTAPI;
        }
        if (normalized.endsWith("dockerfile") || normalized.contains("docker-compose")) {
            return StackType.DOCKER;
        }
        if (normalized.endsWith(".yml") || normalized.endsWith(".yaml") || normalized.endsWith(".properties") || normalized.endsWith(".json")) {
            return StackType.CONFIG;
        }
        return StackType.UNKNOWN;
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

