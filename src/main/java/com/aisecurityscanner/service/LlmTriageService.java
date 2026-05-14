package com.aisecurityscanner.service;

import com.aisecurityscanner.config.ScannerProperties;
import com.aisecurityscanner.model.SemgrepFinding;
import com.aisecurityscanner.model.TriageResult;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

@Service
public class LlmTriageService {

    private final ScannerProperties properties;
    private final ObjectMapper objectMapper;
    private final RestTemplate restTemplate;

    public LlmTriageService(ScannerProperties properties, ObjectMapper objectMapper, RestTemplateBuilder restTemplateBuilder) {
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.restTemplate = restTemplateBuilder.build();
    }

    public TriageResult triage(SemgrepFinding finding, String context, boolean requestLlm) {
        if (requestLlm && properties.getLlm().isEnabled() && StringUtils.hasText(properties.getLlm().getApiKey())) {
            try {
                return callLlm(finding, context);
            } catch (Exception ex) {
                return fallback(finding, context, false);
            }
        }
        return fallback(finding, context, false);
    }

    private TriageResult callLlm(SemgrepFinding finding, String context) throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(properties.getLlm().getApiKey());
        headers.setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> systemMessage = new LinkedHashMap<String, Object>();
        systemMessage.put("role", "system");
        systemMessage.put("content", "You are a secure code reviewer. Return strict JSON with keys: exploitable, explanation, fix, suggestedCode.");

        String prompt = buildPrompt(finding, context);
        Map<String, Object> userMessage = new LinkedHashMap<String, Object>();
        userMessage.put("role", "user");
        userMessage.put("content", prompt);

        Map<String, Object> payload = new LinkedHashMap<String, Object>();
        payload.put("model", properties.getLlm().getModel());
        payload.put("temperature", properties.getLlm().getTemperature());
        payload.put("max_tokens", properties.getLlm().getMaxTokens());
        payload.put("messages", java.util.Arrays.asList(systemMessage, userMessage));

        ResponseEntity<String> response = restTemplate.postForEntity(properties.getLlm().getBaseUrl(), new HttpEntity<Map<String, Object>>(payload, headers), String.class);
        JsonNode root = objectMapper.readTree(response.getBody());
        String content = root.path("choices").get(0).path("message").path("content").asText();
        JsonNode triageJson = objectMapper.readTree(content);

        TriageResult result = new TriageResult();
        result.setExploitable(triageJson.path("exploitable").asBoolean(true));
        result.setExplanation(triageJson.path("explanation").asText(finding.getMessage()));
        result.setFix(triageJson.path("fix").asText(defaultFix(finding)));
        result.setSuggestedCode(triageJson.path("suggestedCode").asText(""));
        result.setLlmVerified(true);
        return result;
    }

    private String buildPrompt(SemgrepFinding finding, String context) {
        return "Analyze this security finding like a penetration tester and secure code reviewer. "
            + "Decide if it is actually exploitable in this context. If yes, explain exactly how and provide the best remediation. "
            + "Return ONLY valid JSON with keys exploitable, explanation, fix, suggestedCode.\n\n"
            + "Rule: " + finding.getRule() + "\n"
            + "Severity: " + finding.getSeverity() + "\n"
            + "File: " + finding.getFilePath() + ":" + finding.getLine() + "\n"
            + "Vulnerability Type: " + finding.getVulnerabilityType() + "\n"
            + "Semgrep Message: " + finding.getMessage() + "\n"
            + "Code Context:\n" + context;
    }

    private TriageResult fallback(SemgrepFinding finding, String context, boolean verified) {
        TriageResult result = new TriageResult();
        result.setExploitable(true);
        result.setExplanation(buildFallbackExplanation(finding, context));
        result.setFix(defaultFix(finding));
        result.setSuggestedCode("");
        result.setLlmVerified(verified);
        return result;
    }

    private String buildFallbackExplanation(SemgrepFinding finding, String context) {
        String lower = (finding.getCheckId() + " " + finding.getMessage()).toLowerCase(Locale.ROOT);
        if (lower.contains("sql")) {
            return "Raw query construction appears in " + finding.getFilePath() + ":" + finding.getLine()
                + ". If attacker-controlled input reaches this statement, it can alter the query structure. Use parameterized queries or repository methods with bound parameters.";
        }
        if (lower.contains("secret") || lower.contains("password") || lower.contains("token")) {
            return "A hardcoded credential-like value is present in " + finding.getFilePath() + ":" + finding.getLine()
                + ". Secrets committed in source control are reusable by anyone with repo access and should be moved to environment-based secret storage.";
        }
        if (lower.contains("auth") || lower.contains("permission") || lower.contains("access")) {
            return "The pattern in " + finding.getFilePath() + ":" + finding.getLine()
                + " indicates missing or weak authorization enforcement. Confirm the request identity and role before allowing the action or data access.";
        }
        if (lower.contains("xss") || lower.contains("html")) {
            return "User-controlled content may reach an HTML rendering sink at " + finding.getFilePath() + ":" + finding.getLine()
                + ". That can allow script execution in the victim browser unless output encoding or sanitization is applied.";
        }
        return "Semgrep found a suspicious pattern at " + finding.getFilePath() + ":" + finding.getLine()
            + ". Review the surrounding data flow to ensure attacker-controlled input cannot reach the vulnerable sink. Context analyzed: "
            + summarizeContext(context);
    }

    private String defaultFix(SemgrepFinding finding) {
        String lower = (finding.getCheckId() + " " + finding.getMessage()).toLowerCase(Locale.ROOT);
        if (lower.contains("sql")) {
            return "Replace string-concatenated SQL with prepared statements, parameterized queries, or typed repository APIs.";
        }
        if (lower.contains("secret") || lower.contains("password") || lower.contains("token")) {
            return "Move the secret to environment variables or a secrets manager, rotate the exposed credential, and prevent future commits with secret scanning.";
        }
        if (lower.contains("auth") || lower.contains("permission") || lower.contains("access")) {
            return "Add server-side authentication and role/ownership checks such as Spring Security method guards and identity-to-resource validation.";
        }
        if (lower.contains("xss") || lower.contains("html")) {
            return "Avoid rendering raw HTML; use framework-safe escaping or a vetted sanitizer before writing user content to the response.";
        }
        if (lower.contains("command") || lower.contains("exec")) {
            return "Do not pass user input into shell commands. Use fixed command arguments, allowlists, or safer library APIs.";
        }
        return "Refactor the code to use a safe API, validate untrusted input, and enforce least privilege around the affected operation.";
    }

    private String summarizeContext(String context) {
        if (context == null) {
            return "no code context available.";
        }
        String compact = context.replaceAll("\\s+", " ").trim();
        if (compact.length() > 180) {
            return compact.substring(0, 180) + "...";
        }
        return compact;
    }
}

