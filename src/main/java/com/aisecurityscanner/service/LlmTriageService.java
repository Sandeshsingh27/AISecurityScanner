package com.aisecurityscanner.service;

import com.aisecurityscanner.config.ScannerProperties;
import com.aisecurityscanner.model.SemgrepFinding;
import com.aisecurityscanner.model.TriageResult;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

    private static final Logger log = LoggerFactory.getLogger(LlmTriageService.class);

    private final ScannerProperties properties;
    private final ObjectMapper objectMapper;
    private final RestTemplate restTemplate;

    public LlmTriageService(ScannerProperties properties, ObjectMapper objectMapper, RestTemplateBuilder restTemplateBuilder) {
        this.properties = properties;
        this.objectMapper = objectMapper;
        this.restTemplate = restTemplateBuilder.build();
    }

    @PostConstruct
    void logLlmState() {
        ScannerProperties.Llm llm = properties.getLlm();
        log.info("LLM triage configuration -> enabled={}, provider={}, model={}, baseUrl={}, apiKeyConfigured={}",
            llm.isEnabled(),
            llm.getProviderLabel(),
            llm.getModel(),
            llm.getBaseUrl(),
            StringUtils.hasText(llm.getApiKey()));
        if (!StringUtils.hasText(llm.getApiKey())) {
            log.warn("scanner.llm.api-key is empty. Requests with llmEnabled=true will fall back to deterministic explanations until SCANNER_LLM_API_KEY is set.");
        } else if (!llm.isEnabled()) {
            log.info("scanner.llm.enabled=false (server default). Per-request llmEnabled=true will still trigger live LLM calls because an API key is configured.");
        }
    }

    public TriageResult triage(SemgrepFinding finding, String context, boolean requestLlm) {
        ScannerProperties.Llm llm = properties.getLlm();
        // Request-level flag takes precedence: if the caller asks for LLM, honor it
        // as long as we have credentials. The server-side scanner.llm.enabled is only
        // a default for callers that don't specify llmEnabled in the request.
        boolean useLlm = requestLlm || llm.isEnabled();
        if (!useLlm) {
            return fallback(finding, context, false);
        }
        if (!StringUtils.hasText(llm.getApiKey())) {
            log.debug("LLM call skipped for {}:{} because scanner.llm.api-key is not configured", finding.getFilePath(), finding.getLine());
            return fallback(finding, context, false);
        }
        try {
            return callLlm(finding, context);
        } catch (IOException | RuntimeException ex) {
            log.warn("LLM triage call failed for {}:{} ({}): {}. Falling back to deterministic explanation.",
                finding.getFilePath(), finding.getLine(), ex.getClass().getSimpleName(), ex.getMessage());
            return fallback(finding, context, false);
        }
    }

    private TriageResult callLlm(SemgrepFinding finding, String context) throws IOException {
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
        JsonNode triageJson = parseModelJson(content, finding);

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
            + "Return ONLY a single raw JSON object (no markdown, no code fences, no prose) with exactly these keys: "
            + "exploitable (boolean), explanation (string), fix (string), suggestedCode (string).\n\n"
            + "Rule: " + finding.getRule() + "\n"
            + "Severity: " + finding.getSeverity() + "\n"
            + "File: " + finding.getFilePath() + ":" + finding.getLine() + "\n"
            + "Vulnerability Type: " + finding.getVulnerabilityType() + "\n"
            + "Semgrep Message: " + finding.getMessage() + "\n"
            + "Code Context:\n" + context;
    }

    /**
     * Some models wrap JSON output in markdown fences (```json ... ```), prepend prose,
     * or append commentary. Strip those wrappers and parse the first balanced JSON object
     * we can find. Falls back to a synthetic JSON node carrying the raw text as the
     * explanation when no parseable JSON is present.
     */
    private JsonNode parseModelJson(String content, SemgrepFinding finding) {
        String cleaned = stripCodeFences(content == null ? "" : content.trim());
        try {
            return objectMapper.readTree(cleaned);
        } catch (IOException parseError) {
            log.debug("Primary LLM JSON parse failed for {}:{}; trying first-object extraction", finding.getFilePath(), finding.getLine(), parseError);
        }
        String candidate = extractFirstJsonObject(cleaned);
        if (candidate != null) {
            try {
                return objectMapper.readTree(candidate);
            } catch (IOException parseError) {
                log.debug("Extracted JSON parse failed for {}:{}; using synthetic fallback", finding.getFilePath(), finding.getLine(), parseError);
            }
        }
        log.warn("LLM returned non-JSON content for {}:{}; using raw text as explanation.",
            finding.getFilePath(), finding.getLine());
        com.fasterxml.jackson.databind.node.ObjectNode synthetic = objectMapper.createObjectNode();
        synthetic.put("exploitable", true);
        synthetic.put("explanation", cleaned.length() > 1500 ? cleaned.substring(0, 1500) + "..." : cleaned);
        synthetic.put("fix", defaultFix(finding));
        synthetic.put("suggestedCode", "");
        return synthetic;
    }

    private String stripCodeFences(String text) {
        if (text.isEmpty()) {
            return text;
        }
        // Remove leading ```json / ```JSON / ``` fences
        String t = text;
        if (t.startsWith("```")) {
            int firstNewline = t.indexOf('\n');
            if (firstNewline >= 0) {
                t = t.substring(firstNewline + 1);
            } else {
                t = t.substring(3);
            }
        }
        // Remove trailing ``` fence
        int lastFence = t.lastIndexOf("```");
        if (lastFence >= 0) {
            t = t.substring(0, lastFence);
        }
        return t.trim();
    }

    private String extractFirstJsonObject(String text) {
        int start = text.indexOf('{');
        if (start < 0) {
            return null;
        }
        JsonScanState state = new JsonScanState();
        for (int i = start; i < text.length(); i++) {
            if (applyJsonChar(state, text.charAt(i))) {
                if (state.depth == 0) {
                    return text.substring(start, i + 1);
                }
            }
        }
        return null;
    }

    private boolean applyJsonChar(JsonScanState state, char c) {
        if (state.escape) {
            state.escape = false;
            return false;
        }
        if (c == '\\') {
            state.escape = true;
            return false;
        }
        if (c == '"') {
            state.inString = !state.inString;
            return false;
        }
        if (state.inString) {
            return false;
        }
        if (c == '{') {
            state.depth++;
            return true;
        }
        if (c == '}') {
            state.depth--;
            return true;
        }
        return false;
    }

    private static class JsonScanState {
        private int depth;
        private boolean inString;
        private boolean escape;
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

