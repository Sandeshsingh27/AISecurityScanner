package com.aisecurityscanner.service;

import com.aisecurityscanner.model.SecurityFinding;
import com.aisecurityscanner.model.Severity;
import com.aisecurityscanner.model.StackType;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Lightweight SonarQube/Trivy-style code quality analyzer that runs purely in-process
 * (no external scanner) so the report always surfaces Bugs, Vulnerabilities, Code Smells
 * and Security Hotspots even when Semgrep returns few findings.
 *
 * Categories produced (SonarQube terminology):
 *  - "Bug"             : reliability problems (broken equality, empty catch, ...)
 *  - "Vulnerability"   : exploitable security defects (weak crypto, disabled CSRF, ...)
 *  - "Security Hotspot": risky patterns that need manual review (HTTP URL, Random for security, ...)
 *  - "Code Smell"      : maintainability problems (System.out, TODO, wildcard import, ...)
 */
@Service
public class CodeQualityAnalyzerService {

    private static final Logger log = LoggerFactory.getLogger(CodeQualityAnalyzerService.class);

    private static final int MAX_FILES_SCANNED = 5000;
    private static final int MAX_FINDINGS_PER_RULE = 50;
    private static final int MAX_FILE_BYTES = 1_500_000;

    private final List<RulePattern> javaRules = new ArrayList<>();
    private final List<RulePattern> jsRules = new ArrayList<>();
    private final List<RulePattern> pythonRules = new ArrayList<>();
    private final List<RulePattern> propertiesRules = new ArrayList<>();
    private final List<RulePattern> dockerRules = new ArrayList<>();
    private final List<RulePattern> genericRules = new ArrayList<>();

    public CodeQualityAnalyzerService() {
        registerJavaRules();
        registerJsRules();
        registerPythonRules();
        registerPropertiesRules();
        registerDockerRules();
        registerGenericRules();
    }

    public List<SecurityFinding> analyze(Path targetPath) {
        List<SecurityFinding> findings = new ArrayList<>();
        if (targetPath == null || !Files.exists(targetPath)) {
            return findings;
        }
        try (Stream<Path> stream = Files.walk(targetPath)) {
            List<Path> files = stream
                .filter(Files::isRegularFile)
                .filter(this::isScannable)
                .limit(MAX_FILES_SCANNED)
                .collect(Collectors.toList());
            for (Path file : files) {
                analyzeFile(targetPath, file, findings);
            }
        } catch (IOException ex) {
            // Never fail the overall scan because quality heuristics could not walk the tree.
            log.debug("Code quality analyzer could not walk {}", targetPath, ex);
        }
        return findings;
    }

    private void analyzeFile(Path root, Path file, List<SecurityFinding> findings) {
        String relative = root.relativize(file).toString().replace('\\', '/');
        // Skip this file itself to avoid reporting its own rule regex declarations as findings.
        if (relative.endsWith("CodeQualityAnalyzerService.java")) {
            return;
        }
        try {
            if (Files.size(file) > MAX_FILE_BYTES) {
                return;
            }
        } catch (IOException ex) {
            return;
        }
        List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (IOException ex) {
            return;
        }
        String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
        StackType stack = detectStack(name, relative);

        List<RulePattern> applicable = new ArrayList<>(genericRules);
        if (name.endsWith(".java")) {
            applicable.addAll(javaRules);
        } else if (name.endsWith(".js") || name.endsWith(".ts") || name.endsWith(".jsx") || name.endsWith(".tsx")) {
            applicable.addAll(jsRules);
        } else if (name.endsWith(".py")) {
            applicable.addAll(pythonRules);
        } else if (name.endsWith(".properties") || name.endsWith(".yml") || name.endsWith(".yaml") || name.endsWith(".env")) {
            applicable.addAll(propertiesRules);
        } else if (name.startsWith("dockerfile") || name.equals("dockerfile")) {
            applicable.addAll(dockerRules);
        }

        // Special multi-line rule: empty catch block in Java
        if (name.endsWith(".java")) {
            detectEmptyCatch(relative, stack, lines, findings);
        }

        for (RulePattern rule : applicable) {
            int matchCount = 0;
            for (int i = 0; i < lines.size(); i++) {
                String line = lines.get(i);
                if (line.length() > 4000) {
                    continue;
                }
                Matcher matcher = rule.pattern.matcher(line);
                if (matcher.find()) {
                    if (rule.requireWordBoundary && !looksLikeRealMatch(line, matcher)) {
                        continue;
                    }
                    if (shouldSkipMatch(rule, line)) {
                        continue;
                    }
                    findings.add(buildFinding(rule, relative, stack, i + 1, line.trim()));
                    matchCount++;
                    if (matchCount >= MAX_FINDINGS_PER_RULE) {
                        break;
                    }
                }
            }
        }
    }

    private boolean looksLikeRealMatch(String line, Matcher matcher) {
        String trimmed = line.trim();
        if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("#")) {
            return false;
        }
        return !trimmed.startsWith("\"") && !trimmed.contains("rule(\"");
    }


    private boolean shouldSkipMatch(RulePattern rule, String line) {
        String normalized = line.toLowerCase(Locale.ROOT);
        if ("java-http-url".equals(rule.id)) {
            return normalized.contains("apache.org/xml/features/")
                || normalized.contains("w3.org/")
                || normalized.contains("xmlns")
                || normalized.contains("schema");
        }
        return false;
    }

    private void detectEmptyCatch(String relative, StackType stack, List<String> lines, List<SecurityFinding> findings) {
        Pattern catchOpen = Pattern.compile("catch\\s*\\([^)]*\\)\\s*\\{\\s*$");
        for (int i = 0; i < lines.size(); i++) {
            if (catchOpen.matcher(lines.get(i)).find()) {
                // look ahead until non-blank, non-comment line
                int j = i + 1;
                while (j < lines.size()) {
                    String next = lines.get(j).trim();
                    if (next.isEmpty() || next.startsWith("//") || next.startsWith("*")) {
                        j++;
                        continue;
                    }
                    if (next.startsWith("}")) {
                        RulePattern rule = new RulePattern(
                            "java-empty-catch", "Empty catch block swallows exceptions",
                            "Bug", Severity.HIGH, null, false, "Java",
                            "Log or rethrow the exception instead of silently ignoring it.");
                        findings.add(buildFinding(rule, relative, stack, i + 1, lines.get(i).trim()));
                    }
                    break;
                }
            }
        }
    }

    private SecurityFinding buildFinding(RulePattern rule, String filePath, StackType stack, int line, String evidence) {
        SecurityFinding finding = new SecurityFinding();
        finding.setSeverity(rule.severity);
        finding.setTitle(rule.title);
        finding.setFilePath(filePath);
        finding.setLine(line);
        finding.setRule(rule.ruleLabel + " (" + rule.id + ")");
        finding.setStack(stack);
        finding.setEvidence(evidence);
        finding.setCategory(rule.category);
        finding.setVulnerabilityType(rule.category);
        finding.setExplanation(rule.fix);
        finding.setFix(rule.fix);
        finding.setTaintChain("Static pattern match — " + rule.id);
        finding.setSuggestedCode("");
        return finding;
    }

    private boolean isScannable(Path file) {
        String normalized = file.toString().replace('\\', '/').toLowerCase(Locale.ROOT);
        if (containsAnyPathSegment(normalized,
            "/target/", "/build/", "/.git/", "/node_modules/", "/.venv/", "/venv/", "/dist/", "/out/")) {
            return false;
        }
        String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
        return hasAnySuffix(name,
            ".java", ".js", ".ts", ".jsx", ".tsx", ".py", ".properties", ".yml", ".yaml", ".env")
            || name.startsWith("dockerfile");
    }

    private boolean containsAnyPathSegment(String text, String... fragments) {
        for (String fragment : fragments) {
            if (text.contains(fragment)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasAnySuffix(String text, String... suffixes) {
        for (String suffix : suffixes) {
            if (text.endsWith(suffix)) {
                return true;
            }
        }
        return false;
    }

    private StackType detectStack(String name, String relative) {
        if (name.endsWith(".java")) {
            return StackType.JAVA_SPRING_BOOT;
        }
        if (name.endsWith(".tsx") || name.endsWith(".jsx") || name.endsWith(".ts") || name.endsWith(".js")) {
            return StackType.REACT_TYPESCRIPT;
        }
        if (name.endsWith(".py")) {
            return StackType.PYTHON_FASTAPI;
        }
        if (name.startsWith("dockerfile")) {
            return StackType.DOCKER;
        }
        if (name.endsWith(".yml") || name.endsWith(".yaml") || name.endsWith(".properties") || name.endsWith(".env")) {
            return StackType.CONFIG;
        }
        return StackType.UNKNOWN;
    }

    // ===== Rule registrations =====

    private void registerJavaRules() {
        // --- Vulnerabilities ---
        javaRules.add(rule("java-md5", "Weak hashing algorithm MD5 used",
            "Vulnerability", Severity.HIGH, "MessageDigest\\.getInstance\\(\\s*\"MD5\"",
            "CWE-327 Weak Hash", "Use SHA-256 or stronger via MessageDigest.getInstance(\"SHA-256\")."));
        javaRules.add(rule("java-sha1", "Weak hashing algorithm SHA-1 used",
            "Vulnerability", Severity.MEDIUM, "MessageDigest\\.getInstance\\(\\s*\"SHA-?1\"",
            "CWE-327 Weak Hash", "Use SHA-256 or stronger."));
        javaRules.add(rule("java-des", "Weak cipher DES/3DES used",
            "Vulnerability", Severity.HIGH, "Cipher\\.getInstance\\(\\s*\"(DES|DESede|RC2|RC4)",
            "CWE-327 Weak Crypto", "Replace DES/3DES with AES-GCM."));
        javaRules.add(rule("java-ecb", "Cipher used in ECB mode",
            "Vulnerability", Severity.HIGH, "Cipher\\.getInstance\\(\\s*\"[^\"]*ECB",
            "CWE-327 ECB Mode", "Use an authenticated mode such as AES/GCM/NoPadding."));
        javaRules.add(rule("java-trustall", "TrustManager that accepts all certificates",
            "Vulnerability", Severity.CRITICAL, "checkServerTrusted\\(.*\\)\\s*\\{?\\s*$|X509TrustManager\\(\\)\\s*\\{",
            "CWE-295 Improper Cert Validation", "Validate the server certificate against a trusted CA."));
        javaRules.add(rule("java-hostname-verifier", "HostnameVerifier always returns true",
            "Vulnerability", Severity.HIGH, "HostnameVerifier.*return\\s+true|ALLOW_ALL_HOSTNAME_VERIFIER",
            "CWE-295 Improper Cert Validation", "Use the default strict hostname verifier."));
        javaRules.add(rule("java-permitall", "Spring Security permitAll() exposes endpoints",
            "Vulnerability", Severity.HIGH, "\\.permitAll\\(\\)",
            "CWE-284 Improper Access Control", "Restrict endpoints with hasRole/hasAuthority and authentication."));
        javaRules.add(rule("java-csrf-disable", "CSRF protection disabled",
            "Vulnerability", Severity.HIGH, "csrf\\(\\)\\s*\\.\\s*disable\\(\\)",
            "CWE-352 Cross-Site Request Forgery", "Re-enable CSRF or use a strict SameSite cookie strategy for stateful endpoints."));
        javaRules.add(rule("java-cors-wildcard", "CORS configured with wildcard origin",
            "Vulnerability", Severity.MEDIUM, "addAllowedOrigin\\(\\s*\"\\*\"|setAllowedOrigins\\(.*\\*",
            "CWE-942 Permissive CORS", "Whitelist explicit trusted origins instead of \"*\"."));
        javaRules.add(rule("java-runtime-exec", "Runtime.exec used — review for command injection",
            "Vulnerability", Severity.HIGH, "Runtime\\.getRuntime\\(\\)\\.exec\\(",
            "CWE-78 OS Command Injection", "Use ProcessBuilder with a fixed command and never concatenate user input."));
        javaRules.add(rule("java-string-format-sql", "SQL built via String concatenation/format",
            "Vulnerability", Severity.HIGH, "(executeQuery|executeUpdate|prepareStatement|createQuery)\\s*\\([^)]*[\"'].*[+]",
            "CWE-89 SQL Injection", "Use parameterized queries (PreparedStatement) or JPA criteria."));
        javaRules.add(rule("java-deserialize", "Java deserialization of untrusted input",
            "Vulnerability", Severity.HIGH, "new\\s+ObjectInputStream\\(",
            "CWE-502 Insecure Deserialization", "Avoid Java serialization or use a safe library with class allow-listing."));

        // --- Security Hotspots ---
        javaRules.add(rule("java-random-for-security", "java.util.Random used — possibly for security",
            "Security Hotspot", Severity.MEDIUM, "new\\s+Random\\(\\)",
            "CWE-330 Insufficient Randomness", "Use SecureRandom for tokens, IDs, salts, or keys."));
        javaRules.add(rule("java-http-url", "Plain HTTP URL detected",
            "Security Hotspot", Severity.LOW, "\"http://[^\"]+\"",
            "Use of unencrypted protocol", "Switch to HTTPS to prevent MITM."));
        javaRules.add(rule("java-system-exit", "System.exit() terminates the JVM",
            "Security Hotspot", Severity.MEDIUM, "System\\.exit\\(",
            "Reliability hotspot", "Avoid System.exit in library/server code; throw or return instead."));

        // --- Bugs ---
        javaRules.add(rule("java-printstacktrace", "Exception logged via printStackTrace()",
            "Bug", Severity.MEDIUM, "\\.printStackTrace\\(\\)",
            "Improper error handling", "Use a logger (SLF4J) and include exception context."));
        javaRules.add(rule("java-broad-catch", "Catching generic Exception/Throwable",
            "Bug", Severity.MEDIUM, "catch\\s*\\(\\s*(Exception|Throwable)\\s+",
            "Overly broad catch", "Catch specific exception types so failures aren't masked."));
        javaRules.add(rule("java-string-equals", "Strings compared with == instead of .equals()",
            "Bug", Severity.HIGH, "\"[^\"]+\"\\s*==\\s*\\w+|\\w+\\s*==\\s*\"[^\"]+\"",
            "Reference equality on String", "Use Objects.equals(a, b) or a.equals(b)."));
        javaRules.add(rule("java-thread-sleep", "Thread.sleep() in production code",
            "Bug", Severity.LOW, "Thread\\.sleep\\(",
            "Sleep in production path", "Prefer scheduled executors or async waits with timeouts."));
        javaRules.add(rule("java-todo", "TODO/FIXME/XXX comment left in source",
            "Code Smell", Severity.INFO, "\\b(TODO|FIXME|XXX)\\b.*",
            "Unfinished work", "Track the work in your issue tracker and remove the comment.", true));
        javaRules.add(rule("java-system-out", "System.out / System.err used for logging",
            "Code Smell", Severity.LOW, "System\\.(out|err)\\.(println|print|printf)\\(",
            "No logger used", "Replace with an SLF4J logger to allow log level control."));
        javaRules.add(rule("java-wildcard-import", "Wildcard import",
            "Code Smell", Severity.LOW, "^\\s*import\\s+[\\w.]+\\.\\*\\s*;",
            "Wildcard import", "Import only the classes you use to keep the namespace explicit."));
        javaRules.add(rule("java-magic-string-todo", "Hardcoded localhost URL",
            "Code Smell", Severity.LOW, "\"https?://localhost(:\\d+)?[^\"]*\"",
            "Environment-specific value", "Move localhost references to configuration."));
        javaRules.add(rule("java-public-field", "Non-final public static field",
            "Code Smell", Severity.LOW, "public\\s+static\\s+(?!final)[\\w<>,\\s]+\\s+\\w+\\s*=",
            "Mutable global state", "Make the field final or expose it through a method."));
    }

    private void registerJsRules() {
        jsRules.add(rule("js-eval", "eval() executes dynamic code",
            "Vulnerability", Severity.HIGH, "\\beval\\s*\\(",
            "CWE-95 Code Injection", "Replace eval with explicit parsing or JSON.parse."));
        jsRules.add(rule("js-innerhtml", "Assignment to innerHTML may enable XSS",
            "Vulnerability", Severity.HIGH, "\\.innerHTML\\s*=",
            "CWE-79 XSS", "Use textContent or a sanitization library (DOMPurify)."));
        jsRules.add(rule("js-document-write", "document.write() is dangerous",
            "Vulnerability", Severity.MEDIUM, "document\\.write\\s*\\(",
            "CWE-79 XSS", "Build the DOM via createElement or React/Vue templates."));
        jsRules.add(rule("js-console-log", "console.log left in source",
            "Code Smell", Severity.LOW, "console\\.(log|debug|info)\\s*\\(",
            "Debug logging", "Remove or guard with a logger before shipping."));
        jsRules.add(rule("js-debugger", "debugger statement left in source",
            "Code Smell", Severity.MEDIUM, "\\bdebugger\\s*;",
            "Debug breakpoint", "Remove debugger statements before committing."));
        jsRules.add(rule("js-todo", "TODO/FIXME/XXX comment left in source",
            "Code Smell", Severity.INFO, "//.*\\b(TODO|FIXME|XXX)\\b",
            "Unfinished work", "Track in issue tracker.", true));
        jsRules.add(rule("js-http-url", "Plain HTTP URL",
            "Security Hotspot", Severity.LOW, "[\"']http://(?!localhost(?::\\d+)?|127\\.0\\.0\\.1(?::\\d+)?)[^\"']+[\"']",
            "Unencrypted protocol", "Use HTTPS."));
        jsRules.add(rule("js-math-random", "Math.random() used — not cryptographically secure",
            "Security Hotspot", Severity.MEDIUM, "Math\\.random\\s*\\(",
            "CWE-330 Insufficient Randomness", "Use crypto.getRandomValues / crypto.randomUUID for security tokens."));
    }

    private void registerPythonRules() {
        pythonRules.add(rule("py-eval", "eval()/exec() on untrusted input",
            "Vulnerability", Severity.HIGH, "\\b(eval|exec)\\s*\\(",
            "CWE-95 Code Injection", "Avoid eval/exec; use ast.literal_eval if you must parse literals."));
        pythonRules.add(rule("py-shell-true", "subprocess called with shell=True",
            "Vulnerability", Severity.HIGH, "shell\\s*=\\s*True",
            "CWE-78 Command Injection", "Pass argument list and shell=False; never concatenate user input."));
        pythonRules.add(rule("py-pickle", "pickle.load on untrusted data",
            "Vulnerability", Severity.HIGH, "pickle\\.(load|loads)\\s*\\(",
            "CWE-502 Insecure Deserialization", "Use JSON or a safe serialization format."));
        pythonRules.add(rule("py-yaml-load", "yaml.load without SafeLoader",
            "Vulnerability", Severity.HIGH, "yaml\\.load\\s*\\((?![^)]*Loader\\s*=\\s*yaml\\.SafeLoader)",
            "CWE-20 Improper Input Validation", "Use yaml.safe_load or pass Loader=yaml.SafeLoader."));
        pythonRules.add(rule("py-assert", "assert used for production checks",
            "Bug", Severity.MEDIUM, "^\\s*assert\\s+",
            "Asserts are stripped with -O", "Replace with explicit if/raise."));
        pythonRules.add(rule("py-print", "print() used for logging",
            "Code Smell", Severity.LOW, "^\\s*print\\s*\\(",
            "Use logging module", "Replace print with logging.getLogger(__name__)."));
        pythonRules.add(rule("py-todo", "TODO/FIXME comment",
            "Code Smell", Severity.INFO, "#.*\\b(TODO|FIXME|XXX)\\b",
            "Unfinished work", "Track in issue tracker.", true));
        pythonRules.add(rule("py-md5", "hashlib.md5 used",
            "Vulnerability", Severity.MEDIUM, "hashlib\\.md5\\s*\\(",
            "CWE-327 Weak Hash", "Use hashlib.sha256 or higher."));
    }

    private void registerPropertiesRules() {
        propertiesRules.add(rule("conf-actuator-all", "Spring actuator exposes all endpoints",
            "Vulnerability", Severity.HIGH, "management\\.endpoints\\.web\\.exposure\\.include\\s*[:=]\\s*\\*",
            "CWE-200 Information Exposure", "Expose only the actuator endpoints you need (e.g. health, info)."));
        propertiesRules.add(rule("conf-debug-true", "Debug mode enabled",
            "Security Hotspot", Severity.MEDIUM, "(debug|spring\\.boot\\.admin\\.client\\.enabled)\\s*[:=]\\s*true",
            "Debug enabled in config", "Disable debug in non-dev profiles."));
        propertiesRules.add(rule("conf-ssl-disabled", "TLS/SSL disabled",
            "Vulnerability", Severity.MEDIUM, "(server\\.ssl\\.enabled|ssl\\.enabled)\\s*[:=]\\s*false",
            "Cleartext transport", "Enable TLS for any non-localhost listener."));
        propertiesRules.add(rule("conf-show-sql", "Hibernate show-sql enabled",
            "Code Smell", Severity.LOW, "(spring\\.jpa\\.show-sql|hibernate\\.show_sql)\\s*[:=]\\s*true",
            "Verbose SQL logging", "Disable show-sql in production to avoid leaking queries."));
        propertiesRules.add(rule("conf-h2-console", "H2 console enabled",
            "Vulnerability", Severity.HIGH, "spring\\.h2\\.console\\.enabled\\s*[:=]\\s*true",
            "Database console exposed", "Disable the H2 console outside local development."));
    }

    private void registerDockerRules() {
        dockerRules.add(rule("docker-latest-tag", "Image uses :latest tag",
            "Code Smell", Severity.LOW, "^FROM\\s+\\S+:latest",
            "Reproducibility", "Pin to an explicit version or digest."));
        dockerRules.add(rule("docker-no-version", "FROM image without explicit tag",
            "Code Smell", Severity.LOW, "^FROM\\s+[^:\\s]+(\\s+as\\s+\\w+)?\\s*$",
            "Reproducibility", "Pin to an explicit version (e.g. eclipse-temurin:21-jre)."));
        dockerRules.add(rule("docker-add-http", "ADD with remote URL",
            "Vulnerability", Severity.MEDIUM, "^ADD\\s+https?://",
            "CWE-494 Download Without Integrity Check", "Use COPY for local files or RUN curl + sha256 verify."));
        dockerRules.add(rule("docker-curl-pipe-sh", "curl piped into shell",
            "Vulnerability", Severity.HIGH, "curl[^|]*\\|\\s*(sudo\\s+)?(sh|bash)",
            "CWE-494 Download Without Integrity Check", "Download to file and verify checksum before executing."));
        dockerRules.add(rule("docker-apt-no-clean", "apt-get install without rm /var/lib/apt/lists",
            "Code Smell", Severity.LOW, "apt-get\\s+install(?!.*rm\\s+-rf\\s+/var/lib/apt/lists)",
            "Image size", "Append && rm -rf /var/lib/apt/lists/* to keep images small."));
    }

    private void registerGenericRules() {
        // applies to every text file
        genericRules.add(rule("generic-aws-key", "Possible AWS Access Key ID",
            "Hardcoded Secret", Severity.CRITICAL, "AKIA[0-9A-Z]{16}",
            "CWE-798 Hardcoded Credential", "Rotate the credential and move it to AWS Secrets Manager / env vars."));
        genericRules.add(rule("generic-private-key", "Private key material in source",
            "Hardcoded Secret", Severity.CRITICAL, "-----BEGIN (RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----",
            "CWE-798 Hardcoded Credential", "Move keys to a secrets manager and rotate them immediately."));
        genericRules.add(rule("generic-jwt", "Hardcoded JWT token",
            "Hardcoded Secret", Severity.HIGH, "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}",
            "CWE-798 Hardcoded Credential", "Don't commit JWTs; pull from a secret store at runtime."));
        genericRules.add(rule("generic-bearer", "Hardcoded bearer/authorization token",
            "Hardcoded Secret", Severity.HIGH, "(?i)(authorization|bearer)\\s*[:=]\\s*[\"']?[A-Za-z0-9_\\-./+]{20,}",
            "CWE-798 Hardcoded Credential", "Inject the token from a secret manager."));
    }

    private static RulePattern rule(String id, String title, String category, Severity severity,
                                    String regex, String ruleLabel, String fix) {
        return new RulePattern(id, title, category, severity, regex, false, ruleLabel, fix);
    }

    private static RulePattern rule(String id, String title, String category, Severity severity,
                                    String regex, String ruleLabel, String fix, boolean requireWordBoundary) {
        return new RulePattern(id, title, category, severity, regex, requireWordBoundary, ruleLabel, fix);
    }

    private static class RulePattern {
        final String id;
        final String title;
        final String category;
        final Severity severity;
        final Pattern pattern;
        final boolean requireWordBoundary;
        final String ruleLabel;
        final String fix;

        RulePattern(String id, String title, String category, Severity severity,
                    String regex, boolean requireWordBoundary, String ruleLabel, String fix) {
            this.id = id;
            this.title = title;
            this.category = category;
            this.severity = severity;
            this.pattern = regex == null ? Pattern.compile("$^") : Pattern.compile(regex);
            this.requireWordBoundary = requireWordBoundary;
            this.ruleLabel = ruleLabel;
            this.fix = fix;
        }
    }
}

