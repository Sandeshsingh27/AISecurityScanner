package com.aisecurityscanner.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "scanner")
public class ScannerProperties {

    private final Semgrep semgrep = new Semgrep();
    private final Llm llm = new Llm();
    private final Report report = new Report();
    private final Cli cli = new Cli();

    public Semgrep getSemgrep() {
        return semgrep;
    }

    public Llm getLlm() {
        return llm;
    }

    public Report getReport() {
        return report;
    }

    public Cli getCli() {
        return cli;
    }

    public static class Semgrep {
        private String command = "semgrep";
        private String defaultConfig = "auto";
        private int timeoutSeconds = 300;

        public String getCommand() {
            return command;
        }

        public void setCommand(String command) {
            this.command = command;
        }

        public String getDefaultConfig() {
            return defaultConfig;
        }

        public void setDefaultConfig(String defaultConfig) {
            this.defaultConfig = defaultConfig;
        }

        public int getTimeoutSeconds() {
            return timeoutSeconds;
        }

        public void setTimeoutSeconds(int timeoutSeconds) {
            this.timeoutSeconds = timeoutSeconds;
        }
    }

    public static class Llm {
        private boolean enabled;
        private String providerLabel = "GitHub Models";
        private String baseUrl = "https://models.inference.ai.azure.com/chat/completions";
        private String apiKey;
        private String model = "gpt-4o-mini";
        private int maxTokens = 900;
        private double temperature = 0.2;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getProviderLabel() {
            return providerLabel;
        }

        public void setProviderLabel(String providerLabel) {
            this.providerLabel = providerLabel;
        }

        public String getBaseUrl() {
            return baseUrl;
        }

        public void setBaseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
        }

        public String getApiKey() {
            return apiKey;
        }

        public void setApiKey(String apiKey) {
            this.apiKey = apiKey;
        }

        public String getModel() {
            return model;
        }

        public void setModel(String model) {
            this.model = model;
        }

        public int getMaxTokens() {
            return maxTokens;
        }

        public void setMaxTokens(int maxTokens) {
            this.maxTokens = maxTokens;
        }

        public double getTemperature() {
            return temperature;
        }

        public void setTemperature(double temperature) {
            this.temperature = temperature;
        }
    }

    public static class Report {
        private int contextLines = 10;
        private int maxFindingsForLlm = 15;

        public int getContextLines() {
            return contextLines;
        }

        public void setContextLines(int contextLines) {
            this.contextLines = contextLines;
        }

        public int getMaxFindingsForLlm() {
            return maxFindingsForLlm;
        }

        public void setMaxFindingsForLlm(int maxFindingsForLlm) {
            this.maxFindingsForLlm = maxFindingsForLlm;
        }
    }

    public static class Cli {
        private boolean enabled;
        private String targetPath = ".";
        private boolean failOnQualityGate = true;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getTargetPath() {
            return targetPath;
        }

        public void setTargetPath(String targetPath) {
            this.targetPath = targetPath;
        }

        public boolean isFailOnQualityGate() {
            return failOnQualityGate;
        }

        public void setFailOnQualityGate(boolean failOnQualityGate) {
            this.failOnQualityGate = failOnQualityGate;
        }
    }
}

