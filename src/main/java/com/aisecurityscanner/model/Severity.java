package com.aisecurityscanner.model;

public enum Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO;

    public String toEmojiLabel() {
        switch (this) {
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
}

