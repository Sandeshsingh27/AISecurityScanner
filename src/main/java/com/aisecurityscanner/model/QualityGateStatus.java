package com.aisecurityscanner.model;

public enum QualityGateStatus {
    PASSED,
    FAILED;

    public String toEmojiLabel() {
        return this == PASSED ? "✅ PASSED" : "❌ FAILED";
    }
}

