package com.aisecurityscanner.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.springframework.stereotype.Component;

@Component
public class VersionComparator {

    public boolean isLowerThan(String currentVersion, String fixedVersion) {
        return compare(currentVersion, fixedVersion) < 0;
    }

    public int compare(String left, String right) {
        List<String> leftTokens = tokenize(clean(left));
        List<String> rightTokens = tokenize(clean(right));
        int max = Math.max(leftTokens.size(), rightTokens.size());
        for (int i = 0; i < max; i++) {
            String l = i < leftTokens.size() ? leftTokens.get(i) : "0";
            String r = i < rightTokens.size() ? rightTokens.get(i) : "0";
            int comparison = compareToken(l, r);
            if (comparison != 0) {
                return comparison;
            }
        }
        return 0;
    }

    private String clean(String version) {
        if (version == null) {
            return "0";
        }
        String cleaned = version.trim();
        if (cleaned.startsWith("^") || cleaned.startsWith("~") || cleaned.startsWith(">=") || cleaned.startsWith("<=")) {
            cleaned = cleaned.substring(cleaned.startsWith(">=") || cleaned.startsWith("<=") ? 2 : 1);
        }
        return cleaned.replace("v", "");
    }

    private List<String> tokenize(String version) {
        String[] raw = version.split("[.-]");
        List<String> tokens = new ArrayList<String>();
        for (String token : raw) {
            if (!token.isEmpty()) {
                tokens.add(token.toLowerCase(Locale.ROOT));
            }
        }
        if (tokens.isEmpty()) {
            tokens.add("0");
        }
        return tokens;
    }

    private int compareToken(String left, String right) {
        boolean leftNumeric = left.matches("\\d+");
        boolean rightNumeric = right.matches("\\d+");
        if (leftNumeric && rightNumeric) {
            return Integer.valueOf(left).compareTo(Integer.valueOf(right));
        }
        if (leftNumeric) {
            return 1;
        }
        if (rightNumeric) {
            return -1;
        }
        return qualifierRank(left) - qualifierRank(right);
    }

    private int qualifierRank(String token) {
        if (token.contains("snapshot") || token.contains("alpha")) {
            return -3;
        }
        if (token.contains("beta")) {
            return -2;
        }
        if (token.contains("rc")) {
            return -1;
        }
        return 0;
    }
}

