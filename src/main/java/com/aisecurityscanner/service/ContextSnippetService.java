package com.aisecurityscanner.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class ContextSnippetService {

    public String extract(Path projectRoot, String filePath, int line, int contextLines) {
        Path resolved = resolve(projectRoot, filePath);
        if (!Files.exists(resolved)) {
            return "";
        }
        try {
            List<String> lines = Files.readAllLines(resolved, StandardCharsets.UTF_8);
            int start = Math.max(1, line - contextLines);
            int end = Math.min(lines.size(), line + contextLines);
            StringBuilder builder = new StringBuilder();
            for (int index = start; index <= end; index++) {
                builder.append(index)
                    .append(" | ")
                    .append(lines.get(index - 1))
                    .append('\n');
            }
            return builder.toString().trim();
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to read context for file: " + resolved, ex);
        }
    }

    private Path resolve(Path projectRoot, String filePath) {
        Path candidate = Paths.get(filePath);
        if (candidate.isAbsolute()) {
            return candidate;
        }
        return projectRoot.resolve(filePath).normalize();
    }
}

