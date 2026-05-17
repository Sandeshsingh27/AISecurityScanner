package com.aisecurityscanner.service;

import com.aisecurityscanner.model.ComplexityHotspot;
import com.aisecurityscanner.model.Severity;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.stereotype.Service;

@Service
public class ComplexityAnalyzerService {

	public List<ComplexityHotspot> analyze(Path targetPath) {
		List<ComplexityHotspot> hotspots = new ArrayList<ComplexityHotspot>();
		try (Stream<Path> stream = Files.walk(targetPath)) {
			List<Path> files = stream.filter(Files::isRegularFile)
				.filter(this::isSupportedCodeFile)
				.collect(Collectors.toList());
			for (Path file : files) {
				hotspots.addAll(analyzeFile(targetPath, file));
			}
		} catch (IOException ex) {
			throw new IllegalStateException("Failed to analyze complexity in " + targetPath, ex);
		}
		return hotspots;
	}

	private List<ComplexityHotspot> analyzeFile(Path root, Path file) {
		List<ComplexityHotspot> hotspots = new ArrayList<ComplexityHotspot>();
		try {
			List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
			String methodName = null;
			int braceDepth = 0;
			int complexity = 0;
			for (int i = 0; i < lines.size(); i++) {
				String line = lines.get(i).trim();
				if (methodName == null && looksLikeMethodDeclaration(file, line)) {
					methodName = extractMethodName(line);
					braceDepth = count(line, '{') - count(line, '}');
					complexity = 1 + countDecisionPoints(line);
					continue;
				}
				if (methodName != null) {
					complexity += countDecisionPoints(line);
					braceDepth += count(line, '{');
					braceDepth -= count(line, '}');
					if (braceDepth <= 0) {
						Severity rating = complexity > 30 ? Severity.HIGH : (complexity > 15 ? Severity.MEDIUM : (complexity >= 10 ? Severity.LOW : null));
						if (rating != null) {
							hotspots.add(new ComplexityHotspot(root.relativize(file).toString().replace('\\', '/'), methodName, complexity, rating));
						}
						methodName = null;
						complexity = 0;
					}
				}
			}
		} catch (IOException ex) {
			throw new IllegalStateException("Failed to read file for complexity analysis: " + file, ex);
		}
		return hotspots;
	}

	private boolean isSupportedCodeFile(Path file) {
		String normalized = file.toString().replace('\\', '/').toLowerCase(Locale.ROOT);
		if (normalized.contains("/node_modules/") || normalized.contains("/.vite/") || normalized.contains("/dist/")
			|| normalized.contains("/target/") || normalized.contains("/build/") || normalized.contains("/.git/")
			|| normalized.contains("/.venv/") || normalized.contains("/venv/")) {
			return false;
		}
		String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
		return name.endsWith(".java") || name.endsWith(".js") || name.endsWith(".ts") || name.endsWith(".py");
	}

	private boolean looksLikeMethodDeclaration(Path file, String line) {
		String name = file.getFileName().toString().toLowerCase(Locale.ROOT);
		if (name.endsWith(".py")) {
			return line.startsWith("def ") || line.startsWith("async def ");
		}
		return line.contains("(") && line.contains(")") && line.endsWith("{")
			&& !line.startsWith("if") && !line.startsWith("for") && !line.startsWith("while") && !line.startsWith("switch") && !line.startsWith("catch");
	}

	private String extractMethodName(String line) {
		String normalized = line.replace("{", " ").trim();
		if (normalized.startsWith("def ")) {
			String rest = normalized.substring(4);
			return rest.substring(0, rest.indexOf('(')).trim();
		}
		if (normalized.startsWith("async def ")) {
			String rest = normalized.substring(10);
			return rest.substring(0, rest.indexOf('(')).trim();
		}
		int parenIndex = normalized.indexOf('(');
		String beforeParen = normalized.substring(0, parenIndex).trim();
		String[] tokens = beforeParen.split("\\s+");
		return tokens[tokens.length - 1];
	}

	private int countDecisionPoints(String line) {
		int count = 0;
		String lower = line.toLowerCase(Locale.ROOT);
		if (lower.startsWith("if ") || lower.startsWith("if(")) {
			count++;
		}
		if (lower.contains(" else if ")) {
			count++;
		}
		if (lower.startsWith("for ") || lower.startsWith("for(")) {
			count++;
		}
		if (lower.startsWith("while ") || lower.startsWith("while(")) {
			count++;
		}
		if (lower.startsWith("case ")) {
			count++;
		}
		if (lower.startsWith("catch ") || lower.startsWith("catch(")) {
			count++;
		}
		count += occurrences(line, "&&");
		count += occurrences(line, "||");
		count += occurrences(line, "?");
		return count;
	}

	private int count(String line, char character) {
		int count = 0;
		for (char current : line.toCharArray()) {
			if (current == character) {
				count++;
			}
		}
		return count;
	}

	private int occurrences(String value, String token) {
		int count = 0;
		int index = 0;
		while ((index = value.indexOf(token, index)) >= 0) {
			count++;
			index += token.length();
		}
		return count;
	}
}

