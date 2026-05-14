package com.aisecurityscanner.service;

import com.aisecurityscanner.model.DependencyFinding;
import com.aisecurityscanner.model.Severity;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

@Service
public class DependencyAuditService {

	private final VersionComparator versionComparator;
	private final ObjectMapper objectMapper;
	private final Map<String, VulnerabilityRule> vulnerabilityCatalog = new LinkedHashMap<String, VulnerabilityRule>();

	public DependencyAuditService(VersionComparator versionComparator, ObjectMapper objectMapper) {
		this.versionComparator = versionComparator;
		this.objectMapper = objectMapper;
		registerDefaults();
	}

	public List<DependencyFinding> audit(Path targetPath) {
		List<DependencyFinding> findings = new ArrayList<DependencyFinding>();
		try (Stream<Path> stream = Files.walk(targetPath)) {
			List<Path> files = stream.filter(Files::isRegularFile).collect(Collectors.toList());
			for (Path file : files) {
				String name = file.getFileName().toString();
				if ("pom.xml".equals(name)) {
					findings.addAll(auditPom(file));
				} else if ("package.json".equals(name)) {
					findings.addAll(auditPackageJson(file));
				} else if ("requirements.txt".equals(name)) {
					findings.addAll(auditRequirements(file));
				}
			}
		} catch (IOException ex) {
			throw new IllegalStateException("Failed to audit dependencies in " + targetPath, ex);
		}
		return findings;
	}

	private List<DependencyFinding> auditPom(Path pomPath) {
		List<DependencyFinding> findings = new ArrayList<DependencyFinding>();
		try (InputStream inputStream = Files.newInputStream(pomPath)) {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
			Document document = factory.newDocumentBuilder().parse(inputStream);
			document.getDocumentElement().normalize();

			Map<String, String> properties = extractProperties(document);
			String parentArtifact = text(document, "parent", "artifactId");
			String parentVersion = resolveProperty(text(document, "parent", "version"), properties);
			if ("spring-boot-starter-parent".equals(parentArtifact) && parentVersion != null) {
				maybeAdd(findings, "spring-boot", parentVersion);
			}

			NodeList dependencies = document.getElementsByTagName("dependency");
			for (int index = 0; index < dependencies.getLength(); index++) {
				Node node = dependencies.item(index);
				if (!(node instanceof Element)) {
					continue;
				}
				Element element = (Element) node;
				String artifactId = childText(element, "artifactId");
				String version = resolveProperty(childText(element, "version"), properties);
				if (artifactId != null && version != null) {
					maybeAdd(findings, artifactId, version);
				}
			}
		} catch (Exception ex) {
			throw new IllegalStateException("Failed to parse pom.xml: " + pomPath, ex);
		}
		return findings;
	}

	private List<DependencyFinding> auditPackageJson(Path packageJsonPath) {
		List<DependencyFinding> findings = new ArrayList<DependencyFinding>();
		try {
			JsonNode root = objectMapper.readTree(Files.readAllBytes(packageJsonPath));
			collectPackageJsonDeps(findings, root.path("dependencies"));
			collectPackageJsonDeps(findings, root.path("devDependencies"));
		} catch (IOException ex) {
			throw new IllegalStateException("Failed to parse package.json: " + packageJsonPath, ex);
		}
		return findings;
	}

	private void collectPackageJsonDeps(List<DependencyFinding> findings, JsonNode dependencies) {
		if (dependencies == null || !dependencies.isObject()) {
			return;
		}
		dependencies.fields().forEachRemaining(entry -> maybeAdd(findings, entry.getKey(), entry.getValue().asText()));
	}

	private List<DependencyFinding> auditRequirements(Path requirementsPath) {
		List<DependencyFinding> findings = new ArrayList<DependencyFinding>();
		try {
			List<String> lines = Files.readAllLines(requirementsPath, StandardCharsets.UTF_8);
			for (String line : lines) {
				String trimmed = line.trim();
				if (trimmed.isEmpty() || trimmed.startsWith("#") || !trimmed.contains("==")) {
					continue;
				}
				String[] parts = trimmed.split("==");
				if (parts.length == 2) {
					maybeAdd(findings, parts[0].trim(), parts[1].trim());
				}
			}
		} catch (IOException ex) {
			throw new IllegalStateException("Failed to parse requirements.txt: " + requirementsPath, ex);
		}
		return findings;
	}

	private void maybeAdd(List<DependencyFinding> findings, String packageName, String version) {
		if (packageName == null || version == null) {
			return;
		}
		String normalized = packageName.toLowerCase(Locale.ROOT);
		VulnerabilityRule rule = vulnerabilityCatalog.get(normalized);
		if (rule != null && versionComparator.isLowerThan(version, rule.vulnerableBelow)) {
			findings.add(new DependencyFinding(packageName, version, rule.vulnerableBelow, rule.cve, rule.severity));
		}
	}

	private Map<String, String> extractProperties(Document document) {
		Map<String, String> properties = new HashMap<String, String>();
		NodeList propertiesNodes = document.getElementsByTagName("properties");
		if (propertiesNodes.getLength() == 0) {
			return properties;
		}
		Node node = propertiesNodes.item(0);
		NodeList children = node.getChildNodes();
		for (int i = 0; i < children.getLength(); i++) {
			Node child = children.item(i);
			if (child instanceof Element) {
				properties.put(child.getNodeName(), child.getTextContent().trim());
			}
		}
		return properties;
	}

	private String resolveProperty(String value, Map<String, String> properties) {
		if (value == null) {
			return null;
		}
		String trimmed = value.trim();
		if (trimmed.startsWith("${") && trimmed.endsWith("}")) {
			String key = trimmed.substring(2, trimmed.length() - 1);
			return properties.get(key);
		}
		return trimmed;
	}

	private String text(Document document, String parentTag, String childTag) {
		NodeList parents = document.getElementsByTagName(parentTag);
		if (parents.getLength() == 0 || !(parents.item(0) instanceof Element)) {
			return null;
		}
		return childText((Element) parents.item(0), childTag);
	}

	private String childText(Element element, String tagName) {
		NodeList children = element.getElementsByTagName(tagName);
		if (children.getLength() == 0) {
			return null;
		}
		return children.item(0).getTextContent().trim();
	}

	private void registerDefaults() {
		vulnerabilityCatalog.put("spring-boot", new VulnerabilityRule("3.2.0", "CVE-2024-22233", Severity.HIGH));
		vulnerabilityCatalog.put("jjwt", new VulnerabilityRule("0.12.0", "Weak key acceptance", Severity.MEDIUM));
		vulnerabilityCatalog.put("log4j", new VulnerabilityRule("2.17.1", "CVE-2021-44228", Severity.CRITICAL));
		vulnerabilityCatalog.put("log4j-core", new VulnerabilityRule("2.17.1", "CVE-2021-44228", Severity.CRITICAL));
		vulnerabilityCatalog.put("jackson-databind", new VulnerabilityRule("2.14.0", "Deserialization CVEs", Severity.HIGH));
		vulnerabilityCatalog.put("commons-text", new VulnerabilityRule("1.10.0", "CVE-2022-42889", Severity.HIGH));
		vulnerabilityCatalog.put("netty", new VulnerabilityRule("4.1.86", "CVE-2022-41881", Severity.HIGH));
		vulnerabilityCatalog.put("express", new VulnerabilityRule("4.18.0", "CVE-2022-24999", Severity.HIGH));
		vulnerabilityCatalog.put("axios", new VulnerabilityRule("1.6.0", "CVE-2023-45857", Severity.HIGH));
		vulnerabilityCatalog.put("lodash", new VulnerabilityRule("4.17.21", "Prototype Pollution", Severity.MEDIUM));
		vulnerabilityCatalog.put("django", new VulnerabilityRule("4.2.0", "Multiple CVEs", Severity.HIGH));
		vulnerabilityCatalog.put("pillow", new VulnerabilityRule("10.0.0", "CVE-2023-44271", Severity.MEDIUM));
		vulnerabilityCatalog.put("requests", new VulnerabilityRule("2.31.0", "CVE-2023-32681", Severity.MEDIUM));
		vulnerabilityCatalog.put("cryptography", new VulnerabilityRule("41.0.0", "Multiple CVEs", Severity.HIGH));
		vulnerabilityCatalog.put("next", new VulnerabilityRule("13.5.0", "CVE-2023-46298", Severity.HIGH));
		vulnerabilityCatalog.put("webpack", new VulnerabilityRule("5.76.0", "CVE-2023-28154", Severity.MEDIUM));
		vulnerabilityCatalog.put("aws-java-sdk-s3", new VulnerabilityRule("1.12.767", "Multiple CVEs", Severity.HIGH));
		vulnerabilityCatalog.put("aws-java-sdk-sts", new VulnerabilityRule("1.12.767", "Multiple CVEs", Severity.HIGH));
	}

	private static class VulnerabilityRule {
		private final String vulnerableBelow;
		private final String cve;
		private final Severity severity;

		private VulnerabilityRule(String vulnerableBelow, String cve, Severity severity) {
			this.vulnerableBelow = vulnerableBelow;
			this.cve = cve;
			this.severity = severity;
		}
	}
}

