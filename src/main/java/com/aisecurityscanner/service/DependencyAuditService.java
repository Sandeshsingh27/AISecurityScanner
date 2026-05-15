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
		// Extended Trivy-style catalog
		vulnerabilityCatalog.put("snakeyaml", new VulnerabilityRule("2.0", "CVE-2022-1471", Severity.HIGH));
		vulnerabilityCatalog.put("xstream", new VulnerabilityRule("1.4.20", "CVE-2021-39139", Severity.CRITICAL));
		vulnerabilityCatalog.put("guava", new VulnerabilityRule("32.0.0", "CVE-2023-2976", Severity.MEDIUM));
		vulnerabilityCatalog.put("commons-collections", new VulnerabilityRule("3.2.2", "CVE-2015-7501", Severity.CRITICAL));
		vulnerabilityCatalog.put("commons-fileupload", new VulnerabilityRule("1.5", "CVE-2023-24998", Severity.HIGH));
		vulnerabilityCatalog.put("commons-io", new VulnerabilityRule("2.14.0", "CVE-2024-47554", Severity.MEDIUM));
		vulnerabilityCatalog.put("spring-core", new VulnerabilityRule("6.1.14", "CVE-2024-38816", Severity.HIGH));
		vulnerabilityCatalog.put("spring-web", new VulnerabilityRule("6.1.14", "Multiple CVEs", Severity.HIGH));
		vulnerabilityCatalog.put("spring-security-core", new VulnerabilityRule("6.3.4", "CVE-2024-38821", Severity.HIGH));
		vulnerabilityCatalog.put("tomcat-embed-core", new VulnerabilityRule("10.1.34", "Multiple CVEs", Severity.HIGH));
		vulnerabilityCatalog.put("undertow-core", new VulnerabilityRule("2.3.17", "CVE-2024-7885", Severity.HIGH));
		vulnerabilityCatalog.put("logback-core", new VulnerabilityRule("1.5.13", "CVE-2024-12798", Severity.MEDIUM));
		vulnerabilityCatalog.put("h2", new VulnerabilityRule("2.2.220", "CVE-2022-45868", Severity.HIGH));
		vulnerabilityCatalog.put("postgresql", new VulnerabilityRule("42.7.2", "CVE-2024-1597", Severity.HIGH));
		vulnerabilityCatalog.put("mysql-connector-java", new VulnerabilityRule("8.0.28", "Multiple CVEs", Severity.MEDIUM));
		vulnerabilityCatalog.put("bcprov-jdk15on", new VulnerabilityRule("1.78", "CVE-2024-29857", Severity.MEDIUM));
		vulnerabilityCatalog.put("netty-codec-http", new VulnerabilityRule("4.1.108", "CVE-2024-29025", Severity.MEDIUM));
		vulnerabilityCatalog.put("nimbus-jose-jwt", new VulnerabilityRule("9.37.2", "CVE-2023-52428", Severity.HIGH));
		// JS / Node
		vulnerabilityCatalog.put("minimist", new VulnerabilityRule("1.2.6", "CVE-2021-44906", Severity.MEDIUM));
		vulnerabilityCatalog.put("ws", new VulnerabilityRule("8.17.1", "CVE-2024-37890", Severity.HIGH));
		vulnerabilityCatalog.put("braces", new VulnerabilityRule("3.0.3", "CVE-2024-4068", Severity.HIGH));
		vulnerabilityCatalog.put("micromatch", new VulnerabilityRule("4.0.8", "CVE-2024-4067", Severity.MEDIUM));
		vulnerabilityCatalog.put("body-parser", new VulnerabilityRule("1.20.3", "CVE-2024-45590", Severity.HIGH));
		vulnerabilityCatalog.put("path-to-regexp", new VulnerabilityRule("0.1.10", "CVE-2024-45296", Severity.HIGH));
		vulnerabilityCatalog.put("send", new VulnerabilityRule("0.19.0", "CVE-2024-43799", Severity.MEDIUM));
		vulnerabilityCatalog.put("serve-static", new VulnerabilityRule("1.16.0", "CVE-2024-43800", Severity.MEDIUM));
		vulnerabilityCatalog.put("react-dom", new VulnerabilityRule("18.3.1", "CVE-2024-XXXX", Severity.MEDIUM));
		vulnerabilityCatalog.put("vite", new VulnerabilityRule("5.4.6", "CVE-2024-45811", Severity.HIGH));
		// Python
		vulnerabilityCatalog.put("urllib3", new VulnerabilityRule("2.2.2", "CVE-2024-37891", Severity.HIGH));
		vulnerabilityCatalog.put("setuptools", new VulnerabilityRule("70.0.0", "CVE-2024-6345", Severity.HIGH));
		vulnerabilityCatalog.put("pyyaml", new VulnerabilityRule("6.0.1", "CVE-2020-14343", Severity.HIGH));
		vulnerabilityCatalog.put("tornado", new VulnerabilityRule("6.4.1", "CVE-2024-52804", Severity.HIGH));
		vulnerabilityCatalog.put("flask", new VulnerabilityRule("3.0.3", "CVE-2023-30861", Severity.MEDIUM));
		vulnerabilityCatalog.put("aiohttp", new VulnerabilityRule("3.10.11", "CVE-2024-52303", Severity.HIGH));
		vulnerabilityCatalog.put("jinja2", new VulnerabilityRule("3.1.4", "CVE-2024-34064", Severity.MEDIUM));
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

