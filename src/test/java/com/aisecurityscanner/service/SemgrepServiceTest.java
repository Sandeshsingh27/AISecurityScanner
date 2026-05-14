package com.aisecurityscanner.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.aisecurityscanner.config.ScannerProperties;
import com.aisecurityscanner.model.SemgrepFinding;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.Test;

class SemgrepServiceTest {

    @Test
    void parseExtractsFindingsFromSemgrepJson() {
        String json = "{\n" +
            "  \"results\": [\n" +
            "    {\n" +
            "      \"check_id\": \"python.sql-injection\",\n" +
            "      \"path\": \"app/repository.py\",\n" +
            "      \"start\": { \"line\": 45 },\n" +
            "      \"end\": { \"line\": 45 },\n" +
            "      \"extra\": {\n" +
            "        \"message\": \"Possible SQL injection\",\n" +
            "        \"severity\": \"ERROR\",\n" +
            "        \"lines\": \"cursor.execute(\\\"SELECT * FROM users WHERE name = ' + name\\\")\",\n" +
            "        \"metadata\": {\n" +
            "          \"cwe\": \"CWE-89\",\n" +
            "          \"owasp\": \"OWASP A03:2021 - Injection\"\n" +
            "        }\n" +
            "      }\n" +
            "    }\n" +
            "  ]\n" +
            "}";

        SemgrepService service = new SemgrepService(new ScannerProperties(), new ObjectMapper());

        List<SemgrepFinding> findings = service.parse(json);

        assertThat(findings).hasSize(1);
        assertThat(findings.get(0).getLine()).isEqualTo(45);
        assertThat(findings.get(0).getSeverity().name()).isEqualTo("HIGH");
        assertThat(findings.get(0).getVulnerabilityType()).isEqualTo("SQL Injection");
    }
}
