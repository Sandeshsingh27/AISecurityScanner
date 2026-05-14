package com.aisecurityscanner.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.aisecurityscanner.model.DependencyFinding;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class DependencyAuditServiceTest {

    @TempDir
    Path tempDir;

    @Test
    void auditFlagsKnownVulnerableDependencies() throws IOException {
        Files.write(tempDir.resolve("package.json"), (
            "{\n" +
                "  \"dependencies\": {\n" +
                "    \"axios\": \"0.27.2\",\n" +
                "    \"lodash\": \"4.17.20\"\n" +
                "  }\n" +
                "}\n").getBytes(StandardCharsets.UTF_8));
        Files.write(tempDir.resolve("requirements.txt"), (
            "requests==2.30.0\n" +
                "cryptography==40.0.0\n").getBytes(StandardCharsets.UTF_8));

        DependencyAuditService service = new DependencyAuditService(new VersionComparator(), new ObjectMapper());

        List<DependencyFinding> findings = service.audit(tempDir);

        assertThat(findings).extracting(DependencyFinding::getPackageName)
            .contains("axios", "lodash", "requests", "cryptography");
    }
}
