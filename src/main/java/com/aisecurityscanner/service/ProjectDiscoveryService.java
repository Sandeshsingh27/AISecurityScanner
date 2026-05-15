package com.aisecurityscanner.service;

import com.aisecurityscanner.model.StackType;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.stereotype.Service;

@Service
public class ProjectDiscoveryService {

    public Set<StackType> detectStacks(Path targetPath) {
        Set<StackType> stacks = new LinkedHashSet<StackType>();
        try (Stream<Path> stream = Files.walk(targetPath)) {
            List<Path> files = stream.filter(Files::isRegularFile).filter(this::isScannableSourceFile).toList();
            for (Path file : files) {
                String name = file.getFileName().toString();
                String normalized = file.toString().replace('\\', '/').toLowerCase();
                String content = safeRead(file);
                if ("pom.xml".equals(name) || normalized.endsWith(".java") || content.contains("@RestController") || content.contains("springframework.boot")) {
                    stacks.add(StackType.JAVA_SPRING_BOOT);
                }
                if ("package.json".equals(name) && content.contains("\"react\"")) {
                    stacks.add(StackType.REACT_TYPESCRIPT);
                }
                if (name.endsWith(".tsx") || name.endsWith(".jsx") || normalized.contains("next.config")) {
                    stacks.add(StackType.REACT_TYPESCRIPT);
                }
                if ("angular.json".equals(name) || name.endsWith(".component.ts") || name.endsWith(".service.ts")) {
                    stacks.add(StackType.ANGULAR);
                }
                if (name.endsWith(".vue") || normalized.endsWith("vue.config.js")) {
                    stacks.add(StackType.VUE);
                }
                if ("package.json".equals(name) && content.contains("\"express\"")) {
                    stacks.add(StackType.NODE_EXPRESS);
                }
                if ("requirements.txt".equals(name) || "manage.py".equals(name) || name.endsWith("settings.py")) {
                    stacks.add(StackType.PYTHON_DJANGO);
                }
                if (name.endsWith(".py") && content.contains("FastAPI(")) {
                    stacks.add(StackType.PYTHON_FASTAPI);
                }
                if (name.endsWith(".py") && content.contains("Flask(")) {
                    stacks.add(StackType.PYTHON_FLASK);
                }
                if (name.startsWith("Dockerfile") || normalized.contains("docker-compose")) {
                    stacks.add(StackType.DOCKER);
                }
                if (normalized.contains(".github/workflows") || ".gitlab-ci.yml".equals(name)) {
                    stacks.add(StackType.CICD);
                }
                if (name.endsWith(".properties") || name.endsWith(".yml") || name.endsWith(".yaml") || name.endsWith(".env") || name.endsWith(".json")) {
                    stacks.add(StackType.CONFIG);
                }
            }
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to inspect target path: " + targetPath, ex);
        }
        if (stacks.isEmpty()) {
            stacks.add(StackType.UNKNOWN);
        }
        return stacks;
    }

    public int countFiles(Path targetPath) {
        try (Stream<Path> stream = Files.walk(targetPath)) {
            return (int) stream.filter(Files::isRegularFile).filter(this::isScannableSourceFile).count();
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to count files in: " + targetPath, ex);
        }
    }

    public List<String> discoverAttackSurface(Path targetPath) {
        List<String> attackSurface = new ArrayList<String>();
        try (Stream<Path> stream = Files.walk(targetPath)) {
            List<Path> files = stream.filter(Files::isRegularFile).filter(this::isScannableSourceFile).collect(Collectors.toList());
            for (Path file : files) {
                String content = safeRead(file);
                String relative = targetPath.relativize(file).toString().replace('\\', '/');
                if (content.contains("@RestController") || content.contains("@Controller")) {
                    List<String> mappings = extractMappings(content, relative);
                    attackSurface.addAll(mappings);
                } else if (content.contains("FastAPI(") || content.contains("@app.get") || content.contains("@app.post") || content.contains("@app.route")) {
                    attackSurface.addAll(extractPythonRoutes(content, relative));
                } else if (content.contains("app.use(") || content.contains("router.")) {
                    attackSurface.add(relative + " -> Express routes detected");
                }
            }
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to discover attack surface: " + targetPath, ex);
        }
        return attackSurface;
    }

    private List<String> extractMappings(String content, String relative) {
        List<String> results = new ArrayList<String>();
        String[] lines = content.split("\\R");
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.startsWith("@GetMapping") || trimmed.startsWith("@PostMapping") || trimmed.startsWith("@PutMapping")
                || trimmed.startsWith("@DeleteMapping") || trimmed.startsWith("@PatchMapping") || trimmed.startsWith("@RequestMapping")) {
                results.add(relative + " -> " + trimmed);
            }
        }
        return results;
    }

    private List<String> extractPythonRoutes(String content, String relative) {
        List<String> results = new ArrayList<String>();
        String[] lines = content.split("\\R");
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.startsWith("@app.get") || trimmed.startsWith("@app.post") || trimmed.startsWith("@app.put")
                || trimmed.startsWith("@app.delete") || trimmed.startsWith("@app.route")) {
                results.add(relative + " -> " + trimmed);
            }
        }
        return results;
    }

    private String safeRead(Path file) {
        try {
            byte[] bytes = Files.readAllBytes(file);
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (IOException ex) {
            return "";
        }
    }

    private boolean isScannableSourceFile(Path file) {
        String normalized = file.toString().replace('\\', '/').toLowerCase();
        if (normalized.contains("/target/") || normalized.contains("/build/") || normalized.contains("/.git/")
            || normalized.contains("/node_modules/") || normalized.contains("/.venv/") || normalized.contains("/venv/")) {
            return false;
        }
        return !(normalized.endsWith(".jar") || normalized.endsWith(".class") || normalized.endsWith(".zip") || normalized.endsWith(".war"));
    }
}

