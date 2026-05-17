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
                addIf(stacks, isJavaSpringBoot(name, normalized, content), StackType.JAVA_SPRING_BOOT);
                addIf(stacks, isReactTypeScript(name, normalized, content), StackType.REACT_TYPESCRIPT);
                addIf(stacks, isAngular(name), StackType.ANGULAR);
                addIf(stacks, isVue(name, normalized), StackType.VUE);
                addIf(stacks, isNodeExpress(name, content), StackType.NODE_EXPRESS);
                addIf(stacks, isPythonDjango(name), StackType.PYTHON_DJANGO);
                addIf(stacks, isPythonFastApi(name, content), StackType.PYTHON_FASTAPI);
                addIf(stacks, isPythonFlask(name, content), StackType.PYTHON_FLASK);
                addIf(stacks, isDocker(name, normalized), StackType.DOCKER);
                addIf(stacks, isCiCd(name, normalized), StackType.CICD);
                addIf(stacks, isConfigFile(name), StackType.CONFIG);
            }
        } catch (IOException ex) {
            throw new IllegalStateException("Failed to inspect target path: " + targetPath, ex);
        }
        if (stacks.isEmpty()) {
            stacks.add(StackType.UNKNOWN);
        }
        return stacks;
    }

    private void addIf(Set<StackType> stacks, boolean condition, StackType stackType) {
        if (condition) {
            stacks.add(stackType);
        }
    }

    private boolean isJavaSpringBoot(String name, String normalized, String content) {
        return "pom.xml".equals(name) || normalized.endsWith(".java")
            || content.contains("@RestController") || content.contains("springframework.boot");
    }

    private boolean isReactTypeScript(String name, String normalized, String content) {
        if ("package.json".equals(name) && content.contains("\"react\"")) {
            return true;
        }
        return name.endsWith(".tsx") || name.endsWith(".jsx") || normalized.contains("next.config");
    }

    private boolean isAngular(String name) {
        return "angular.json".equals(name) || name.endsWith(".component.ts") || name.endsWith(".service.ts");
    }

    private boolean isVue(String name, String normalized) {
        return name.endsWith(".vue") || normalized.endsWith("vue.config.js");
    }

    private boolean isNodeExpress(String name, String content) {
        return "package.json".equals(name) && content.contains("\"express\"");
    }

    private boolean isPythonDjango(String name) {
        return "requirements.txt".equals(name) || "manage.py".equals(name) || name.endsWith("settings.py");
    }

    private boolean isPythonFastApi(String name, String content) {
        return name.endsWith(".py") && content.contains("FastAPI(");
    }

    private boolean isPythonFlask(String name, String content) {
        return name.endsWith(".py") && content.contains("Flask(");
    }

    private boolean isDocker(String name, String normalized) {
        return name.startsWith("Dockerfile") || normalized.contains("docker-compose");
    }

    private boolean isCiCd(String name, String normalized) {
        return normalized.contains(".github/workflows") || ".gitlab-ci.yml".equals(name);
    }

    private boolean isConfigFile(String name) {
        return name.endsWith(".properties") || name.endsWith(".yml") || name.endsWith(".yaml")
            || name.endsWith(".env") || name.endsWith(".json");
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

