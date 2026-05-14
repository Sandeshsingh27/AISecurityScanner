package com.aisecurityscanner.model;

public enum StackType {
    JAVA_SPRING_BOOT("Java/Spring Boot"),
    REACT_TYPESCRIPT("React/TypeScript"),
    ANGULAR("Angular"),
    VUE("Vue"),
    NODE_EXPRESS("Node/Express"),
    PYTHON_DJANGO("Python/Django"),
    PYTHON_FASTAPI("Python/FastAPI"),
    PYTHON_FLASK("Python/Flask"),
    DOCKER("Docker"),
    CICD("CI/CD"),
    CONFIG("Config"),
    UNKNOWN("Unknown");

    private final String displayName;

    StackType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}

