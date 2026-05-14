package com.aisecurityscanner;

import com.aisecurityscanner.config.ScannerProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(ScannerProperties.class)
public class AiSecurityScannerApplication {

    public static void main(String[] args) {
        SpringApplication.run(AiSecurityScannerApplication.class, args);
    }
}

