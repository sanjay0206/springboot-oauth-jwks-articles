package com.oauth.resourceserver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping
public class AppController {

    Logger logger = LoggerFactory.getLogger(AppController.class);

    @GetMapping("/public-article")
    @PreAuthorize("hasAuthority('SCOPE_profile')")
    public ResponseEntity<Map<String, String>> getPublicData() {
        logger.info("Inside getPublicData = " + SecurityContextHolder.getContext());
        return ResponseEntity.ok(Map.of("message", "This is a public article"));
    }

    @GetMapping("/private-article")
    @PreAuthorize("hasAuthority('SCOPE_read')")
    public ResponseEntity<Map<String, String>> getPrivateData() {
        logger.info("Inside getPrivateData = " + SecurityContextHolder.getContext());
        return ResponseEntity.ok(Map.of("message", "This is a private article"));
    }
}
