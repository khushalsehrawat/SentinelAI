package com.ai.ThreatDetection.controller;


import com.ai.ThreatDetection.dto.AlertResponse;
import com.ai.ThreatDetection.service.AlertService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Alerts API:
 * - GET /api/alerts  → show recent alerts for dashboard
 */
@RestController
@RequestMapping("/api/alerts")
public class AlertController {

    private final AlertService alertService;

    public AlertController(AlertService alertService) {
        this.alertService = alertService;
    }

    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    @GetMapping
    public ResponseEntity<List<AlertResponse>> list() {
        return ResponseEntity.ok(alertService.list());
    }

}
