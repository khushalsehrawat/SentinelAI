package com.ai.ThreatDetection.controller;


import com.ai.ThreatDetection.dto.AlertResponse;
import com.ai.ThreatDetection.entity.Alert;
import com.ai.ThreatDetection.entity.Incident;
import com.ai.ThreatDetection.repository.AlertRepository;
import com.ai.ThreatDetection.service.AlertService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Alerts API:
 * - GET /api/alerts  → show recent alerts for dashboard
 */
@RestController
@RequestMapping("/api/alerts")
public class AlertController {

    private final AlertService alertService;
    private final AlertRepository alertRepository;

    public AlertController(AlertService alertService, AlertRepository alertRepository) {
        this.alertService = alertService;
        this.alertRepository = alertRepository;
    }

    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    @GetMapping
    public ResponseEntity<List<AlertResponse>> list() {
        return ResponseEntity.ok(alertService.list());
    }

    @PutMapping("/{id}/status")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> updateStatus(
            @PathVariable Long id,
            @RequestBody Map<String, String> req
    ) {
        String newStatus = req.get("status");

        Alert alert = alertRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Alert not found"));

        alert.setStatus(newStatus);
        alertRepository.save(alert);

        return ResponseEntity.ok().build();
    }


    List<Alert> findByIncident(Incident incident) {
        return null;
    }

}
