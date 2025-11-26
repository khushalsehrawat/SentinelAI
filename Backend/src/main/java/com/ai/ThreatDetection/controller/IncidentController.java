package com.ai.ThreatDetection.controller;


import com.ai.ThreatDetection.entity.Incident;
import com.ai.ThreatDetection.service.IncidentService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Incidents API:
 * - GET  /api/incidents
 * - GET  /api/incidents/{id}
 * - PUT  /api/incidents/{id}/status?value=RESOLVED
 */
@RestController
@RequestMapping("/api/incidents")
public class IncidentController {

    private final IncidentService incidentService;

    public IncidentController(IncidentService incidentService) {
        this.incidentService = incidentService;
    }

    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    @GetMapping
    public ResponseEntity<List<Incident>> list() {
        return ResponseEntity.ok(incidentService.list());
    }

    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    @GetMapping("/{id}")
    public ResponseEntity<Incident> get(@PathVariable Long id) {
        return incidentService.find(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    @PutMapping("/{id}/status")
    public ResponseEntity<Incident> updateStatus(@PathVariable Long id,
                                                 @RequestParam("value") String status) {
        return ResponseEntity.ok(incidentService.updateStatus(id, status));
    }
}
