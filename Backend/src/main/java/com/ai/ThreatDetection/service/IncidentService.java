package com.ai.ThreatDetection.service;


import com.ai.ThreatDetection.entity.Incident;
import com.ai.ThreatDetection.repository.IncidentRepository;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

/**
 * IncidentService: track lifecycle of incidents
 * - create from an analyzed LogEntry
 * - update status (OPEN -> RESOLVED)
 * - list/view
 */
@Service
public class IncidentService {

    private final IncidentRepository incidentRepository;

    public IncidentService(IncidentRepository incidentRepository) {
        this.incidentRepository = incidentRepository;
    }

    public Incident create(Incident incident){
        return incidentRepository.save(incident);
    }

    public List<Incident> list(){
        return incidentRepository.findAll();
    }

    public Optional<Incident> find(Long id){
        return incidentRepository.findById(id);
    }

    public Incident updateStatus(Long id, String status)
    {
        Incident i = incidentRepository.findById(id)
                .orElseThrow(()-> new RuntimeException("Incident Not Found"));
        i.setStatus(status);
        return incidentRepository.save(i);
    }
}
