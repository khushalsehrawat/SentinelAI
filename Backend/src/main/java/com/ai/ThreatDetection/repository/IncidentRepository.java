package com.ai.ThreatDetection.repository;


import com.ai.ThreatDetection.entity.Incident;
import com.ai.ThreatDetection.entity.LogEntry;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface IncidentRepository extends JpaRepository<Incident, Long> {

    List<Incident> findByLogEntry(LogEntry entry);


}
