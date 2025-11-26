package com.ai.ThreatDetection.repository;

import com.ai.ThreatDetection.entity.Alert;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AlertRepository extends JpaRepository<Alert, Long> {
}
