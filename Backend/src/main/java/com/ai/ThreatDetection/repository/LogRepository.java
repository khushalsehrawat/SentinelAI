package com.ai.ThreatDetection.repository;

import com.ai.ThreatDetection.entity.LogEntry;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LogRepository extends JpaRepository<LogEntry, Long> {

  List<LogEntry> findByUser(User user);

}
