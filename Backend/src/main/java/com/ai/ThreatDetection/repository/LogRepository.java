package com.ai.ThreatDetection.repository;

import com.ai.ThreatDetection.entity.LogEntry;
import com.ai.ThreatDetection.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface LogRepository extends JpaRepository<LogEntry, Long> {


    List<LogEntry> findByUser(User user);



}
