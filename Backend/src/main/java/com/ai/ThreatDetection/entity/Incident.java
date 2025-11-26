package com.ai.ThreatDetection.entity;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;

import java.util.Date;


/**
 * Represents a security incident generated from a log entry.
 * Incidents are tracked and reviewed by analysts.
 */
@Entity
public class Incident {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String status = "OPEN";     // OPEN / RESOLVED
    private String severity;            // Copy from analyzed LogEntry

    @Temporal(TemporalType.TIMESTAMP)
    private Date detectedAt = new Date();

    @Column(columnDefinition = "TEXT")
    private String details;             // Summary of the issue


    // Relationship: one Incident ↔ one LogEntry
    @OneToOne
    @JoinColumn(name = "log_entry_id")
    @JsonManagedReference
    private LogEntry logEntry;

    public Incident() {}

    public Incident(Long id, String status, String severity, Date detectedAt, String details, LogEntry logEntry) {
        this.id = id;
        this.status = status;
        this.severity = severity;
        this.detectedAt = detectedAt;
        this.details = details;
        this.logEntry = logEntry;
    }

    public Incident(String details, LogEntry entry) {
        this.details = details;
        this.logEntry = entry;
        this.detectedAt = new Date();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public Date getDetectedAt() {
        return detectedAt;
    }

    public void setDetectedAt(Date detectedAt) {
        this.detectedAt = detectedAt;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    public LogEntry getLogEntry() {
        return logEntry;
    }

    public void setLogEntry(LogEntry logEntry) {
        this.logEntry = logEntry;
    }
}
