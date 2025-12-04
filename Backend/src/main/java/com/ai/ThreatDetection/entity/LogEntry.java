package com.ai.ThreatDetection.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;

import java.util.Date;



/**
 * Stores raw logs/events coming from servers, apps, or networks.
 * Each LogEntry is analyzed by the AI service for anomalies.
 */
@Entity
@Table(name = "log_entries")
public class LogEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;


    @Column(columnDefinition = "TEXT")
    private String logData;

    private String source;    // e.g., "Firewall", "Application", "System"

    private Date timestamp = new Date();

    @Column(length = 20)
    private String severity;  // e.g., LOW / MEDIUM / HIGH / CRITICAL

    @Column(length = 100)
    private String category;  // e.g., "Malware", "Unauthorized Access"

    @Column(columnDefinition = "TEXT")
    private String recommendation; // AI-suggested remediation

    // Relationship: One log may lead to one incident
    @OneToOne(mappedBy = "logEntry", cascade = CascadeType.ALL)
    @JsonBackReference
    private Incident incident;


    @ManyToOne
    @JoinColumn(name="user_id")
    private User user;


    private String title;
    private String userCategory;



    public LogEntry(){}

    public LogEntry(Long id, String logData, String source, Date timestamp, String severity, String category, String recommendation, Incident incident, User user, String title, String userCategory) {
        this.id = id;
        this.logData = logData;
        this.source = source;
        this.timestamp = timestamp;
        this.severity = severity;
        this.category = category;
        this.recommendation = recommendation;
        this.incident = incident;
        this.user = user;
        this.title = title;
        this.userCategory = userCategory;
    }

    public LogEntry(String logData, String source) {
        this.logData = logData;
        this.source = source;
        this.timestamp = new Date();
        this.severity = "LOW";
        this.category = "General";
    }


    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getLogData() {
        return logData;
    }

    public void setLogData(String logData) {
        this.logData = logData;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Date timestamp) {
        this.timestamp = timestamp;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public void setRecommendation(String recommendation) {
        this.recommendation = recommendation;
    }

    public Incident getIncident() {
        return incident;
    }

    public void setIncident(Incident incident) {
        this.incident = incident;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getUserCategory() {
        return userCategory;
    }

    public void setUserCategory(String userCategory) {
        this.userCategory = userCategory;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }
}
