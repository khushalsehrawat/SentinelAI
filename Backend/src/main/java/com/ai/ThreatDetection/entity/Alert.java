package com.ai.ThreatDetection.entity;

import jakarta.persistence.*;

import java.util.Date;

@Entity
public class Alert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String type;   // e.g., EMAIL / SMS
    private String status = "PENDING"; // PENDING / SENT
    private String severity;

    @Temporal(TemporalType.TIMESTAMP)
    private Date createdAt = new Date();

    // Relationship: one Alert belongs to one Incident
    @ManyToOne
    @JoinColumn(name = "incident_id")
    private Incident incident;

    @Column(columnDefinition = "TEXT")
    private String message; // Full alert message text


    private String title;
    private String userCategory;

    public Alert() {}


    // Constructor used by your service
    public Alert(String type, String message, Incident incident, String severity) {
        this.type = type;
        this.message = message;
        this.incident = incident;
        this.severity = severity;
        this.status = "PENDING";
        this.createdAt = new Date();
    }


    public Alert(Long id, String type, String status, String severity, Date createdAt, Incident incident, String message, String title, String userCategory) {
        this.id = id;
        this.type = type;
        this.status = status;
        this.severity = severity;
        this.createdAt = createdAt;
        this.incident = incident;
        this.message = message;
        this.title = title;
        this.userCategory = userCategory;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
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

    public Date getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Date createdAt) {
        this.createdAt = createdAt;
    }

    public Incident getIncident() {
        return incident;
    }

    public void setIncident(Incident incident) {
        this.incident = incident;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
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
}
